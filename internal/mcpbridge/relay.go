package mcpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/webhook"
)

// NewSafeHTTPClient is the MCP adapter's view of webhook.NewSafeClient.
func NewSafeHTTPClient(allowPrivateNetworks bool) *http.Client {
	c := webhook.NewSafeClient(allowPrivateNetworks)
	c.Timeout = 15 * time.Second
	return c
}

func publicIP(ip netip.Addr) bool { return webhook.PublicIP(ip) }

func validateHTTPSURL(raw string) (*url.URL, error) { return webhook.ValidateHTTPSURL(raw) }

// RelayError never includes upstream bodies, URLs, tokens or message content.
// Ambiguous means a write may have succeeded and MUST NOT be automatically retried.
type RelayError struct {
	Kind       string `json:"kind"`
	Status     int    `json:"status,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
	Ambiguous  bool   `json:"ambiguous,omitempty"`
}

func (e *RelayError) Error() string {
	if e.Ambiguous {
		return "relay outcome unknown; do not retry automatically"
	}
	return "relay request failed: " + e.Kind
}

type HTTPRelay struct{ client *http.Client }

func NewHTTPRelay(allowPrivateNetworks bool) *HTTPRelay {
	return &HTTPRelay{client: NewSafeHTTPClient(allowPrivateNetworks)}
}
func (r *HTTPRelay) request(ctx context.Context, a Account, key, method, path string, body []byte) (json.RawMessage, error) {
	u, err := validateHTTPSURL(a.RelayURL)
	if err != nil || key == "" {
		return nil, &RelayError{Kind: "configuration"}
	}
	target := strings.TrimRight(u.String(), "/") + path
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, &RelayError{Kind: "configuration"}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// No idempotency header and no retry loop: writes can have ambiguous outcomes.
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, &RelayError{Kind: "transport", Ambiguous: method == http.MethodPost}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		if retry < 0 || retry > 86400 {
			retry = 0
		}
		return nil, &RelayError{Kind: "upstream", Status: resp.StatusCode, RetryAfter: retry, Ambiguous: method == http.MethodPost && resp.StatusCode >= 500}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 || !json.Valid(data) {
		return nil, &RelayError{Kind: "invalid_response", Ambiguous: method == http.MethodPost}
	}
	return data, nil
}

// verifiedKey checks the credential's peer identity before EVERY operation and
// retains that exact key for the operation, avoiding rotation TOCTOU confusion.
func (r *HTTPRelay) verifiedKey(ctx context.Context, a Account) (string, error) {
	key := os.Getenv(a.APIKeyEnv)
	if a.ID == "" || a.PeerID == "" || key == "" {
		return "", &RelayError{Kind: "configuration"}
	}
	raw, err := r.request(ctx, a, key, http.MethodGet, "/v1/me", nil)
	if err != nil {
		return "", err
	}
	var me struct {
		PeerID string `json:"peer_id"`
	}
	if json.Unmarshal(raw, &me) != nil || me.PeerID != a.PeerID {
		return "", &RelayError{Kind: "account_binding"}
	}
	return key, nil
}

type relayGrant struct {
	Owner   string   `json:"owner"`
	Grantee string   `json:"grantee"`
	Scopes  []string `json:"scopes"`
	Bags    []string `json:"bags"`
}

func (r *HTTPRelay) grants(ctx context.Context, a Account, key string) ([]relayGrant, error) {
	raw, err := r.request(ctx, a, key, http.MethodGet, "/v1/grants", nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Grants []relayGrant `json:"grants"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return nil, &RelayError{Kind: "invalid_response"}
	}
	for _, g := range v.Grants {
		if g.Owner != a.PeerID && g.Grantee != a.PeerID {
			return nil, &RelayError{Kind: "account_binding"}
		}
	}
	return v.Grants, nil
}
func grantAllows(gs []relayGrant, owner, grantee string) bool {
	for _, g := range gs {
		if g.Owner == owner && g.Grantee == grantee {
			for _, s := range g.Scopes {
				if s == "messages" {
					return true
				}
			}
		}
	}
	return false
}
func (r *HTTPRelay) Grants(ctx context.Context, a Account) (json.RawMessage, error) {
	key, err := r.verifiedKey(ctx, a)
	if err != nil {
		return nil, err
	}
	gs, err := r.grants(ctx, a, key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"grants": gs})
}
func (r *HTTPRelay) CanReceive(ctx context.Context, a Account, sender string) (bool, error) {
	key, err := r.verifiedKey(ctx, a)
	if err != nil {
		return false, err
	}
	gs, err := r.grants(ctx, a, key)
	if err != nil {
		return false, err
	}
	return grantAllows(gs, a.PeerID, sender), nil
}
func (r *HTTPRelay) Send(ctx context.Context, a Account, to string, in SendInput) (json.RawMessage, error) {
	allowed := false
	for _, peer := range a.Peers {
		if peer == to {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, &RelayError{Kind: "permission", Status: 403}
	}
	if to == "" || strings.ContainsAny(to, "/\\?#% \t\r\n") || msg.Input(in).Validate() != nil {
		return nil, &RelayError{Kind: "invalid_input"}
	}
	key, err := r.verifiedKey(ctx, a)
	if err != nil {
		return nil, err
	}
	gs, err := r.grants(ctx, a, key)
	if err != nil {
		return nil, err
	}
	if !grantAllows(gs, to, a.PeerID) {
		return nil, &RelayError{Kind: "permission", Status: 403}
	}
	body, _ := json.Marshal(in)
	raw, err := r.request(ctx, a, key, http.MethodPost, "/v1/peers/"+url.PathEscape(to)+"/messages", body)
	if err != nil {
		return nil, err
	}
	var m Message
	if json.Unmarshal(raw, &m) != nil || m.ID <= 0 || m.From != a.PeerID || m.To != to {
		return nil, &RelayError{Kind: "invalid_response", Ambiguous: true}
	}
	return json.Marshal(m)
}
func (r *HTTPRelay) Inbox(ctx context.Context, a Account, since int64, limit int) (InboxPage, error) {
	if since < 0 || limit < 1 || limit > 200 {
		return InboxPage{}, &RelayError{Kind: "invalid_input"}
	}
	key, err := r.verifiedKey(ctx, a)
	if err != nil {
		return InboxPage{}, err
	}
	raw, err := r.request(ctx, a, key, http.MethodGet, "/v1/inbox?since="+strconv.FormatInt(since, 10)+"&limit="+strconv.Itoa(limit), nil)
	if err != nil {
		return InboxPage{}, err
	}
	var page InboxPage
	if json.Unmarshal(raw, &page) != nil || page.NextSince < since || len(page.Messages) > limit {
		return InboxPage{}, &RelayError{Kind: "invalid_response"}
	}
	last := since
	for _, m := range page.Messages {
		if m.ID <= last || m.To != a.PeerID || m.From == "" {
			return InboxPage{}, &RelayError{Kind: "account_binding"}
		}
		last = m.ID
	}
	if page.NextSince != last {
		return InboxPage{}, &RelayError{Kind: "invalid_response"}
	}
	return page, nil
}
