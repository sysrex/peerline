package api

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/store"
)

func TestUserWebhookSecretOnceAndEmailFallback(t *testing.T) {
	const token = "s3cret-register-token"
	cap := &captureMailer{}
	srv, apiSrv, st := newServerWithAccess(t, Config{Mailer: cap, RegisterToken: token})
	var posted []string
	var postedBody []byte
	var postedSig string
	apiSrv.testWebhookChallenge = func(url, secret string) error {
		if secret == "" || url == "" {
			return errors.New("missing")
		}
		return nil
	}
	apiSrv.testWebhookPost = func(id string, body []byte, signature string) (int, error) {
		posted = append(posted, id)
		postedBody = append([]byte(nil), body...)
		postedSig = signature
		return 200, nil
	}

	a := registerAs(t, srv, "alice", map[string]string{"X-Peerline-Register-Token": token})
	b := &client{t: t, srv: srv}
	resp, body := b.do("POST", "/v1/register", map[string]string{
		"name": "bob", "notify_email": "bob@mail.grokbot.com",
	}, map[string]string{"X-Peerline-Register-Token": token})
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&b.id, &b.key})
	verifyToken := extractVerifyToken(cap.all()[0].Body)
	resp, body = b.do("POST", "/v1/me/verify-email?token="+verifyToken, nil, nil)
	want(t, resp, body, 200)
	cap.mu.Lock()
	cap.msgs = nil
	cap.mu.Unlock()

	resp, body = b.do("PUT", "/v1/me/webhook", map[string]any{
		"url": "https://10.1.2.3/hook", "events": []string{"message.received"},
	}, nil)
	want(t, resp, body, 400)

	resp, body = b.do("PUT", "/v1/me/webhook", map[string]any{
		"url": "https://1.1.1.1/hook", "events": []string{"message.received"},
	}, nil)
	want(t, resp, body, 200)
	var created struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(body, &created)
	if created.Secret == "" {
		t.Fatalf("secret missing: %s", body)
	}
	resp, body = b.do("GET", "/v1/me/webhook", nil, nil)
	want(t, resp, body, 200)
	if strings.Contains(string(body), "whsec_") || strings.Contains(string(body), `"secret"`) {
		t.Fatalf("get leaked secret: %s", body)
	}
	resp, body = b.do("POST", "/v1/me/webhook/rotate-secret", nil, nil)
	want(t, resp, body, 200)
	var rotated struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(body, &rotated)
	if rotated.Secret == "" || rotated.Secret == created.Secret {
		t.Fatalf("rotate: %s", body)
	}
	resp, body = b.do("GET", "/v1/me/webhook", nil, nil)
	if strings.Contains(string(body), "whsec_") || strings.Contains(string(body), `"secret"`) {
		t.Fatalf("get leaked rotated secret: %s", body)
	}

	pairUp(t, b, a, []string{"messages"}, nil, nil)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "ping"}, nil)
	want(t, resp, body, 201)
	var sent struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(body, &sent)
	if n := len(cap.all()); n != 0 {
		t.Fatalf("email sent despite webhook: %d", n)
	}
	n, err := st.WebhookDeliveryCount(t.Context(), b.id, sent.ID)
	if err != nil || n != 1 {
		t.Fatalf("deliveries %d err %v", n, err)
	}
	if strings.Contains(string(postedBody), "ping") || !strings.Contains(string(postedBody), `"type":"message.received"`) {
		t.Fatalf("payload: %s", postedBody)
	}
	if strings.Count(postedSig, "v1,") != 2 {
		t.Fatalf("rotation overlap signature: %s", postedSig)
	}
	if !apiSrv.deliverWebhook(t.Context(), &store.Message{ID: sent.ID, To: b.id, From: a.id}) {
		t.Fatal("retry should still count as webhook")
	}
	n, err = st.WebhookDeliveryCount(t.Context(), b.id, sent.ID)
	if err != nil || n != 1 {
		t.Fatalf("duplicate delivery row: %d err %v", n, err)
	}
	wantID := "msg_" + strconv.FormatInt(sent.ID, 10)
	if len(posted) != 2 || posted[0] != wantID || posted[1] != wantID {
		t.Fatalf("retry id: %v want %s", posted, wantID)
	}
	resp, body = b.do("GET", "/v1/me/webhook/deliveries?limit=50", nil, nil)
	want(t, resp, body, 200)
	if strings.Contains(string(body), "whsec_") || strings.Contains(string(body), "ping") || !strings.Contains(string(body), `"status":"delivered"`) {
		t.Fatalf("deliveries: %s", body)
	}

	apiSrv.testWebhookPost = func(id string, body []byte, signature string) (int, error) {
		return 410, nil
	}
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "gone"}, nil)
	want(t, resp, body, 201)
	if n := len(cap.all()); n != 1 {
		t.Fatalf("dead webhook should fall back to email, got %d", n)
	}
	resp, body = b.do("GET", "/v1/me/webhook", nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"dead":true`) {
		t.Fatalf("dead status: %s", body)
	}

	resp, body = b.do("DELETE", "/v1/me/webhook", nil, nil)
	want(t, resp, body, 204)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "again"}, nil)
	want(t, resp, body, 201)
	if n := len(cap.all()); n != 2 {
		t.Fatalf("fallback emails: %d", n)
	}
}
