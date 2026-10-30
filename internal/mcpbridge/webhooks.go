package mcpbridge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func signingKey(secret string) ([]byte, error) {
	if !strings.HasPrefix(secret, "whsec_") {
		return nil, errors.New("invalid secret")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) < 24 || len(key) > 64 {
		return nil, errors.New("invalid secret")
	}
	return key, nil
}
func webhookSignature(secret, id, stamp string, body []byte) string {
	key, _ := signingKey(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id + "." + stamp + "."))
	h.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(h.Sum(nil))
}
func (e *EventEngine) post(ctx context.Context, id, sub, url, secret, old string, body []byte) (int, []byte, error) {
	if len(body) > 262144 {
		return 413, nil, errors.New("event exceeds limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	stamp := strconv.FormatInt(e.now().Unix(), 10)
	sig := webhookSignature(secret, id, stamp, body)
	if old != "" {
		sig += " " + webhookSignature(old, id, stamp, body)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", stamp)
	req.Header.Set("webhook-signature", sig)
	req.Header.Set("X-MCP-Subscription-Id", sub)
	res, err := e.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8193))
	if len(b) > 8192 {
		return res.StatusCode, nil, errors.New("callback response exceeds limit")
	}
	return res.StatusCode, b, err
}
func (e *EventEngine) verify(ctx context.Context, id, url, secret string) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	challenge := hex.EncodeToString(nonce)
	body, _ := json.Marshal(map[string]string{"type": "verification", "challenge": challenge})
	status, b, err := e.post(ctx, "msg_verification_"+challenge, id, url, secret, "", body)
	if err != nil {
		return err
	}
	var result struct {
		Challenge string `json:"challenge"`
	}
	if status < 200 || status > 299 || json.Unmarshal(b, &result) != nil || subtle.ConstantTimeCompare([]byte(challenge), []byte(result.Challenge)) != 1 {
		return errors.New("challenge failed")
	}
	return nil
}
