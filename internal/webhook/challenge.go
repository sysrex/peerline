package webhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Challenge posts a signed verification body and requires the endpoint to echo
// the challenge. The caller supplies the HTTP client (production uses NewSafeClient).
func Challenge(ctx context.Context, client *http.Client, rawURL, secret string, now time.Time) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	challenge := hex.EncodeToString(nonce)
	body, err := json.Marshal(map[string]string{"type": "verification", "challenge": challenge})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	id := "msg_verification_" + challenge
	stamp := strconv.FormatInt(now.Unix(), 10)
	sig, err := Sign(secret, id, stamp, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", stamp)
	req.Header.Set("webhook-signature", sig)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8193))
	if err != nil {
		return err
	}
	if len(b) > 8192 {
		return errors.New("challenge response exceeds limit")
	}
	var result struct {
		Challenge string `json:"challenge"`
	}
	if res.StatusCode < 200 || res.StatusCode > 299 || json.Unmarshal(b, &result) != nil || subtle.ConstantTimeCompare([]byte(challenge), []byte(result.Challenge)) != 1 {
		return errors.New("challenge failed")
	}
	return nil
}
