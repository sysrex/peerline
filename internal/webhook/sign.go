package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Sign returns a Standard Webhooks v1 signature: v1,<base64 hmac>.
// The MAC is over id + "." + timestamp + "." + body.
func Sign(secret, id, timestamp string, body []byte) (string, error) {
	key, err := SigningKey(secret)
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id + "." + timestamp + "."))
	h.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// SigningKey decodes a whsec_ secret. The key must be 24 to 64 bytes.
func SigningKey(secret string) ([]byte, error) {
	if !strings.HasPrefix(secret, "whsec_") {
		return nil, errors.New("invalid secret")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) < 24 || len(key) > 64 {
		return nil, errors.New("invalid secret")
	}
	return key, nil
}

// Verify accepts a webhook-signature header signed by any of secrets.
// Timestamp must be within tolerance of now. The comparison is constant time.
func Verify(secrets []string, id, timestamp string, body []byte, header string, now time.Time, tolerance time.Duration) error {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	when := time.Unix(sec, 0)
	if when.Before(now.Add(-tolerance)) || when.After(now.Add(tolerance)) {
		return errors.New("timestamp outside tolerance")
	}
	for _, part := range strings.Fields(header) {
		for _, secret := range secrets {
			want, err := Sign(secret, id, timestamp, body)
			if err != nil {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(part), []byte(want)) == 1 {
				return nil
			}
		}
	}
	return errors.New("signature mismatch")
}
