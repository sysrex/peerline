package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestChallengeEcho(t *testing.T) {
	secret := "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("webhook-signature") == "" || r.Header.Get("webhook-id") == "" {
			t.Fatal("missing signature")
		}
		body, _ := io.ReadAll(r.Body)
		var in struct {
			Challenge string `json:"challenge"`
		}
		if json.Unmarshal(body, &in) != nil || in.Challenge == "" {
			t.Fatal("body")
		}
		out, _ := json.Marshal(map[string]string{"challenge": in.Challenge})
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytesReader(out)),
			Header:     make(http.Header),
		}, nil
	})}
	if err := Challenge(t.Context(), client, "https://hooks.example/hook", secret, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeRejectsWrongEcho(t *testing.T) {
	secret := "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		out, _ := json.Marshal(map[string]string{"challenge": "nope"})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytesReader(out)), Header: make(http.Header)}, nil
	})}
	if err := Challenge(t.Context(), client, "https://hooks.example/hook", secret, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("expected failure")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type byteReader struct{ b []byte }

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

func (b *byteReader) Read(p []byte) (int, error) {
	if len(b.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.b)
	b.b = b.b[n:]
	return n, nil
}
