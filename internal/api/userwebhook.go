package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/store"
	"github.com/sysrex/peerline/internal/webhook"
)

func (s *Server) webhookRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /v1/me/webhook", s.rateLimitWrite(s.putWebhook))
	mux.HandleFunc("GET /v1/me/webhook", s.rateLimitAuth(s.getWebhook))
	mux.HandleFunc("DELETE /v1/me/webhook", s.rateLimitWrite(s.deleteWebhook))
	mux.HandleFunc("POST /v1/me/webhook/rotate-secret", s.rateLimitWrite(s.rotateWebhookSecret))
	mux.HandleFunc("GET /v1/me/webhook/deliveries", s.rateLimitAuth(s.listWebhookDeliveries))
}

func (s *Server) putWebhook(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Events) != 1 || in.Events[0] != "message.received" {
		writeErr(w, http.StatusBadRequest, "events must be [message.received]")
		return
	}
	if err := validateWebhookURL(in.URL); err != nil {
		writeErr(w, http.StatusBadRequest, "webhook url must be public https")
		return
	}
	me := auth.PeerID(r.Context())
	secret, err := s.st.PutPeerWebhook(r.Context(), me, in.URL)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.runWebhookChallenge(r.Context(), in.URL, secret); err != nil {
		_ = s.st.DeletePeerWebhook(r.Context(), me)
		writeErr(w, http.StatusBadRequest, "webhook challenge failed")
		return
	}
	if err := s.st.MarkPeerWebhookEnabled(r.Context(), me); err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("webhook.registered", "event", "webhook.registered", "peer_id", me)
	writeJSON(w, http.StatusOK, map[string]any{
		"url":    in.URL,
		"secret": secret,
		"note":   "secret is shown once",
	})
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) {
	me := auth.PeerID(r.Context())
	wh, err := s.st.GetPeerWebhook(r.Context(), me, false)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no webhook")
		return
	}
	out := map[string]any{
		"url": wh.URL, "enabled": wh.Enabled, "dead": wh.Dead, "events": []string{wh.Events},
	}
	if rows, err := s.st.ListWebhookDeliveries(r.Context(), me, 1); err == nil && len(rows) > 0 {
		out["last_delivery"] = deliveryStatus(rows[0])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 50 {
			writeErr(w, http.StatusBadRequest, "limit must be 1..50")
			return
		}
		limit = n
	}
	rows, err := s.st.ListWebhookDeliveries(r.Context(), auth.PeerID(r.Context()), limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, deliveryStatus(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": out})
}

func deliveryStatus(d store.WebhookDelivery) map[string]any {
	return map[string]any{
		"id": d.ID, "message_id": d.MessageID, "status": d.Status, "attempts": d.Attempts,
	}
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	me := auth.PeerID(r.Context())
	if err := s.st.DeletePeerWebhook(r.Context(), me); err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("webhook.disabled", "event", "webhook.disabled", "peer_id", me)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	me := auth.PeerID(r.Context())
	secret, err := s.st.RotatePeerWebhookSecret(r.Context(), me, s.clk.Now().Unix()+3600)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no webhook")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "note": "secret is shown once"})
}

func validateWebhookURL(raw string) error {
	u, err := webhook.ValidateHTTPSURL(raw)
	if err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !webhook.PublicIP(ip) {
		return errPrivateWebhook
	}
	if ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", u.Hostname()); err == nil {
		for _, ip := range ips {
			if !webhook.PublicIP(ip) {
				return errPrivateWebhook
			}
		}
	}
	return nil
}

var errPrivateWebhook = errString("private webhook url")

type errString string

func (e errString) Error() string { return string(e) }

func (s *Server) runWebhookChallenge(ctx context.Context, url, secret string) error {
	if s.testWebhookChallenge != nil {
		return s.testWebhookChallenge(url, secret)
	}
	return webhook.Challenge(ctx, webhook.NewSafeClient(false), url, secret, s.clk.Now())
}

// deliverWebhook posts one minimal event for an enabled endpoint.
// It returns true when the email fallback should be skipped.
// Retries of the same message keep the webhook id msg_<message_id>.
func (s *Server) deliverWebhook(ctx context.Context, m *store.Message) bool {
	wh, err := s.st.GetPeerWebhook(ctx, m.To, true)
	if err != nil || !wh.Enabled || wh.Dead {
		return false
	}
	id := "msg_" + strconv.FormatInt(m.ID, 10)
	body, err := json.Marshal(map[string]any{
		"type": "message.received", "id": id, "from": m.From,
		"message_id": m.ID, "created_at": m.CreatedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return false
	}
	if s.webhookDeliv != nil && !s.webhookDeliv.Allow(m.To) {
		_, _ = s.st.SaveWebhookDelivery(ctx, id, m.To, m.ID, string(body), "rate_limited", s.clk.Now().Unix())
		return true
	}
	status, postErr := s.postUserWebhook(ctx, wh, id, body)
	state := "delivered"
	if postErr != nil || status < 200 || status >= 300 {
		state = "failed"
	}
	attempts, saveErr := s.st.SaveWebhookDelivery(ctx, id, m.To, m.ID, string(body), state, s.clk.Now().Unix())
	if saveErr != nil {
		s.log.Error("webhook delivery", "recipient", m.To, "message_id", m.ID, "err", saveErr)
		attempts = 1
	}
	decision := webhook.Decide(status, attempts, s.clk.Now(), 0)
	s.webhookMetrics.Note(decision, status)
	if state != "delivered" {
		webhook.LogFailure(s.log, id, status)
	}
	if decision.Dead {
		if err := s.st.MarkPeerWebhookDead(ctx, m.To); err != nil {
			s.log.Error("webhook disable", "recipient", m.To, "err", err)
		}
		s.log.Info("webhook.disabled", "event", "webhook.disabled", "peer_id", m.To)
		return false
	}
	return true
}

func (s *Server) postUserWebhook(ctx context.Context, wh store.PeerWebhook, id string, body []byte) (int, error) {
	stamp := strconv.FormatInt(s.clk.Now().Unix(), 10)
	sig, err := webhook.Sign(wh.Secret, id, stamp, body)
	if err != nil {
		return 0, err
	}
	if wh.OldSecret != "" && s.clk.Now().Unix() < wh.OldSecretExpires {
		if old, err := webhook.Sign(wh.OldSecret, id, stamp, body); err == nil {
			sig += " " + old
		}
	}
	if s.testWebhookPost != nil {
		return s.testWebhookPost(id, body, sig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", stamp)
	req.Header.Set("webhook-signature", sig)
	res, err := webhook.NewSafeClient(false).Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
	return res.StatusCode, nil
}
