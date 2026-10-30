// Package mcpbridge exposes a narrow, account-isolated MCP interface to Peerline.
package mcpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Account is trusted operator configuration, never populated from tool arguments.
// ID identifies one OAuth principal-to-relay connection; it must be immutable.
type Account struct {
	AccessToken          string    `json:"-"` // request credential; never serialized in tool output
	AccessTokenExpiresAt time.Time `json:"-"` // authorization lifetime, not subscription lease

	ID        string            `json:"id"`
	Subject   string            `json:"subject"`
	RelayURL  string            `json:"relay_url"`
	PeerID    string            `json:"peer_id"`
	APIKeyEnv string            `json:"api_key_env"`
	Peers     map[string]string `json:"peers"` // operator-verified alias -> peer ID
}

// Relay scopes every operation to a configured account. Errors must not contain secrets.
type Relay interface {
	Inbox(context.Context, Account, int64, int) (InboxPage, error)
	Send(context.Context, Account, string, SendInput) (json.RawMessage, error)
	Grants(context.Context, Account) (json.RawMessage, error)
	// CanReceive checks that the sender still has messages permission on this account.
	CanReceive(context.Context, Account, string) (bool, error)
}
type SendInput struct {
	Type    string `json:"type"`
	Body    string `json:"body"`
	ReplyTo *int64 `json:"reply_to,omitempty"`
}
type Message struct {
	ID        int64     `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Type      string    `json:"type"`
	Body      string    `json:"body"`
	ReplyTo   *int64    `json:"reply_to,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
type InboxPage struct {
	Messages  []Message `json:"messages"`
	NextSince int64     `json:"next_since"`
}

// Authenticator must derive the account from verified authentication, not headers naming a user.
type Authenticator interface {
	Authenticate(*http.Request) (Account, error)
}
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

// EventService is implemented by the durable event engine. It does not send peer replies.
type EventService interface {
	Call(context.Context, Account, string, json.RawMessage) (any, *RPCError)
}

// EventAuthorizer revalidates the original OAuth grant before background delivery.
// False,nil is definitive denial; errors require fail-closed transient backoff.
type EventAuthorizer interface {
	CheckAccess(context.Context, Account, string) (bool, error)
}
