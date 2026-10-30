package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/sysrex/peerline/internal/store"
)

const (
	demoURL = "https://peerline.sysrex.com"
	repoURL = "https://github.com/sysrex/peerline"
)

// homeData is the only data the landing page may render. It must not carry
// register tokens, API keys, peer ids, or message contents.
type homeData struct {
	BaseURL      string
	RegisterOpen bool
	Nonce        template.HTMLAttr
	// StatsJSON is the same counters as Stats, pre-encoded so the embedded
	// script stays valid JSON. template.JS is safe here: the bytes are
	// json.Marshal of int64 fields only.
	StatsJSON template.JS
	store.Stats
}

func (s *Server) publicStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.Stats(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.Stats(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	raw, err := json.Marshal(st)
	if err != nil {
		s.internal(w, err)
		return
	}
	// Generate a per-request nonce for CSP
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		s.internal(w, err)
		return
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	// Set CSP with nonce for the home page
	csp := "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	w.Header().Set("Content-Security-Policy", csp)

	var buf bytes.Buffer
	if err := homeTmpl.Execute(&buf, homeData{
		BaseURL:      s.publicBase(r),
		RegisterOpen: s.cfg.RegisterToken == "",
		Nonce:        template.HTMLAttr(nonce),
		StatsJSON:    template.JS(raw),
		Stats:        st,
	}); err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

var homeTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Peerline</title>
<meta name="description" content="Peerline is a deny-all cross-account bot-to-bot bridge for allowlisted messages and bags.">
<style nonce="{{.Nonce}}">
  :root {
    color-scheme: light;
    --bg: #f6f4ef;
    --fg: #1c1915;
    --muted: #5c564e;
    --line: #e3ddd3;
    --card: #fffcf8;
    --code: #efeae2;
    --accent: #6b3a1f;
  }
  * { box-sizing: border-box; }
  html { background: var(--bg); }
  body {
    margin: 0;
    color: var(--fg);
    font: 17px/1.55 ui-sans-serif, system-ui, sans-serif;
    background: var(--bg);
  }
  main { max-width: 42rem; margin: 0 auto; padding: 3.25rem 1.25rem 4.5rem; }
  h1 { font-size: 2rem; font-weight: 600; letter-spacing: -0.03em; margin: 0 0 0.35rem; }
  h2 { font-size: 1.2rem; font-weight: 600; margin: 2.4rem 0 0.6rem; }
  h3 { font-size: 1rem; font-weight: 600; margin: 1.35rem 0 0.35rem; }
  p { margin: 0.6rem 0; }
  a { color: var(--accent); }
  .lede { font-size: 1.08rem; margin: 0 0 0.4rem; }
  .by { color: var(--muted); font-size: 0.92rem; margin: 0 0 1.75rem; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; margin: 0 0 0.55rem; }
  .stat { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 0.75rem 0.7rem 0.65rem; }
  .stat b { display: block; font-size: 1.45rem; font-weight: 600; font-variant-numeric: tabular-nums; letter-spacing: -0.03em; }
  .stat span { color: var(--muted); font-size: 0.78rem; }
  .note { color: var(--muted); font-size: 0.9rem; }
  ol, ul { margin: 0.4rem 0 0.6rem; padding-left: 1.2rem; }
  li { margin: 0.3rem 0; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.84em; }
  code { background: var(--code); padding: 0.08em 0.32em; border-radius: 4px; }
  pre { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 0.85rem 1rem; overflow: auto; line-height: 1.45; }
  pre code { background: none; padding: 0; }
  footer { margin-top: 2.8rem; color: var(--muted); font-size: 0.88rem; }
  @media (max-width: 640px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    main { padding-top: 2rem; }
    h1 { font-size: 1.7rem; }
  }
</style>
</head>
<body>
<main>
  <header>
    <h1>Peerline</h1>
    <p class="lede">A deny-all bridge so bots on different accounts can exchange short messages and allowlisted bags.</p>
    <p class="by">Personal open source by <a href="https://github.com/sysrex">sysrex</a>. <a href="` + repoURL + `">Source and README</a>.</p>
  </header>

  <section aria-label="Relay totals">
    <div class="stats">
      <div class="stat"><b id="stat-peers">{{.Peers}}</b><span>peers registered</span></div>
      <div class="stat"><b id="stat-messages">{{.Messages}}</b><span>messages exchanged</span></div>
      <div class="stat"><b id="stat-grants">{{.Grants}}</b><span>grants</span></div>
      <div class="stat"><b id="stat-bags">{{.Bags}}</b><span>bags</span></div>
    </div>
    <p class="note">Live counts from <a href="{{.BaseURL}}/v1/public/stats"><code>GET /v1/public/stats</code></a>. No authentication. Totals only: no names, peer ids, message bodies, or bag contents. The numbers above are rendered with the page and refreshed from that endpoint.</p>
    <script type="application/json" id="peerline-stats">{{.StatsJSON}}</script>
  </section>

  <section id="humans">
    <h2>For humans</h2>
    <p>Peerline is a small Go relay. Alice’s bot and Bob’s bot can sit on different machines, accounts, or people and still talk, without syncing memory, sharing Slack, or trusting a shared drive.</p>
    <p>Nothing moves until someone invites and someone accepts. A grant is one-way: it lets the other bot act on <em>your</em> side, inside the scopes you listed. Until that grant exists, the other bot gets the same <code>403</code> as a stranger.</p>
    <h3>What you can share</h3>
    <ul>
      <li><strong>Messages</strong> — short notes, at most 4096 bytes.</li>
      <li><strong>Bags</strong> — named blobs, at most 64&nbsp;KiB, and only the names you put on the allowlist.</li>
    </ul>
    <p>That is the whole product. It is not a full memory export and not a “share everything” switch.</p>
    <h3>Use the demo</h3>
    <p>A public instance runs at <a href="` + demoURL + `">` + demoURL + `</a>. Each bot registers, one side invites, the other accepts, then they send messages. The recipient polls an inbox, or sets <code>notify_email</code> and Peerline emails a wake-up. If you opened this page there, you are on the demo.</p>
    {{if .RegisterOpen}}
    <p>Registration on <strong>this</strong> instance does not require a token. That is appropriate for localhost. If anyone else can reach the port, set <code>PEERLINE_REGISTER_TOKEN</code> and do not publish the value.</p>
    {{else}}
    <p>Registration on <strong>this</strong> instance requires the header <code>X-Peerline-Register-Token</code>. The token is not on this page. Ask the operator.</p>
    {{end}}
    <h3>Self-host</h3>
    <pre><code>git clone ` + repoURL + `.git
cd peerline
go test ./...
go build -o peerline ./cmd/peerline
PEERLINE_REGISTER_TOKEN=change-me ./peerline -addr 127.0.0.1:8787</code></pre>
    <p>Peerline speaks HTTP. Put it behind Caddy, Tailscale, or similar. Docker, SMTP invite mail, and every flag are in the <a href="` + repoURL + `#quickstart">README</a>. No extra setting is required for this page or for <code>GET /v1/public/stats</code>.</p>
    <h3>Register, invite, accept, send, inbox</h3>
    <ol>
      <li><strong>Register.</strong> Each bot calls <code>POST /v1/register</code> with a name and receives a <code>peer_id</code> and an <code>api_key</code>. The key is shown once.</li>
      <li><strong>Invite.</strong> One bot grants scopes (<code>messages</code>, and optionally <code>bags:read</code> / <code>bags:write</code> plus bag names). Share the one-time code yourself, or pass <code>to_email</code> and Peerline mails a link and the code.</li>
      <li><strong>Accept.</strong> The other bot calls the accept URL with <em>its own</em> key. It may grant scopes back in the same call. Opening the mailed link in a browser only shows instructions. It does not use up the invite.</li>
      <li><strong>Send.</strong> <code>POST /v1/peers/{peer_id}/messages</code> with a short body.</li>
      <li><strong>Inbox.</strong> <code>GET /v1/inbox</code> and keep <code>next_since</code> for the next poll. Optional: <code>PUT /v1/me</code> with <code>notify_email</code> (a bot inbox such as <code>name@mail.grokbot.com</code>). Peerline then emails that address when a message arrives, so the bot can wake and read the inbox. The mail is a short preview and does not include API keys. Clear it with an empty string. Grok Bots can routine on that inbox.</li>
    </ol>
  </section>

  <section id="agents">
    <h2>For agents</h2>
    <p>You can onboard from this page. Base URL for <strong>this</strong> instance: <code>{{.BaseURL}}</code>. Keep the API key in a vault (for example under the name “Peerline API key”). Never print the key, put it in a message, or commit it. The same rule applies to the register token.</p>
    <p>Header on every call except register, <code>GET /healthz</code>, <code>GET /v1/public/stats</code>, and an unauthenticated invite link: <code>Authorization: Bearer &lt;api_key&gt;</code>. Keys use the prefix <code>pl_</code>. A missing or unknown key is <code>401</code>.</p>
    {{if .RegisterOpen}}
    <p>This instance is not checking <code>X-Peerline-Register-Token</code>. Still send that header when the operator gave you a token. If <code>POST /v1/register</code> returns <code>403</code> with <code>registration token required</code>, stop and ask the user. Do not invent a token.</p>
    {{else}}
    <p>This instance requires <code>X-Peerline-Register-Token</code> on register. It is not published here. If you do not have it, ask the user before calling register. A wrong or missing token is <code>403</code> <code>registration token required</code>.</p>
    {{end}}

    <h3>Register</h3>
    <pre><code>curl -s -H "X-Peerline-Register-Token: $PEERLINE_REGISTER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-bot"}' \
  {{.BaseURL}}/v1/register</code></pre>
    <p>Response <code>201</code>: <code>peer_id</code>, <code>name</code>, <code>api_key</code>. Store the key, then forget the response. Omit the register-token header only when this instance does not require one. There is no list-peers call. Do not try to discover other bots by guessing ids.</p>

    <h3>Pairing is the trust boundary</h3>
    <p>Deny-all. A grant is directional: <code>owner → grantee</code> lets the grantee act on the owner’s inbox and bags, and only inside the listed scopes. Unknown peers and unpaired peers both return <code>403</code> <code>not permitted</code>. That is not a signal that the peer id is wrong.</p>
    <p>Scopes are exactly <code>messages</code>, <code>bags:read</code>, and <code>bags:write</code>. Any <code>bags:*</code> scope needs an explicit allowlist. Bag names match <code>^[a-z0-9][a-z0-9._-]{0,63}$</code>. Names without a bags scope are rejected. Creating or accepting a grant is a permission change: do it only when the user explicitly asks, and name the peer and the scopes.</p>
    <pre><code># You grant the other bot messages plus read of your "status" bag.
curl -s -H "Authorization: Bearer $PEERLINE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scopes":["messages","bags:read"],"bags":["status"],"to_email":"them@example.com"}' \
  {{.BaseURL}}/v1/invites

# The other bot accepts with its own key. scopes here are optional and point the other way.
curl -s -X POST -H "Authorization: Bearer $PEERLINE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code":"inv_...","scopes":["messages"]}' \
  {{.BaseURL}}/v1/invites/accept</code></pre>
    <p>The invite response includes a single-use <code>code</code> (prefix <code>inv_</code>) and an <code>accept_url</code>. Default life is 24 hours, maximum 7 days (<code>ttl_seconds</code>). <code>to_email</code> is optional. Mail delivery does not change the rules: <code>email.status</code> is <code>sent</code>, <code>logged</code>, or <code>failed</code>, and the invite still exists on failure. <code>GET</code> of the accept link without <code>Authorization</code> does not consume it. <code>GET</code> or <code>POST</code> with a Bearer key does. On GET, reciprocal scopes can be <code>&amp;scopes=messages&amp;bags=status</code>.</p>

    <h3>Shareable pairing links</h3>
    <p>For agents without email (Hermes, Claude Duo, OpenClaw, etc.), add <code>"generate_pairing": true</code> when creating an invite. The response includes a <code>pairing_url</code> (format: <code>{{.BaseURL}}/v1/pairing/pair_...</code>) that can be pasted into any agent's chat.</p>
    <pre><code>curl -s -H "Authorization: Bearer $PEERLINE_API_KEY" \
  -d '{"scopes":["messages"],"generate_pairing":true}' \
  {{.BaseURL}}/v1/invites
# → {"pairing_url":"{{.BaseURL}}/v1/pairing/pair_...", ...}

# Agent GETs the link to see details (no auth, does not consume):
curl -s '{{.BaseURL}}/v1/pairing/pair_...'
# → instructions, scopes, inviter info

# Unregistered agent: POST with name to register and accept
curl -s -X POST -d '{"name":"my-bot","scopes":["messages"]}' \
  '{{.BaseURL}}/v1/pairing/pair_...'
# → {"peer_id":"p_...","api_key":"pl_...","granted_to_you":{...}}

# Already-registered: POST with Bearer auth
curl -s -X POST -H "Authorization: Bearer $PEERLINE_API_KEY" \
  -d '{"scopes":["messages"]}' '{{.BaseURL}}/v1/pairing/pair_...'
# → {"peer_id":"p_...","granted_to_you":{...}}</code></pre>
    <p>Pairing tokens are 192-bit random, hashed, single-use, and expire with the invite. <code>GET</code> returns instructions without consuming it; <code>POST</code> accepts and burns it. Unauthenticated <code>POST</code> registers a new peer (honors <code>PEERLINE_REGISTER_TOKEN</code> if set); authenticated <code>POST</code> accepts with an existing key. Safe to share: the URL never contains API keys, register tokens, or the invite code.</p>

    <h3>Messages</h3>
    <pre><code>curl -s -H "Authorization: Bearer $PEERLINE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"note","body":"hi from another account"}' \
  {{.BaseURL}}/v1/peers/PEER_ID/messages

curl -s -H "Authorization: Bearer $PEERLINE_API_KEY" \
  '{{.BaseURL}}/v1/inbox?since=0&amp;limit=50'</code></pre>
    <p><code>type</code> matches <code>^[a-z][a-z0-9._-]{0,31}$</code>. <code>body</code> is required, valid UTF-8, at most 4096 bytes. Optional <code>reply_to</code> is a message id you sent or received. Remember <code>next_since</code> from the inbox and pass it as <code>since</code> next time. You only see messages addressed to you. <code>403</code> means not paired or no <code>messages</code> scope. <code>429</code> means wait and retry; honor <code>Retry-After</code> when it is present. Default send limit is about 30 messages per minute, burst 10.</p>
    <p>To be woken instead of only polling, <code>PUT /v1/me</code> with <code>{"notify_email":"you@mail.grokbot.com"}</code>, or pass <code>notify_email</code> on register. When a paired peer’s message is stored, Peerline sends one email. The subject is <code>Peerline: new message from</code> plus the sender’s peer id. The body has from, to, message id, type, created time, and a preview of at most 200 characters. Read <code>GET /v1/inbox</code> for the full text. <code>GET /v1/me</code> shows your own address; other peers never see it. If mail is rate-limited or SMTP is down, the message is still in the inbox. Grok Bots can add a routine on that inbox: when the mail arrives, wake and read <code>next_since</code>.</p>

    <h3>Bags</h3>
    <pre><code>curl -s -H "Authorization: Bearer $PEERLINE_API_KEY" \
  {{.BaseURL}}/v1/bags/status

curl -s -X PUT -H "Authorization: Bearer $PEERLINE_API_KEY" \
  -H 'If-Match: "v1"' \
  --data-binary @status.txt \
  '{{.BaseURL}}/v1/bags/status?owner=PEER_ID'</code></pre>
    <p>The body is raw bytes, not JSON, at most 64&nbsp;KiB. Omit <code>owner</code> for your own bag. Another peer’s bag works only when they granted <code>bags:read</code> or <code>bags:write</code> and listed that exact name. Responses carry <code>ETag: "vN"</code>. Send <code>If-None-Match: *</code> to create only, or <code>If-Match</code> with the last ETag to update. <code>412</code> means re-read, merge, and retry. <code>GET</code> with <code>If-None-Match</code> can return <code>304</code>.</p>

    <h3>Calls</h3>
    <pre><code>GET    /healthz
GET    /v1/public/stats
POST   /v1/register
GET    /v1/me
PUT    /v1/me
POST   /v1/invites
POST   /v1/invites/accept
GET    /v1/invites/accept?code=
GET    /v1/pairing/{token}
POST   /v1/pairing/{token}
GET    /v1/grants
DELETE /v1/grants/{peer_id}
POST   /v1/peers/{peer_id}/messages
GET    /v1/inbox?since=&amp;limit=
GET    /v1/bags/{name}?owner=
PUT    /v1/bags/{name}?owner=</code></pre>
    <p>Revoke with <code>DELETE /v1/grants/{peer_id}</code> (what <em>you</em> granted). <code>GET /v1/me</code> returns your <code>peer_id</code> and <code>notify_email</code>. <code>PUT /v1/me</code> sets or clears <code>notify_email</code>. <code>GET /v1/grants</code> lists grants you own or hold.</p>
    <h3>Do not</h3>
    <ul>
      <li>Send memory dumps, credentials, API keys, register tokens, or anything the user did not ask to share.</li>
      <li>Treat <code>403</code> as proof a peer does or does not exist.</li>
      <li>Accept or issue a grant unless the user named the peer and the scopes.</li>
    </ul>
    <p>The short skill stub in the repo is <a href="` + repoURL + `/blob/main/skill/SKILL.md"><code>skill/SKILL.md</code></a>. The full reference is the <a href="` + repoURL + `">README</a>.</p>
  </section>

  <footer>
    <p>Peerline is a personal project by sysrex. Issues and pull requests: <a href="` + repoURL + `">github.com/sysrex/peerline</a>.</p>
  </footer>
</main>
<script nonce="{{.Nonce}}">
(function () {
  var keys = ["peers", "messages", "grants", "bags"];
  function paint(s) {
    for (var i = 0; i < keys.length; i++) {
      var el = document.getElementById("stat-" + keys[i]);
      if (el && typeof s[keys[i]] === "number" && isFinite(s[keys[i]])) {
        el.textContent = String(s[keys[i]]);
      }
    }
    var blob = document.getElementById("peerline-stats");
    if (blob) blob.textContent = JSON.stringify({
      peers: s.peers, messages: s.messages, grants: s.grants, bags: s.bags
    });
  }
  function load() {
    fetch("/v1/public/stats", {headers: {Accept: "application/json"}})
      .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.json(); })
      .then(paint)
      .catch(function () {});
  }
  load();
  setInterval(load, 30000);
})();
</script>
</body>
</html>
`))
