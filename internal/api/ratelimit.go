package api

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sysrex/peerline/internal/clock"
	"github.com/sysrex/peerline/internal/msg"
)

// rejectedIPv4Prefixes lists IPv4 transition ranges that are rejected
// from trusted proxy lists because they cover arbitrary clients.
var rejectedIPv4Prefixes = [...]struct {
	prefix netip.Prefix
	errMsg string
}{
	{netip.MustParsePrefix("192.88.99.0/24"), "overlaps 6to4 relay anycast prefix 192.88.99.0/24"},
}

// rejectedIPv6Prefixes lists IPv6 transition/translation ranges that are rejected
// from trusted proxy lists because they cover arbitrary clients.
var rejectedIPv6Prefixes = [...]struct {
	prefix netip.Prefix
	errMsg string
}{
	{netip.MustParsePrefix("2001::/32"), "overlaps Teredo prefix 2001::/32"},
	{netip.MustParsePrefix("64:ff9b::/96"), "overlaps NAT64 well-known prefix 64:ff9b::/96"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "overlaps NAT64 local prefix 64:ff9b:1::/48"},
	{netip.MustParsePrefix("2002::/16"), "overlaps 6to4 prefix 2002::/16"},
}

// clientIP returns the client IP, honoring X-Forwarded-For only from trusted proxies.
// It walks X-Forwarded-For right-to-left, skipping entries in trustedNets, and returns
// the first untrusted IP. Only consults XFF when RemoteAddr itself is trusted.
// IPs are normalized (IPv4-mapped IPv6 → IPv4, canonical form, no zone/port).
// Combines all X-Forwarded-For header lines (clients may send multiple headers).
func clientIP(remoteAddr string, xffHeaders []string, trustedNets []*net.IPNet) string {
	// Parse and normalize RemoteAddr
	remoteIP := parseAndNormalizeIP(remoteAddr)
	if remoteIP == "" {
		return remoteAddr // fallback to raw string if unparseable
	}

	// If no trusted proxies configured, always use RemoteAddr
	if len(trustedNets) == 0 {
		return remoteIP
	}

	// Check if RemoteAddr is a trusted proxy
	remoteAddr_parsed, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return remoteIP
	}

	trusted := false
	for _, ipnet := range trustedNets {
		if ipnet.Contains(net.IP(remoteAddr_parsed.AsSlice())) {
			trusted = true
			break
		}
	}

	// If RemoteAddr is not from a trusted proxy, ignore X-Forwarded-For
	if !trusted {
		return remoteIP
	}

	// Parse all X-Forwarded-For headers and combine them
	// Each header value may contain comma-separated IPs
	if len(xffHeaders) == 0 {
		return remoteIP
	}

	var allIPs []string
	for _, header := range xffHeaders {
		parts := strings.Split(header, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				allIPs = append(allIPs, trimmed)
			}
		}
	}

	// Walk right-to-left through all IPs, cap at 50 entries to prevent DoS
	maxEntries := 50
	stopIdx := 0
	if len(allIPs) > maxEntries {
		stopIdx = len(allIPs) - maxEntries
	}

	// Track the rightmost trusted IP we've seen (for fallback on malformed entry)
	lastTrustedIP := remoteIP

	for i := len(allIPs) - 1; i >= stopIdx; i-- {
		candidate := allIPs[i]

		// Normalize the candidate
		normalized := parseAndNormalizeIP(candidate)
		if normalized == "" {
			// Invalid IP, stop and fall back to last trusted hop (#61)
			return lastTrustedIP
		}

		candidateAddr, err := netip.ParseAddr(normalized)
		if err != nil {
			// Parse error, stop and fall back to last trusted hop (#61)
			return lastTrustedIP
		}

		// Check if this IP is in a trusted CIDR
		isTrusted := false
		for _, ipnet := range trustedNets {
			if ipnet.Contains(net.IP(candidateAddr.AsSlice())) {
				isTrusted = true
				break
			}
		}

		// If not trusted, this is the real client IP
		if !isTrusted {
			return normalized
		}

		// This IP is trusted, remember it as potential fallback
		lastTrustedIP = normalized
	}

	// All XFF entries were trusted, fall back to RemoteAddr
	return remoteIP
}

// parseAndNormalizeIP extracts an IP from a host:port or bare IP string,
// and returns it in canonical form (IPv4-mapped IPv6 → IPv4, no zone).
func parseAndNormalizeIP(s string) string {
	// Try parsing as host:port first
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		// Not a host:port, try as bare IP
		host = s
	}

	// Handle bare bracketed IPv6 (e.g., "[2001:db8::1]")
	// Only strip brackets if the interior is a valid IPv6 address
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		interior := host[1 : len(host)-1]
		if addr, err := netip.ParseAddr(interior); err == nil && addr.Is6() {
			host = interior
		}
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}

	// Unmap IPv4-mapped IPv6 addresses, remove zone
	addr = addr.Unmap().WithZone("")
	return addr.String()
}

// rateLimitKey returns a normalized key for rate limiting.
// For IPv6 addresses, returns the /64 prefix to prevent attackers from evicting
// hot buckets by rotating through IPv6 addresses within their allocation.
// For IPv4, returns the full address.
func rateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}

	// Unmap first (e.g., ::ffff:1.2.3.4 → 1.2.3.4)
	addr = addr.Unmap()

	// IPv6: use /64 prefix (standard delegation size)
	if addr.Is6() {
		prefix := netip.PrefixFrom(addr, 64)
		return prefix.Masked().Addr().String()
	}

	// IPv4: use full address
	return addr.String()
}

// ParseTrustedProxies parses a list of CIDR strings (or bare IPs) into IPNets.
// Rejects overly broad prefixes (0.0.0.0/0, ::/0, and prefixes shorter than
// /8 for IPv4 or /32 for IPv6) to prevent misconfiguration (#62).
// IPv4-mapped IPv6 prefixes (e.g., ::ffff:10.0.0.0/104) are unmapped and
// converted to IPv4 (10.0.0.0/8), with the IPv4 /8 floor applied.
// Rejects zone identifiers (e.g., fe80::1%eth0).
// Rejects 0.0.0.0/8 ("this network") and its IPv4-mapped form.
// Rejects IPv4 6to4 relay anycast prefix 192.88.99.0/24.
// Rejects IPv6 transition/translation prefixes: Teredo 2001::/32,
// NAT64 64:ff9b::/96 and 64:ff9b:1::/48, and 6to4 2002::/16.
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	nets, _, err := ParseTrustedProxiesWithOpts(cidrs, false)
	return nets, err
}

// ParseTrustedProxiesWithOpts parses trusted proxies with optional broader IPv6 floor.
// When allowBroadIPv6 is true, the IPv6 floor is /29 (allowing Cloudflare 2a06:98c0::/29,
// and rejecting 2000::/3 as too broad), and ULA ranges contained in fc00::/7
// (bits >= 7) are permitted. ::/0 is always rejected.
// IPv4 6to4 relay anycast prefix 192.88.99.0/24 is always rejected.
// IPv6 transition/translation prefixes are always rejected: Teredo 2001::/32,
// NAT64 64:ff9b::/96 and 64:ff9b:1::/48, and 6to4 2002::/16.
// Returns the parsed networks and a list of entries that were accepted only because allowBroadIPv6 was true.
func ParseTrustedProxiesWithOpts(cidrs []string, allowBroadIPv6 bool) ([]*net.IPNet, []string, error) {
	var nets []*net.IPNet
	var relaxed []string
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Reject zone identifiers
		if strings.Contains(cidr, "%") {
			return nil, nil, fmt.Errorf("parsing %q: zone identifiers are not allowed", cidr)
		}

		// Parse as prefix or bare IP
		var prefix netip.Prefix
		var err error
		if strings.Contains(cidr, "/") {
			// CIDR notation
			prefix, err = netip.ParsePrefix(cidr)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing %q: %w", cidr, err)
			}
		} else {
			// Bare IP - convert to /32 or /128
			addr, err := netip.ParseAddr(cidr)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing %q: %w", cidr, err)
			}
			// Bare IPv4-mapped IPv6 addresses like ::ffff:10.0.0.1 should unmap to IPv4/32
			if addr.Is4In6() {
				addr = addr.Unmap()
			}
			if addr.Is4() {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				prefix = netip.PrefixFrom(addr, 128)
			}
		}

		// Check for IPv4-mapped IPv6 prefixes BEFORE masking
		addr := prefix.Addr()
		if addr.Is4In6() {
			// This is an IPv4-mapped IPv6 prefix like ::ffff:10.0.0.0/104
			bits := prefix.Bits()
			if bits < 96 {
				return nil, nil, fmt.Errorf("parsing %q: IPv4-mapped IPv6 prefix must be at least /96", cidr)
			}
			ipv4PrefixLen := bits - 96
			// Apply IPv4 rules: reject /0, require at least /8
			if ipv4PrefixLen == 0 {
				return nil, nil, fmt.Errorf("parsing %q: IPv4-mapped prefix covers all of IPv4 (equivalent to 0.0.0.0/0)", cidr)
			}
			if ipv4PrefixLen < 8 {
				return nil, nil, fmt.Errorf("parsing %q: IPv4-mapped prefix must map to at least /8 in IPv4 (need /%d or longer)", cidr, 96+8)
			}
			// Unmap to native IPv4 prefix
			unmapped := addr.Unmap()
			prefix = netip.PrefixFrom(unmapped, ipv4PrefixLen)
		}

		// Normalize the prefix (mask it)
		prefix = prefix.Masked()

		// Check prefix length
		bits := prefix.Bits()
		if bits == 0 {
			return nil, nil, fmt.Errorf("parsing %q: prefix length /0 is too broad", cidr)
		}
		if prefix.Addr().Is4() {
			if bits < 8 {
				return nil, nil, fmt.Errorf("parsing %q: IPv4 prefix must be at least /8", cidr)
			}
			// Reject any prefix that overlaps 0.0.0.0/8 ("this network")
			thisNet := netip.MustParsePrefix("0.0.0.0/8")
			if thisNet.Overlaps(prefix) {
				return nil, nil, fmt.Errorf("parsing %q: overlaps 0.0.0.0/8 (this network)", cidr)
			}
			// Reject IPv4 transition prefixes that cover arbitrary clients
			// (after floor check, so overly broad prefixes get the floor error)
			for _, rejected := range rejectedIPv4Prefixes {
				if rejected.prefix.Overlaps(prefix) {
					return nil, nil, fmt.Errorf("parsing %q: %s", cidr, rejected.errMsg)
				}
			}
		} else {
			// IPv6: apply floor and additional checks
			addr := prefix.Addr()

			// Check if prefix is ULA (fc00::/7) and contained within fc00::/7
			// (bits >= 7 ensures it's not broader than fc00::/7 itself)
			isContainedULA := (addr.As16()[0] == 0xfc || addr.As16()[0] == 0xfd) && bits >= 7

			// Apply floor: /32 by default, /29 with allowBroadIPv6
			// Exception: with opt-in, ULA contained in fc00::/7 is exempt from floor
			minBits := 32
			neededOptIn := false
			if allowBroadIPv6 {
				if isContainedULA {
					// ULA ranges contained in fc00::/7 are exempt from floor with opt-in
					if bits < 32 {
						neededOptIn = true
					}
					minBits = 0 // no floor for contained ULA
				} else {
					// Public IPv6: floor is /29 with opt-in
					if bits < 32 && bits >= 29 {
						neededOptIn = true
					}
					minBits = 29
				}
			}

			if bits < minBits {
				return nil, nil, fmt.Errorf("parsing %q: IPv6 prefix must be at least /%d", cidr, minBits)
			}

			// Reject transition/translation prefixes that cover arbitrary clients
			// (after floor check, so overly broad prefixes get the floor error)
			for _, rejected := range rejectedIPv6Prefixes {
				if rejected.prefix.Overlaps(prefix) {
					return nil, nil, fmt.Errorf("parsing %q: %s", cidr, rejected.errMsg)
				}
			}

			if neededOptIn {
				relaxed = append(relaxed, prefix.String())
			}
		}

		// Convert netip.Prefix to *net.IPNet
		// We need to convert because clientIP uses []*net.IPNet
		ipnetStr := prefix.String()
		_, ipnet, err := net.ParseCIDR(ipnetStr)
		if err != nil {
			return nil, nil, fmt.Errorf("converting %q to IPNet: %w", ipnetStr, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, relaxed, nil
}

// categorizeRelaxed examines the relaxed entries and returns whether they contain
// public /29 prefixes or ULA prefixes. Used to word warnings precisely.
func categorizeRelaxed(relaxed []string) (hasPublic bool, hasULA bool) {
	for _, s := range relaxed {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		if addr.Is6() {
			// Check if this is a ULA prefix (starts with fc or fd)
			if addr.As16()[0] == 0xfc || addr.As16()[0] == 0xfd {
				hasULA = true
			} else {
				hasPublic = true
			}
		}
	}
	return
}

// relaxedWarning returns the appropriate warning message based on which types
// of relaxed entries were detected. Extracted for testing.
func relaxedWarning(hasPublic, hasULA bool) string {
	if hasPublic && hasULA {
		return "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled: trusting a public /29 lets anyone inside it spoof X-Forwarded-For; ULA (fc00::/7) ranges are also permitted and exempt from the /32 floor"
	}
	if hasPublic {
		return "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled: trusting a public /29 lets anyone inside it spoof X-Forwarded-For"
	}
	if hasULA {
		return "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled: ULA (fc00::/7) ranges are permitted and exempt from the /32 floor"
	}
	// Fallback when categorization cannot classify the relaxed entries (e.g., unparsable)
	return "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled: broader ranges are permitted"
}

// LimiterManager manages multiple rate limiters with proper lifecycle and pruning.
type LimiterManager struct {
	msgLim        *msg.Limiter
	regLim        *msg.Limiter
	pairLim       *msg.Limiter
	failLim       *msg.Limiter // Failed auth lookups (per-IP)
	getLim        *msg.Limiter
	versionLim    *msg.Limiter // Dedicated limiter for /version
	authLim       *msg.Limiter
	writeLim      *msg.Limiter // Authenticated write operations (per-peer)
	bagWriteLim   *msg.Limiter // Bag PUTs, keyed by authenticated caller (never the bag owner)
	mailLim       *msg.Limiter
	rcptLim       *msg.Limiter
	notifyLim     *msg.Limiter
	notifyAddrLim *msg.Limiter // Per-address notification rate limit

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Rate limit constants for public GET, authenticated GET, registration, pairing,
// version, and bag write endpoints.
const (
	getPerMinute      = 60
	getBurst          = 20
	authGetPerMinute  = 120
	authGetBurst      = 40
	regPerMinute      = 10
	regBurst          = 5
	pairPerMinute     = 10
	pairBurst         = 5
	versionPerMinute  = 120
	versionBurst      = 30
	bagWritePerMinute = 30
	bagWriteBurst     = 10
)

// NewLimiterManager creates and starts a new limiter manager.
func NewLimiterManager(cfg Config) *LimiterManager {
	ctx, cancel := context.WithCancel(context.Background())
	clk := msg.WithClock(clock.Or(cfg.Clock).Now)
	lm := &LimiterManager{
		msgLim:        msg.NewLimiter(cfg.MsgPerMinute, cfg.MsgBurst, clk),
		regLim:        msg.NewLimiter(regPerMinute, regBurst, clk),
		pairLim:       msg.NewLimiter(pairPerMinute, pairBurst, clk),
		failLim:       msg.NewLimiter(cfg.AuthFailPerMinute, cfg.AuthFailBurst, clk),
		getLim:        msg.NewLimiter(getPerMinute, getBurst, clk),
		versionLim:    msg.NewLimiter(versionPerMinute, versionBurst, clk), // Separate limiter for /version to avoid monitor conflicts
		authLim:       msg.NewLimiter(authGetPerMinute, authGetBurst, clk),
		writeLim:      msg.NewLimiter(cfg.WritePerMinute, cfg.WriteBurst, clk),
		bagWriteLim:   msg.NewLimiter(bagWritePerMinute, bagWriteBurst, clk),
		mailLim:       msg.NewLimiterPerHour(cfg.EmailPerHour, cfg.EmailBurst, clk),
		rcptLim:       msg.NewLimiterPerHour(cfg.EmailRcptPerHour, cfg.EmailRcptPerHour, clk),
		notifyLim:     msg.NewLimiterPerHour(cfg.NotifyPerHour, cfg.NotifyBurst, clk),
		notifyAddrLim: msg.NewLimiterPerHour(cfg.NotifyPerHour, cfg.NotifyBurst, clk), // Same limits, but per-address
		ctx:           ctx,
		cancel:        cancel,
	}

	lm.wg.Add(1)
	go lm.pruneLoop()

	return lm
}

// all returns all limiters in a single list for iteration.
func (lm *LimiterManager) all() []*msg.Limiter {
	return []*msg.Limiter{
		lm.msgLim,
		lm.regLim,
		lm.pairLim,
		lm.failLim,
		lm.getLim,
		lm.versionLim,
		lm.authLim,
		lm.writeLim,
		lm.bagWriteLim,
		lm.mailLim,
		lm.rcptLim,
		lm.notifyLim,
		lm.notifyAddrLim,
	}
}

// pruneLoop periodically prunes stale buckets from all limiters.
func (lm *LimiterManager) pruneLoop() {
	defer lm.wg.Done()
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-lm.ctx.Done():
			return
		case <-ticker.C:
			lm.prune()
		}
	}
}

func (lm *LimiterManager) prune() {
	pruned := 0
	for _, lim := range lm.all() {
		pruned += lim.Prune()
	}
	_ = pruned // Could log if needed
}

// Stop gracefully stops the limiter manager's background goroutines.
func (lm *LimiterManager) Stop() {
	lm.cancel()
	lm.wg.Wait()
}
