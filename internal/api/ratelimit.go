package api

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sysrex/peerline/internal/msg"
)

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
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Reject zone identifiers
		if strings.Contains(cidr, "%") {
			return nil, fmt.Errorf("parsing %q: zone identifiers are not allowed", cidr)
		}

		// Parse as prefix or bare IP
		var prefix netip.Prefix
		var err error
		if strings.Contains(cidr, "/") {
			// CIDR notation
			prefix, err = netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("parsing %q: %w", cidr, err)
			}
		} else {
			// Bare IP - convert to /32 or /128
			addr, err := netip.ParseAddr(cidr)
			if err != nil {
				return nil, fmt.Errorf("parsing %q: %w", cidr, err)
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
				return nil, fmt.Errorf("parsing %q: IPv4-mapped IPv6 prefix must be at least /96", cidr)
			}
			ipv4PrefixLen := bits - 96
			// Apply IPv4 rules: reject /0, require at least /8
			if ipv4PrefixLen == 0 {
				return nil, fmt.Errorf("parsing %q: IPv4-mapped prefix covers all of IPv4 (equivalent to 0.0.0.0/0)", cidr)
			}
			if ipv4PrefixLen < 8 {
				return nil, fmt.Errorf("parsing %q: IPv4-mapped prefix must map to at least /8 in IPv4 (need /%d or longer)", cidr, 96+8)
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
			return nil, fmt.Errorf("parsing %q: prefix length /0 is too broad", cidr)
		}
		if prefix.Addr().Is4() {
			if bits < 8 {
				return nil, fmt.Errorf("parsing %q: IPv4 prefix must be at least /8", cidr)
			}
		} else {
			if bits < 32 {
				return nil, fmt.Errorf("parsing %q: IPv6 prefix must be at least /32", cidr)
			}
		}

		// Convert netip.Prefix to *net.IPNet
		// We need to convert because clientIP uses []*net.IPNet
		ipnetStr := prefix.String()
		_, ipnet, err := net.ParseCIDR(ipnetStr)
		if err != nil {
			return nil, fmt.Errorf("converting %q to IPNet: %w", ipnetStr, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// LimiterManager manages multiple rate limiters with proper lifecycle and pruning.
type LimiterManager struct {
	msgLim        *msg.Limiter
	regLim        *msg.Limiter
	pairLim       *msg.Limiter
	getLim        *msg.Limiter
	authLim       *msg.Limiter
	bagLim        *msg.Limiter // Bag writes, per authenticated caller
	mailLim       *msg.Limiter
	rcptLim       *msg.Limiter
	notifyLim     *msg.Limiter
	notifyAddrLim *msg.Limiter // Per-address notification rate limit

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Rate limit constants for public GET endpoints and authenticated endpoints.
const (
	getPerMinute     = 60
	getBurst         = 20
	authGetPerMinute = 120
	authGetBurst     = 40
)

// NewLimiterManager creates and starts a new limiter manager.
func NewLimiterManager(cfg Config) *LimiterManager {
	ctx, cancel := context.WithCancel(context.Background())
	clk := msg.WithClock(cfg.Now)
	lm := &LimiterManager{
		msgLim:        msg.NewLimiter(cfg.MsgPerMinute, cfg.MsgBurst, clk),
		regLim:        msg.NewLimiter(10, 5, clk),
		pairLim:       msg.NewLimiter(10, 5, clk),
		bagLim:        msg.NewLimiter(10, 5, clk),
		getLim:        msg.NewLimiter(getPerMinute, getBurst, clk),
		authLim:       msg.NewLimiter(authGetPerMinute, authGetBurst, clk),
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
		lm.bagLim,
		lm.getLim,
		lm.authLim,
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
