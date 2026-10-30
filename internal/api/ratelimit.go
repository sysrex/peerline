package api

import (
	"context"
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

	// Walk right-to-left through all IPs
	for i := len(allIPs) - 1; i >= 0; i-- {
		candidate := allIPs[i]

		// Normalize the candidate
		normalized := parseAndNormalizeIP(candidate)
		if normalized == "" {
			// Invalid IP, skip
			continue
		}

		candidateAddr, err := netip.ParseAddr(normalized)
		if err != nil {
			continue
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
	}

	// All XFF entries were trusted (or malformed), fall back to RemoteAddr
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
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// If it doesn't contain a slash, treat it as a single IP
		if !strings.Contains(cidr, "/") {
			// Parse as IP and make it a /32 or /128
			addr, err := netip.ParseAddr(cidr)
			if err != nil {
				return nil, err
			}
			var ipnet *net.IPNet
			if addr.Is4() {
				_, ipnet, _ = net.ParseCIDR(cidr + "/32")
			} else {
				_, ipnet, _ = net.ParseCIDR(cidr + "/128")
			}
			nets = append(nets, ipnet)
			continue
		}

		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
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
	failLim       *msg.Limiter // Failed pairing token lookups (per-IP)
	getLim        *msg.Limiter
	authLim       *msg.Limiter
	mailLim       *msg.Limiter
	rcptLim       *msg.Limiter
	notifyLim     *msg.Limiter
	notifyAddrLim *msg.Limiter // Per-address notification rate limit

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewLimiterManager creates and starts a new limiter manager.
func NewLimiterManager(cfg Config) *LimiterManager {
	ctx, cancel := context.WithCancel(context.Background())
	lm := &LimiterManager{
		msgLim:        msg.NewLimiter(cfg.MsgPerMinute, cfg.MsgBurst),
		regLim:        msg.NewLimiter(10, 5),
		pairLim:       msg.NewLimiter(10, 5),
		failLim:       msg.NewLimiter(30, 10), // Failed pairing lookups: more lenient per-IP budget
		getLim:        msg.NewLimiter(60, 20),
		authLim:       msg.NewLimiter(120, 40), // Higher limit for authenticated polling
		mailLim:       msg.NewLimiterPerHour(cfg.EmailPerHour, cfg.EmailBurst),
		rcptLim:       msg.NewLimiterPerHour(cfg.EmailRcptPerHour, cfg.EmailRcptPerHour),
		notifyLim:     msg.NewLimiterPerHour(cfg.NotifyPerHour, cfg.NotifyBurst),
		notifyAddrLim: msg.NewLimiterPerHour(cfg.NotifyPerHour, cfg.NotifyBurst), // Same limits, but per-address
		ctx:           ctx,
		cancel:        cancel,
	}

	lm.wg.Add(1)
	go lm.pruneLoop()

	return lm
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
	pruned := lm.msgLim.Prune() + lm.regLim.Prune() + lm.pairLim.Prune() + lm.failLim.Prune() +
		lm.getLim.Prune() + lm.authLim.Prune() +
		lm.mailLim.Prune() + lm.rcptLim.Prune() + lm.notifyLim.Prune() + lm.notifyAddrLim.Prune()
	_ = pruned // Could log if needed
}

// Stop gracefully stops the limiter manager's background goroutines.
func (lm *LimiterManager) Stop() {
	lm.cancel()
	lm.wg.Wait()
}
