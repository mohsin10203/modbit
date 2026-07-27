package gateway

import (
	"context"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Provider egress control (MOD-A01k).
//
// Requirements: SDD v5.1 §10 ("provider egress allowlist"), INV-1 (hosted model traffic traverses
// the gateway), INV-2 (credentials exist only inside this boundary).
//
// # Why this is a library control and not only a deployment one
//
// A network policy on the gateway's pod is the outer fence, and it should exist. It is not
// sufficient on its own: it is applied by a different team in a different repository, it is absent
// in local and desktop deployments entirely, and it cannot distinguish one provider's traffic from
// another's. An adapter that follows a redirect to the cloud metadata endpoint, or that is
// misconfigured to point at an internal service, is doing something the pod policy may well permit.
//
// Guard sits in the adapter's own HTTP transport, so a provider adapter cannot reach a destination
// its capability record does not declare — including on a redirect, and including when DNS resolves
// a legitimate hostname to an illegitimate address.
//
// # What it defends against
//
//   - An adapter, plugin, or dependency reaching an internal service with a provider credential
//     attached.
//   - Cloud instance-metadata retrieval (169.254.169.254 and its IPv6 equivalent), the standard
//     path from server-side request forgery to full credential compromise.
//   - DNS rebinding: the hostname is on the allowlist, but resolves to a private address. The host
//     check alone would pass; the address check is what catches it.
//   - A redirect chain that starts at an allowed host and ends somewhere else. Each hop is a
//     separate RoundTrip, so each hop is checked.

// Destination declares where one provider may be reached.
type Destination struct {
	// Hosts are permitted hostnames. A leading "*." permits exactly one or more subdomain labels,
	// so "*.acme.test" admits "api.acme.test" but not "acme.test" itself.
	Hosts []string
	// AllowPlaintext permits http://. Hosted providers must never set it; a credential on a
	// plaintext connection is a credential on the wire.
	AllowPlaintext bool
	// AllowPrivateNetwork permits resolution to loopback, private, or link-local addresses.
	//
	// Local inference endpoints — Ollama, vLLM, an LM Studio-compatible server — legitimately live
	// on 127.0.0.1, so the capability must exist. A *hosted* provider resolving to a private
	// address is either a rebind or a misconfiguration, and is refused.
	AllowPrivateNetwork bool
}

// EgressPolicy maps provider identifiers to their permitted destinations.
//
// A provider absent from the map is denied. Fail-closed matters more here than convenience: the
// failure mode of an accidentally permissive default is a credential delivered to an attacker.
type EgressPolicy struct {
	destinations map[string]Destination
}

// NewEgressPolicy validates and returns a policy.
func NewEgressPolicy(destinations map[string]Destination) (*EgressPolicy, error) {
	out := &EgressPolicy{destinations: make(map[string]Destination, len(destinations))}
	for provider, d := range destinations {
		if provider == "" {
			return nil, modberr.New(modberr.CodeInvalidArgument, "egress policy has an empty provider id")
		}
		if len(d.Hosts) == 0 {
			return nil, modberr.Newf(modberr.CodeInvalidArgument,
				"provider %q declares no permitted hosts; an empty allowlist is denied, not unrestricted", provider)
		}
		normalized := make([]string, 0, len(d.Hosts))
		for _, h := range d.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" || h == "*" {
				// "*" would turn the allowlist into a no-op while looking configured.
				return nil, modberr.Newf(modberr.CodeInvalidArgument,
					"provider %q declares a wildcard host; egress must name its destinations", provider)
			}
			normalized = append(normalized, h)
		}
		sort.Strings(normalized)
		d.Hosts = normalized
		out.destinations[strings.ToLower(provider)] = d
	}
	return out, nil
}

// Destination returns the rule for a provider.
func (p *EgressPolicy) Destination(providerID string) (Destination, bool) {
	d, ok := p.destinations[strings.ToLower(providerID)]
	return d, ok
}

// Resolver looks up a hostname. Injected so egress decisions are testable without DNS.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type systemResolver struct{}

func (systemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// Guard is an http.RoundTripper enforcing a provider's egress policy.
//
// One Guard serves one provider, because the whole point is that a provider's transport cannot
// reach another provider's destinations.
type Guard struct {
	providerID  string
	destination Destination
	base        http.RoundTripper
	resolver    Resolver
}

var _ http.RoundTripper = (*Guard)(nil)

// Transport returns a RoundTripper for providerID.
//
// A provider with no declared destination is refused here rather than at request time: an adapter
// constructed with a working transport that denies everything is harder to diagnose than one that
// could not be constructed at all.
func (p *EgressPolicy) Transport(providerID string, base http.RoundTripper, resolver Resolver) (*Guard, error) {
	d, ok := p.Destination(providerID)
	if !ok {
		return nil, modberr.Newf(modberr.CodePolicyDenied,
			"provider %q has no declared egress destination", providerID).
			WithDetail("rule_id", "egress.no_destination")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	if resolver == nil {
		resolver = systemResolver{}
	}
	return &Guard{providerID: providerID, destination: d, base: base, resolver: resolver}, nil
}

// RoundTrip refuses any request outside the provider's declared destination.
//
// It runs per hop, so a redirect chain is checked at every step rather than only at the origin.
func (g *Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.check(req.Context(), req.URL.Scheme, req.URL.Hostname()); err != nil {
		return nil, err
	}
	return g.base.RoundTrip(req)
}

// Check reports whether a scheme and host are permitted. Exported so a caller can validate a
// configured endpoint at startup instead of on the first request.
func (g *Guard) Check(ctx context.Context, scheme, host string) error {
	return g.check(ctx, scheme, host)
}

func (g *Guard) check(ctx context.Context, scheme, host string) error {
	deny := func(rule, msg string) error {
		return modberr.Newf(modberr.CodePolicyDenied, "egress denied: %s", msg).
			WithDetail("rule_id", rule)
	}

	switch strings.ToLower(scheme) {
	case "https":
	case "http":
		if !g.destination.AllowPlaintext {
			return deny("egress.plaintext_denied",
				"plaintext http is not permitted for this provider")
		}
	default:
		return deny("egress.scheme_denied", "only http and https are permitted")
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return deny("egress.empty_host", "request has no host")
	}
	if !g.hostAllowed(host) {
		return deny("egress.host_not_allowed", "host is not in the provider's allowlist")
	}

	// The host check alone is satisfied by a rebind: an allowlisted name whose DNS record points at
	// an internal address. Resolving and checking the addresses is what closes that.
	ips, err := g.resolveHost(ctx, host)
	if err != nil {
		return modberr.Wrap(err, modberr.CodePolicyDenied,
			"egress denied: the destination could not be resolved for address checking").
			WithDetail("rule_id", "egress.unresolvable")
	}
	for _, ip := range ips {
		if blockedAddress(ip) && !g.destination.AllowPrivateNetwork {
			return deny("egress.private_address_denied",
				"the destination resolves to a loopback, private, or link-local address")
		}
	}
	return nil
}

func (g *Guard) resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	// A literal address needs no lookup, and passing one to a resolver would let a resolver
	// implementation decide whether to honour it.
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return g.resolver.LookupIP(ctx, host)
}

// hostAllowed matches against the provider's allowlist. A "*." prefix permits subdomains but not
// the bare domain, so a wildcard cannot accidentally widen to the apex.
func (g *Guard) hostAllowed(host string) bool {
	for _, allowed := range g.destination.Hosts {
		if suffix, ok := strings.CutPrefix(allowed, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == allowed {
			return true
		}
	}
	return false
}

// blockedAddress reports whether an address is one a hosted provider must never resolve to.
//
// Link-local is listed first because it is the one that matters most: 169.254.169.254 and
// fd00:ec2::254 are the cloud instance-metadata endpoints, and reaching them from a process holding
// provider credentials is the standard escalation from request forgery to full compromise.
func blockedAddress(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 (::ffff:169.254.169.254) so a mapped form cannot bypass the checks.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return true
	case ip.IsLoopback():
		return true
	case ip.IsPrivate():
		return true
	case ip.IsUnspecified():
		return true
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return true
	}
	// 100.64.0.0/10, carrier-grade NAT, is where cloud providers place internal service endpoints
	// that net.IP.IsPrivate does not cover.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// Providers returns every provider with a declared destination, sorted.
func (p *EgressPolicy) Providers() []string {
	out := make([]string, 0, len(p.destinations))
	for provider := range p.destinations {
		out = append(out, provider)
	}
	sort.Strings(out)
	return out
}
