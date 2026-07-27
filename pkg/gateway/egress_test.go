package gateway_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/modbit/modbit/pkg/gateway"
	"github.com/modbit/modbit/pkg/modberr"
)

// stubResolver returns fixed addresses so egress decisions are deterministic and need no DNS.
type stubResolver struct {
	addrs map[string][]net.IP
	err   error
}

func (s stubResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if s.err != nil {
		return nil, s.err
	}
	if ips, ok := s.addrs[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

// countingTransport records whether a request was allowed through to the network.
type countingTransport struct{ attempts int }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.attempts++
	return nil, errors.New("network dial suppressed in tests")
}

func hostedPolicy(t *testing.T) *gateway.EgressPolicy {
	t.Helper()
	p, err := gateway.NewEgressPolicy(map[string]gateway.Destination{
		"acme": {Hosts: []string{"api.acme.test", "*.regional.acme.test"}},
		"local": {
			Hosts:          []string{"localhost", "127.0.0.1"},
			AllowPlaintext: true, AllowPrivateNetwork: true,
		},
	})
	if err != nil {
		t.Fatalf("NewEgressPolicy: %v", err)
	}
	return p
}

func guard(t *testing.T, provider string, resolver gateway.Resolver) (*gateway.Guard, *countingTransport) {
	t.Helper()
	base := &countingTransport{}
	g, err := hostedPolicy(t).Transport(provider, base, resolver)
	if err != nil {
		t.Fatalf("Transport(%q): %v", provider, err)
	}
	return g, base
}

func publicResolver() stubResolver {
	return stubResolver{addrs: map[string][]net.IP{
		"api.acme.test":         {net.ParseIP("203.0.113.10")},
		"eu.regional.acme.test": {net.ParseIP("203.0.113.11")},
		"localhost":             {net.ParseIP("127.0.0.1")},
	}}
}

// An empty or wildcard allowlist would look configured while permitting everything.
func TestEgressPolicyRejectsAnEmptyOrWildcardAllowlist(t *testing.T) {
	t.Parallel()
	if _, err := gateway.NewEgressPolicy(map[string]gateway.Destination{"acme": {}}); err == nil {
		t.Error("a provider with no hosts must be refused")
	}
	if _, err := gateway.NewEgressPolicy(map[string]gateway.Destination{
		"acme": {Hosts: []string{"*"}},
	}); err == nil {
		t.Error("a wildcard host must be refused; egress must name its destinations")
	}
}

// A provider absent from the policy is denied, and denied at construction rather than at request
// time: a transport that silently refuses everything is harder to diagnose than one that could not
// be built.
func TestUndeclaredProviderCannotObtainATransport(t *testing.T) {
	t.Parallel()
	_, err := hostedPolicy(t).Transport("unknown", nil, publicResolver())
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want MODBIT_POLICY_DENIED", err)
	}
}

func TestAllowedDestinationPassesTheGuard(t *testing.T) {
	t.Parallel()
	g, base := guard(t, "acme", publicResolver())

	for _, url := range []string{
		"https://api.acme.test/v1/messages",
		"https://eu.regional.acme.test/v1/messages",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
		if _, err := g.RoundTrip(req); err == nil {
			t.Fatalf("%s: expected the suppressed-dial error from the base transport", url)
		} else if modberr.Is(err, modberr.CodePolicyDenied) {
			t.Fatalf("%s was denied by the guard: %v", url, err)
		}
	}
	if base.attempts != 2 {
		t.Errorf("base transport saw %d requests, want 2", base.attempts)
	}
}

// The defining case: an allowlisted hostname whose DNS record points somewhere internal. The host
// check alone passes; the address check is what catches it.
func TestSecurityDNSRebindToAPrivateAddressIsRefused(t *testing.T) {
	t.Parallel()
	rebind := stubResolver{addrs: map[string][]net.IP{
		"api.acme.test": {net.ParseIP("10.0.0.5")},
	}}
	g, base := guard(t, "acme", rebind)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://api.acme.test/v1/messages", nil)
	_, err := g.RoundTrip(req)
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want MODBIT_POLICY_DENIED", err)
	}
	if base.attempts != 0 {
		t.Error("a rebound destination reached the network")
	}
}

// Instance metadata is the standard escalation from request forgery to credential compromise. Every
// spelling of it must be refused, including the IPv4-mapped IPv6 form.
func TestSecurityCloudMetadataEndpointsAreRefused(t *testing.T) {
	t.Parallel()
	blocked := []struct {
		name string
		ip   net.IP
	}{
		{"aws/gcp/azure ipv4 metadata", net.ParseIP("169.254.169.254")},
		{"ipv4-mapped ipv6 metadata", net.ParseIP("::ffff:169.254.169.254")},
		{"ipv6 link-local", net.ParseIP("fe80::1")},
		{"loopback", net.ParseIP("127.0.0.1")},
		{"ipv6 loopback", net.ParseIP("::1")},
		{"rfc1918 ten", net.ParseIP("10.1.2.3")},
		{"rfc1918 172", net.ParseIP("172.16.0.1")},
		{"rfc1918 192", net.ParseIP("192.168.1.1")},
		{"carrier-grade nat", net.ParseIP("100.64.0.1")},
		{"unspecified", net.ParseIP("0.0.0.0")},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, base := guard(t, "acme", stubResolver{
				addrs: map[string][]net.IP{"api.acme.test": {tc.ip}},
			})
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"https://api.acme.test/latest/meta-data/", nil)
			if _, err := g.RoundTrip(req); !modberr.Is(err, modberr.CodePolicyDenied) {
				t.Fatalf("%s was not refused: %v", tc.ip, err)
			}
			if base.attempts != 0 {
				t.Errorf("%s reached the network", tc.ip)
			}
		})
	}
}

// Each redirect hop is its own RoundTrip, so a chain starting at an allowed host and ending
// elsewhere is caught at the hop that leaves the allowlist.
func TestSecurityRedirectOffTheAllowlistIsRefused(t *testing.T) {
	t.Parallel()
	g, base := guard(t, "acme", publicResolver())

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://evil.test/collect", nil)
	if _, err := g.RoundTrip(req); !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want the redirect target refused", err)
	}
	if base.attempts != 0 {
		t.Error("a non-allowlisted redirect target reached the network")
	}
}

// A wildcard admits subdomains, never the apex: otherwise "*.acme.test" would silently widen to
// "acme.test" and any host that happens to end with it.
func TestWildcardHostsAdmitSubdomainsOnly(t *testing.T) {
	t.Parallel()
	resolver := stubResolver{addrs: map[string][]net.IP{
		"regional.acme.test":     {net.ParseIP("203.0.113.20")},
		"evilregional.acme.test": {net.ParseIP("203.0.113.21")},
		"eu.regional.acme.test":  {net.ParseIP("203.0.113.22")},
	}}
	g, _ := guard(t, "acme", resolver)

	for _, host := range []string{"regional.acme.test", "evilregional.acme.test"} {
		if err := g.Check(context.Background(), "https", host); !modberr.Is(err, modberr.CodePolicyDenied) {
			t.Errorf("%s should not match *.regional.acme.test: %v", host, err)
		}
	}
	if err := g.Check(context.Background(), "https", "eu.regional.acme.test"); err != nil {
		t.Errorf("a genuine subdomain was refused: %v", err)
	}
}

// A credential on a plaintext connection is a credential on the wire.
func TestPlaintextIsRefusedForHostedProviders(t *testing.T) {
	t.Parallel()
	g, _ := guard(t, "acme", publicResolver())
	if err := g.Check(context.Background(), "http", "api.acme.test"); !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want plaintext refused", err)
	}
	if err := g.Check(context.Background(), "ftp", "api.acme.test"); !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Error("a non-http scheme must be refused")
	}
}

// Local inference endpoints legitimately live on loopback, so the capability must exist — scoped to
// providers that declare it, and never inherited by a hosted one.
func TestLocalProvidersMayUseLoopbackAndPlaintext(t *testing.T) {
	t.Parallel()
	g, _ := guard(t, "local", publicResolver())

	if err := g.Check(context.Background(), "http", "localhost"); err != nil {
		t.Errorf("a declared local endpoint was refused: %v", err)
	}
	if err := g.Check(context.Background(), "http", "127.0.0.1"); err != nil {
		t.Errorf("a literal loopback address was refused: %v", err)
	}

	// The hosted provider does not inherit it.
	hosted, _ := guard(t, "acme", stubResolver{
		addrs: map[string][]net.IP{"api.acme.test": {net.ParseIP("127.0.0.1")}},
	})
	if err := hosted.Check(context.Background(), "https", "api.acme.test"); err == nil {
		t.Error("a hosted provider must not reach loopback")
	}
}

// An unresolvable destination cannot be address-checked, so it is refused rather than allowed
// through unverified.
func TestUnresolvableDestinationFailsClosed(t *testing.T) {
	t.Parallel()
	g, base := guard(t, "acme", stubResolver{err: errors.New("dns timeout")})

	if err := g.Check(context.Background(), "https", "api.acme.test"); !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want the unresolvable destination refused", err)
	}
	if base.attempts != 0 {
		t.Error("an unverified destination reached the network")
	}
}

// A literal address needs no lookup, and must not be handed to a resolver that could decide to
// honour it differently.
func TestLiteralAddressesAreCheckedWithoutResolution(t *testing.T) {
	t.Parallel()
	// The resolver would error on any lookup; a literal must not consult it.
	g, _ := guard(t, "local", stubResolver{err: errors.New("resolver must not be consulted")})
	if err := g.Check(context.Background(), "http", "127.0.0.1"); err != nil {
		t.Fatalf("a literal loopback address consulted the resolver: %v", err)
	}
}

func TestEgressPolicyListsItsProviders(t *testing.T) {
	t.Parallel()
	got := hostedPolicy(t).Providers()
	if len(got) != 2 || got[0] != "acme" || got[1] != "local" {
		t.Errorf("Providers = %v, want a sorted [acme local]", got)
	}
}
