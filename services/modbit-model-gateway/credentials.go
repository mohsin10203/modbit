package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
)

// envBroker leases provider credentials held only in this process.
//
// INV-2 is the reason this service exists as a separate deployable rather than a library linked
// into the agent host: provider credentials must not enter the IDE, extension host, agent context,
// worker, sandbox, browser host, plugin, hook or MCP server. A `pkg/gateway` linked into any of
// those would put the credential in that address space, and no amount of care inside the library
// changes which process holds the secret. SDD §4.4 states the same thing as architecture — the
// gateway is a "separate security identity and egress boundary".
//
// So the boundary is the deliverable, and this type is where it lives.
type envBroker struct {
	// mu guards nothing mutable today. It exists because a rotating broker is the obvious next
	// change and rotation without a lock is the obvious next defect.
	mu sync.RWMutex
	// byProvider maps a provider id to its secret. The map is populated once at construction and
	// never logged, serialized, or returned.
	byProvider map[string]string
}

// credentialEnvPrefix is the environment prefix a provider credential is read from:
// MODBIT_PROVIDER_CREDENTIAL_<PROVIDER>.
const credentialEnvPrefix = "MODBIT_PROVIDER_CREDENTIAL_"

// newEnvBroker reads provider credentials from the environment and scrubs them from it.
//
// Scrubbing matters: a credential left in `os.Environ()` is inherited by every child process this
// service ever starts, and appears in `/proc/self/environ`, in a crash dump, and in any library
// that logs its environment. Reading it once and unsetting it keeps the secret in one place that
// this file controls.
func newEnvBroker(environ []string, unset func(string) error) (*envBroker, error) {
	b := &envBroker{byProvider: map[string]string{}}
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(name, credentialEnvPrefix) {
			continue
		}
		provider := strings.ToLower(strings.TrimPrefix(name, credentialEnvPrefix))
		if provider == "" || value == "" {
			continue
		}
		b.byProvider[provider] = value
		if unset != nil {
			// A failure here is fatal rather than ignorable: continuing would leave the secret
			// readable by every descendant, which is the condition this is preventing.
			if err := unset(name); err != nil {
				return nil, modberr.Wrap(err, modberr.CodeInternal,
					"a provider credential could not be removed from the environment").
					WithDetail("constraint", "credential_scrub")
			}
		}
	}
	if len(b.byProvider) == 0 {
		// Fail closed at construction, as NewSeatbeltBackend does when its helper is absent. A
		// gateway with no credentials cannot serve any hosted call, and discovering that per-request
		// turns a configuration error into an outage that looks like a provider fault.
		return nil, modberr.New(modberr.CodeSettingInvalid,
			"no provider credentials are configured; set "+credentialEnvPrefix+"<PROVIDER>").
			WithDetail("constraint", "credential_source")
	}
	return b, nil
}

// leaseTTL bounds a credential lease.
//
// `inference.Credential` documents leases as per call rather than per process, and the adapter
// checks Expired. A short TTL means a credential captured out of a call — the thing Secret()'s
// comment warns against — stops working quickly instead of silently outliving its use.
const leaseTTL = 5 * time.Minute

// Lease implements gateway.CredentialBroker.
func (b *envBroker) Lease(_ context.Context, providerID string) (inference.Credential, error) {
	b.mu.RLock()
	secret, held := b.byProvider[strings.ToLower(providerID)]
	b.mu.RUnlock()
	if !held {
		// The provider id is echoed because it is a routing identifier the caller supplied, not a
		// secret. The absence of a credential is not itself sensitive; the credential is.
		return inference.Credential{}, modberr.Newf(modberr.CodeProviderUnavailable,
			"no credential is configured for provider %q", providerID).
			WithDetail("constraint", "credential_source")
	}
	// NewCredential is the only way to populate the unexported secret, which is what keeps the
	// value out of every %v, JSON encoding and log line by construction rather than by care.
	return inference.NewCredential(
		providerID, id.MustNew(id.SecretLease).String(), secret, time.Now().Add(leaseTTL),
	), nil
}

// Providers lists the configured provider ids in a stable order.
//
// Ids only. This is what capability discovery is allowed to expose, and keeping it separate from
// the secret map is what stops a future handler from ranging over the wrong one.
func (b *envBroker) Providers() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.byProvider))
	for provider := range b.byProvider {
		out = append(out, provider)
	}
	sort.Strings(out)
	return out
}

// String keeps the broker out of a formatted log line.
//
// `%v` on a struct prints its fields, so one `log.Printf("broker=%v", b)` would publish every
// secret this type exists to contain (INV-11). Implementing Stringer makes that impossible rather
// than merely discouraged.
func (b *envBroker) String() string {
	return fmt.Sprintf("envBroker(providers=%d)", len(b.byProvider))
}

// GoString does the same for `%#v`, which ignores Stringer.
func (b *envBroker) GoString() string { return b.String() }

// scrubEnv is the production unset. It is a variable so a test can observe the calls without
// mutating the test process's own environment.
var scrubEnv = os.Unsetenv
