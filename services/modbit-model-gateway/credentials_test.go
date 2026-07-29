package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/modberr"
)

const testSecret = "sk-live-DO-NOT-DISCLOSE-8f3a91"

func testBroker(t *testing.T) (*envBroker, []string) {
	t.Helper()
	var unset []string
	b, err := newEnvBroker(
		[]string{
			credentialEnvPrefix + "OPENAI=" + testSecret,
			credentialEnvPrefix + "ANTHROPIC=sk-ant-second-secret",
			"PATH=/usr/bin",
		},
		func(name string) error { unset = append(unset, name); return nil },
	)
	if err != nil {
		t.Fatalf("newEnvBroker: %v", err)
	}
	return b, unset
}

// INV-2. The credential must not be reachable through any of the routes a value normally escapes by.
//
// This is the property that justifies the gateway being a separate process at all: if the secret can
// be printed, serialized or wrapped into an error, then putting it behind a network boundary bought
// nothing, because the disclosure happens on this side of it. Each subtest is one escape route.
func TestSecurityACredentialNeverEscapesTheBroker(t *testing.T) {
	b, _ := testBroker(t)

	t.Run("formatting the broker", func(t *testing.T) {
		for _, rendered := range []string{
			fmt.Sprintf("%v", b), fmt.Sprintf("%s", b), fmt.Sprintf("%+v", b), fmt.Sprintf("%#v", b),
		} {
			if strings.Contains(rendered, testSecret) {
				t.Fatalf("a formatted broker disclosed the secret: %q", rendered)
			}
		}
	})

	t.Run("formatting a leased credential", func(t *testing.T) {
		cred, err := b.Lease(context.Background(), "openai")
		if err != nil {
			t.Fatalf("Lease: %v", err)
		}
		for _, rendered := range []string{
			fmt.Sprintf("%v", cred), fmt.Sprintf("%s", cred), fmt.Sprintf("%+v", cred), fmt.Sprintf("%#v", cred),
		} {
			if strings.Contains(rendered, testSecret) {
				t.Fatalf("a formatted credential disclosed the secret: %q", rendered)
			}
		}
		// The accessor still works, or the boundary would be useless rather than safe.
		if cred.Secret() != testSecret {
			t.Fatalf("the credential does not carry the configured secret")
		}
	})

	t.Run("JSON encoding a leased credential", func(t *testing.T) {
		cred, err := b.Lease(context.Background(), "openai")
		if err != nil {
			t.Fatalf("Lease: %v", err)
		}
		// A handler that marshals a credential by mistake is the realistic disclosure, and an
		// unexported field is what makes it impossible rather than merely unlikely.
		encoded, err := json.Marshal(cred)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(encoded), testSecret) {
			t.Fatalf("JSON encoding disclosed the secret: %s", encoded)
		}
	})

	t.Run("the error for an unknown provider", func(t *testing.T) {
		_, err := b.Lease(context.Background(), "unconfigured")
		if err == nil {
			t.Fatal("an unconfigured provider produced no error")
		}
		if !modberr.Is(err, modberr.CodeProviderUnavailable) {
			t.Fatalf("err = %v, want CodeProviderUnavailable", err)
		}
		// R-ERR-02: an error is a log line waiting to happen.
		if strings.Contains(err.Error(), testSecret) {
			t.Fatalf("the error disclosed a secret: %v", err)
		}
	})

	t.Run("provider discovery", func(t *testing.T) {
		providers := b.Providers()
		for _, p := range providers {
			if strings.Contains(p, testSecret) {
				t.Fatalf("a provider id disclosed the secret: %q", p)
			}
		}
		if len(providers) != 2 || providers[0] != "anthropic" || providers[1] != "openai" {
			t.Fatalf("providers = %v, want a sorted [anthropic openai]", providers)
		}
	})
}

// The credential is removed from the environment once read.
//
// A secret left in os.Environ() is inherited by every child this process starts, and readable from
// /proc/self/environ and any crash dump. The gateway launches no children today, which is exactly
// why this is worth pinning now: the first time one is added, nobody will revisit this decision.
func TestSecurityCredentialsAreScrubbedFromTheEnvironment(t *testing.T) {
	_, unset := testBroker(t)

	want := map[string]bool{
		credentialEnvPrefix + "OPENAI":    true,
		credentialEnvPrefix + "ANTHROPIC": true,
	}
	for _, name := range unset {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("these credential variables were left in the environment: %v", want)
	}
	for _, name := range unset {
		if name == "PATH" {
			t.Fatal("the broker unset PATH; it must touch only credential variables")
		}
	}
}

// A failed scrub is fatal rather than ignored.
//
// Continuing would leave the secret readable by every descendant, which is the condition the scrub
// exists to prevent. Reporting success while the secret is still exposed is worse than refusing.
func TestSecurityAFailedScrubRefusesToStart(t *testing.T) {
	_, err := newEnvBroker(
		[]string{credentialEnvPrefix + "OPENAI=" + testSecret},
		func(string) error { return fmt.Errorf("unset refused") },
	)
	if err == nil {
		t.Fatal("the broker started despite failing to remove a credential from the environment")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatalf("the failure disclosed the secret: %v", err)
	}
}

// No credentials means no start.
//
// SBX-6's reasoning applied to configuration: a gateway with no credentials can serve no hosted
// call, and discovering that per request turns a configuration error into what looks like a
// provider outage.
func TestNoCredentialsFailsClosedAtStartup(t *testing.T) {
	_, err := newEnvBroker([]string{"PATH=/usr/bin"}, func(string) error { return nil })
	if err == nil {
		t.Fatal("the broker started with no credentials configured")
	}
	if !modberr.Is(err, modberr.CodeSettingInvalid) {
		t.Fatalf("err = %v, want CodeSettingInvalid", err)
	}
}

// A lease is bounded in time.
//
// `inference.Credential` documents leases as per call rather than per process. An unbounded lease
// would let a credential captured out of a call — the misuse Secret()'s own comment warns about —
// keep working indefinitely.
func TestALeaseExpires(t *testing.T) {
	b, _ := testBroker(t)
	cred, err := b.Lease(context.Background(), "openai")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if cred.ExpiresAt.IsZero() {
		t.Fatal("the lease has no expiry")
	}
	if cred.LeaseID == "" {
		t.Fatal("the lease has no id, so it cannot be correlated in an audit")
	}
}
