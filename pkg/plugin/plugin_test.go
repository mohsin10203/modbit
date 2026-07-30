package plugin_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/plugin"
)

// PLG invariants (G1–G8). One test each; a test without a G-number, or a G-number without a test,
// is a gap.
//
//	G1 PLG-1: a manifest declaring no permissions is refused.
//	G2 PLG-4: a defined-but-empty allowlist permits nothing; an undefined one restricts nothing.
//	G3 PLG-2: a managed deployment refuses an unsigned package.
//	G4 PLG-2: a present-but-unverified signature is refused, distinctly from an absent one.
//	G5 PLG-3: a revoked version never installs, even when it is the pinned one.
//	G6 PLG-3: a pin refuses another version, and a platform floor is honoured.
//	G7 PLG-3: rollback never offers a revoked version.
//	G8 An unmanaged deployment does not require a signature, so the flag means something.

func manifest() plugin.Manifest {
	return plugin.Manifest{
		PackageID: "acme.linter", Publisher: "acme", Version: "1.2.0",
		Permissions: []string{"repo:read"}, MinPlatform: 5,
	}
}

func signed() plugin.Signature { return plugin.Signature{Present: true, Verified: true} }

func openPolicy() plugin.Policy { return plugin.Policy{PlatformVersion: 5} }

// G1. PLG-1: a plugin that declares nothing is not harmless, it is one whose capability nobody
// stated — and the requirement exists so a reviewer can see what they are granting.
func TestPLG1RequiresDeclaredPermissions(t *testing.T) {
	for name, mutate := range map[string]func(*plugin.Manifest){
		"no permissions":    func(m *plugin.Manifest) { m.Permissions = nil },
		"empty permission":  func(m *plugin.Manifest) { m.Permissions = []string{" "} },
		"no package id":     func(m *plugin.Manifest) { m.PackageID = "" },
		"no publisher":      func(m *plugin.Manifest) { m.Publisher = "" },
		"no version":        func(m *plugin.Manifest) { m.Version = "" },
		"negative platform": func(m *plugin.Manifest) { m.MinPlatform = -1 },
	} {
		m := manifest()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: an incomplete manifest validated", name)
		}
		if _, err := plugin.Admit(m, signed(), openPolicy()); err == nil {
			t.Errorf("%s: an incomplete manifest was admitted", name)
		}
	}
	if err := manifest().Validate(); err != nil {
		t.Fatalf("a complete manifest was refused: %v", err)
	}
}

// G2. A defined-but-empty allowlist means nothing is permitted.
//
// "Defined and empty" and "not defined" are the same value in most representations and mean opposite
// things. Reading an administrator's empty allowlist as "no restriction" installs everything at
// exactly the moment somebody was trying to stop it.
func TestSecurityAnEmptyAllowlistPermitsNothing(t *testing.T) {
	var undefined plugin.Allowlist
	if undefined.Defined() {
		t.Fatal("a nil allowlist reported itself defined")
	}
	if !undefined.Permits("anything") {
		t.Fatal("an undefined allowlist restricted something")
	}

	empty := plugin.Allowlist{}
	if !empty.Defined() {
		t.Fatal("an empty-but-present allowlist reported itself undefined")
	}
	if empty.Permits("acme") {
		t.Fatal("a defined-but-empty allowlist permitted a publisher; it permits nothing")
	}

	// Through Admit, on both axes.
	p := openPolicy()
	p.Publishers = plugin.Allowlist{}
	d, err := plugin.Admit(manifest(), signed(), p)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Install {
		t.Fatal("a package installed against an empty publisher allowlist")
	}

	p = openPolicy()
	p.Packages = plugin.Allowlist{}
	if d, _ := plugin.Admit(manifest(), signed(), p); d.Install {
		t.Fatal("a package installed against an empty package allowlist")
	}

	// A populated allowlist admits what it names.
	p = openPolicy()
	p.Publishers = plugin.Allowlist{"acme"}
	if d, _ := plugin.Admit(manifest(), signed(), p); !d.Install {
		t.Fatal("an allowlisted publisher was refused")
	}
}

// G3, G4. PLG-2, and the distinction between absent and unverified.
//
// A present-but-unverified signature is worse than none: it looks like assurance to anyone reading
// a package listing, so it is refused with its own reason rather than folded into "unsigned".
func TestSecurityAManagedDeploymentRequiresAVerifiedSignature(t *testing.T) {
	p := openPolicy()
	p.Managed = true

	d, err := plugin.Admit(manifest(), plugin.Signature{}, p)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Install {
		t.Fatal("an unsigned package installed in a managed deployment")
	}
	if !strings.Contains(d.Reason, "signed") {
		t.Fatalf("reason = %q; it must say a signature is required", d.Reason)
	}

	d, err = plugin.Admit(manifest(), plugin.Signature{Present: true}, p)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Install {
		t.Fatal("a package whose signature did not verify was installed")
	}
	if !strings.Contains(d.Reason, "verify") {
		t.Fatalf("reason = %q; an unverified signature must be distinguished from an absent one",
			d.Reason)
	}

	if d, _ := plugin.Admit(manifest(), signed(), p); !d.Install {
		t.Fatal("a properly signed package was refused in a managed deployment")
	}
}

// G5. PLG-3: a revoked version never installs, even pinned.
//
// A pin says what an operator wants; a revocation says a version is unsafe. Checking the pin first
// would let the older instruction beat the newer safety one, which is exactly the situation after
// an advisory: the pin was set before anybody knew.
func TestSecurityARevokedVersionNeverInstallsEvenWhenPinned(t *testing.T) {
	p := openPolicy()
	p.RevokedVersions = map[string][]string{"acme.linter": {"1.2.0"}}
	p.PinnedVersion = map[string]string{"acme.linter": "1.2.0"}

	d, err := plugin.Admit(manifest(), signed(), p)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Install {
		t.Fatal("a revoked version installed because it was also the pinned one")
	}
	if !strings.Contains(d.Reason, "revoked") {
		t.Fatalf("reason = %q; the revocation must be the stated reason", d.Reason)
	}
}

// G6. Pinning and compatibility.
func TestPinningAndPlatformFloorAreHonoured(t *testing.T) {
	p := openPolicy()
	p.PinnedVersion = map[string]string{"acme.linter": "1.1.0"}
	if d, _ := plugin.Admit(manifest(), signed(), p); d.Install {
		t.Fatal("version 1.2.0 installed against a pin to 1.1.0")
	}

	p = plugin.Policy{PlatformVersion: 4} // manifest needs 5
	if d, _ := plugin.Admit(manifest(), signed(), p); d.Install {
		t.Fatal("a package needing platform 5 installed on platform 4")
	}
}

// G7. PLG-3: rollback never offers a revoked version.
//
// Rolling back to a revoked version is the most likely way to reintroduce the vulnerability the
// revocation was issued for, and it is the moment somebody most wants "the last one that worked".
func TestSecurityRollbackNeverOffersARevokedVersion(t *testing.T) {
	p := plugin.Policy{RevokedVersions: map[string][]string{"acme.linter": {"1.1.0"}}}
	got := plugin.RollbackTargets("acme.linter", []string{"1.0.0", "1.1.0", "1.2.0"}, p)

	for _, v := range got {
		if v == "1.1.0" {
			t.Fatal("rollback offered a revoked version")
		}
	}
	if len(got) != 2 {
		t.Fatalf("targets = %v, want the two unrevoked versions", got)
	}
	// Newest first, so the obvious choice is the most recent safe one.
	if got[0] != "1.2.0" {
		t.Fatalf("targets = %v, want newest first", got)
	}
}

// G8. An unmanaged deployment does not require a signature, so the flag means something.
//
// Without this the managed check would be untested in the negative, and a mutation making every
// deployment managed would look correct.
func TestAnUnmanagedDeploymentDoesNotRequireASignature(t *testing.T) {
	d, err := plugin.Admit(manifest(), plugin.Signature{}, openPolicy())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !d.Install {
		t.Fatalf("an unsigned package was refused in an unmanaged deployment: %s", d.Reason)
	}
}
