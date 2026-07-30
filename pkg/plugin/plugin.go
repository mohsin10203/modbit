// Package plugin admits plugin packages for installation (PLG-1..PLG-4).
//
// Boundary: it decides whether a package may be installed, given its manifest and the deployment's
// policy. It downloads nothing, verifies no cryptography itself, and executes no plugin code — a
// caller supplies a verified signature result and this decides what it means.
//
// Requirements: PRD §9D PLG-1 (manifest with declared permissions), PLG-2 (signing in managed
// deployments), PLG-3 (pinning, compatibility, revocation, rollback), PLG-4 (publisher and package
// allowlists).
//
// # An empty allowlist is not an absent allowlist
//
// PLG-4 lets administrators define allowlists. The trap is that "defined and empty" and "not
// defined" are the same value in most representations, and they mean opposite things: an
// administrator who saved an empty allowlist has said *nothing is permitted*, and reading that as
// "no restriction" installs everything at precisely the moment somebody was trying to stop it.
//
// So `Allowlist` distinguishes a nil slice from an empty one, and the type's documentation says
// which is which rather than leaving it to a caller's intuition.
//
// # Why revocation is checked before everything else
//
// PLG-3 lists pinning, compatibility, revocation and rollback together, but they are not peers. A
// pin is a statement about what an operator wants; a revocation is a statement that a version is
// unsafe. A revoked version that is also pinned must not install, and checking the pin first would
// let the older, stronger-looking instruction win.
package plugin

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Manifest is what a package declares about itself (PLG-1).
type Manifest struct {
	PackageID string `json:"package_id"`
	Publisher string `json:"publisher"`
	Version   string `json:"version"`
	// Permissions are the capabilities the plugin asks for. An empty list is refused: a plugin that
	// declares nothing is not a harmless plugin, it is one whose capability nobody stated, and
	// PLG-1 exists so a reviewer can see what they are granting.
	Permissions []string `json:"permissions"`
	// MinPlatform is the lowest platform version the package supports (PLG-3).
	MinPlatform int `json:"min_platform"`
}

// Validate enforces PLG-1.
func (m Manifest) Validate() error {
	switch {
	case strings.TrimSpace(m.PackageID) == "":
		return field("a manifest names no package", "package_id")
	case strings.TrimSpace(m.Publisher) == "":
		return field(fmt.Sprintf("package %q names no publisher", m.PackageID), "publisher")
	case strings.TrimSpace(m.Version) == "":
		return field(fmt.Sprintf("package %q states no version", m.PackageID), "version")
	case len(m.Permissions) == 0:
		return field(fmt.Sprintf(
			"package %q declares no permissions; PLG-1 requires the manifest to state what it asks for",
			m.PackageID), "permissions")
	case m.MinPlatform < 0:
		return field(fmt.Sprintf("package %q has a negative platform floor", m.PackageID), "min_platform")
	}
	for _, p := range m.Permissions {
		if strings.TrimSpace(p) == "" {
			return field(fmt.Sprintf("package %q declares an empty permission", m.PackageID),
				"permissions")
		}
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Allowlist is an administrator-defined set (PLG-4).
//
// nil means no allowlist is defined, so nothing is restricted by it. A non-nil empty slice means an
// allowlist *is* defined and permits nothing. Those are opposite instructions and collapsing them is
// the failure this type exists to prevent.
type Allowlist []string

// Defined reports whether an administrator set this allowlist at all.
func (a Allowlist) Defined() bool { return a != nil }

// Permits reports whether the allowlist admits a value. An undefined allowlist permits everything;
// a defined one permits only what it lists.
func (a Allowlist) Permits(v string) bool {
	if !a.Defined() {
		return true
	}
	for _, item := range a {
		if item == v {
			return true
		}
	}
	return false
}

// Policy is the deployment's stance.
type Policy struct {
	// Managed marks a deployment where PLG-2 requires signatures.
	Managed bool `json:"managed"`
	// Publishers and Packages are the PLG-4 allowlists. See Allowlist for nil versus empty.
	Publishers Allowlist `json:"publishers"`
	Packages   Allowlist `json:"packages"`
	// RevokedVersions maps a package id to versions that must never install (PLG-3).
	RevokedVersions map[string][]string `json:"revoked_versions,omitempty"`
	// PinnedVersion maps a package id to the only version permitted (PLG-3).
	PinnedVersion map[string]string `json:"pinned_version,omitempty"`
	// PlatformVersion is what this deployment runs, checked against a manifest's floor.
	PlatformVersion int `json:"platform_version"`
}

// Signature is the caller's verification result. This package does not verify anything itself; it
// decides what a result means.
type Signature struct {
	// Present reports that the package carried a signature.
	Present bool `json:"present"`
	// Verified reports that the caller checked it and it held. A present-but-unverified signature is
	// worse than none: it looks like assurance.
	Verified bool `json:"verified"`
}

// Decision is the admission outcome.
type Decision struct {
	Install bool `json:"install"`
	// Reason explains a refusal, naming the rule that refused.
	Reason string `json:"reason,omitempty"`
}

// Admit decides whether a package may be installed.
//
// Order matters and is documented at each step: a refusal should name the most fundamental reason,
// not the first one a loop happened to reach.
func Admit(m Manifest, sig Signature, p Policy) (Decision, error) {
	if err := m.Validate(); err != nil {
		return Decision{}, err
	}

	// PLG-3 revocation, first. A revocation says a version is unsafe; a pin says an operator wants
	// it. Checking the pin first would let the older instruction beat the newer safety one, and a
	// revoked-but-pinned version is exactly the case that arises after an advisory.
	for _, v := range p.RevokedVersions[m.PackageID] {
		if v == m.Version {
			return Decision{Reason: fmt.Sprintf(
				"version %s of %s is revoked", m.Version, m.PackageID)}, nil
		}
	}

	// PLG-2. A present-but-unverified signature is refused distinctly from an absent one, because
	// it is worse: it looks like assurance to anyone reading a package listing.
	if p.Managed {
		switch {
		case !sig.Present:
			return Decision{Reason: "managed deployments require a signed package"}, nil
		case !sig.Verified:
			return Decision{Reason: "the package signature did not verify"}, nil
		}
	}

	// PLG-4. Publisher first: an administrator who has allowlisted publishers has made a statement
	// about who they trust, and a package from an untrusted publisher is refused on that basis
	// rather than on its own id.
	if !p.Publishers.Permits(m.Publisher) {
		return Decision{Reason: fmt.Sprintf(
			"publisher %q is not on the administrator's allowlist", m.Publisher)}, nil
	}
	if !p.Packages.Permits(m.PackageID) {
		return Decision{Reason: fmt.Sprintf(
			"package %q is not on the administrator's allowlist", m.PackageID)}, nil
	}

	// PLG-3 pinning and compatibility.
	if pinned, ok := p.PinnedVersion[m.PackageID]; ok && pinned != m.Version {
		return Decision{Reason: fmt.Sprintf(
			"%s is pinned to %s and this package is %s", m.PackageID, pinned, m.Version)}, nil
	}
	if m.MinPlatform > p.PlatformVersion {
		return Decision{Reason: fmt.Sprintf(
			"%s needs platform %d and this deployment runs %d",
			m.PackageID, m.MinPlatform, p.PlatformVersion)}, nil
	}

	return Decision{Install: true}, nil
}

// RollbackTargets returns the versions a package may roll back to, newest first (PLG-3).
//
// Revoked versions are excluded. Rolling back to a revoked version is the most likely way to
// reintroduce the vulnerability the revocation was issued for, and it is the moment somebody is
// most inclined to reach for "just use the last one that worked".
func RollbackTargets(packageID string, installed []string, p Policy) []string {
	revoked := map[string]bool{}
	for _, v := range p.RevokedVersions[packageID] {
		revoked[v] = true
	}
	var out []string
	for _, v := range installed {
		if !revoked[v] {
			out = append(out, v)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}
