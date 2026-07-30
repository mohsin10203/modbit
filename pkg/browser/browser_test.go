package browser_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/browser"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// BRS invariants (O1–O8). One test each; a test without an O-number, or an O-number without a test,
// is a gap.
//
//	O1 BRS-1/§35: a profile is keyed by organization, workspace and profile, so "default" is not shared.
//	O2 BRS-2/INV-2: a session carries broker references, never credential material.
//	O3 BRS-3: the five capture kinds are a closed set.
//	O4 BRS-4: a takeover records who, when it started, when it ended, and why.
//	O5 BRS-5: the zero DownloadState is quarantined, and an unchecked file is not released.
//	O6 BRS-5/INV-13: a released download carries Web provenance, never lower.
//	O7 BRS-6: desktop automation needs an enabled worker and an explicitly listed profile.
//	O8 BRS-6: an empty profile list runs nothing — the opposite of an allowlist's nil.

func session() browser.Session {
	return browser.Session{
		ID: "s-1", OrganizationID: "org-a", WorkspaceID: "ws-1", ProfileID: "default",
		CredentialRefs:  []string{"vault://ci/browser-login"},
		CapturesEnabled: []browser.ArtifactKind{browser.CaptureScreenshot},
	}
}

func download() browser.Download {
	return browser.Download{
		SessionID: "s-1", Filename: "report.pdf", SourceURL: "https://example.test/report.pdf",
	}
}

// O1. BRS-1 and §35: two sessions calling their profile "default" must not share cookies.
//
// "Default" is what everything is called, so isolation is derived from organization, workspace and
// profile rather than trusting a caller-supplied id to be unique.
func TestSecurityProfilesAreIsolatedAcrossOrganizationsAndWorkspaces(t *testing.T) {
	mine := session()

	otherOrg := session()
	otherOrg.OrganizationID = "org-b"
	if !mine.Isolated(otherOrg) {
		t.Fatal("two organizations share a profile called default")
	}

	otherWorkspace := session()
	otherWorkspace.WorkspaceID = "ws-2"
	if !mine.Isolated(otherWorkspace) {
		t.Fatal("two workspaces share a profile called default")
	}

	otherProfile := session()
	otherProfile.ProfileID = "logged-in"
	if !mine.Isolated(otherProfile) {
		t.Fatal("two profiles in the same workspace share storage")
	}

	// The same three values are the same profile — a session resuming its own profile must find it.
	same := session()
	same.ID = "s-2"
	if mine.Isolated(same) {
		t.Fatal("a session could not resume its own profile")
	}

	// Each partition field is required, or a session shares with whatever else has the same blank.
	for name, mutate := range map[string]func(*browser.Session){
		"no organization": func(s *browser.Session) { s.OrganizationID = "" },
		"no workspace":    func(s *browser.Session) { s.WorkspaceID = " " },
		"no profile":      func(s *browser.Session) { s.ProfileID = "" },
		"no id":           func(s *browser.Session) { s.ID = "" },
	} {
		s := session()
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: an unpartitioned session validated", name)
		}
	}
	if err := session().Validate(); err != nil {
		t.Fatalf("a well-formed session was refused: %v", err)
	}
}

// O2. BRS-2 and INV-2: brokering exists so the credential never reaches the model's context.
//
// A session that logs in by having the agent type a password has satisfied every word of
// "controlled" and none of the requirement.
func TestSecurityASessionCarriesBrokerReferencesNeverCredentials(t *testing.T) {
	for _, material := range []string{
		"ghp_" + strings.Repeat("a", 36),
		"password=hunter2hunter2hunter2hunter2hunter2hunter2",
		"-----BEGIN PRIVATE KEY-----",
		strings.Repeat("x", 64),
		" ",
	} {
		s := session()
		s.CredentialRefs = []string{material}
		if err := s.Validate(); err == nil {
			t.Errorf("a session carrying %.14s... validated", material)
		}
	}

	for _, ref := range []string{"vault://ci/browser-login", "org/test-account", "secrets.browser.pw"} {
		s := session()
		s.CredentialRefs = []string{ref}
		if err := s.Validate(); err != nil {
			t.Errorf("the broker reference %q was refused: %v", ref, err)
		}
	}

	// A session needing no credentials is fine; the field is not a formality.
	none := session()
	none.CredentialRefs = nil
	if err := none.Validate(); err != nil {
		t.Fatalf("a session needing no credentials was refused: %v", err)
	}
}

// O3. BRS-3's five capture kinds are a closed set.
func TestTheCaptureKindsAreClosed(t *testing.T) {
	if len(browser.CaptureKinds) != 5 {
		t.Fatalf("capture kinds = %v, want BRS-3's five", browser.CaptureKinds)
	}
	s := session()
	s.CapturesEnabled = append([]browser.ArtifactKind(nil), browser.CaptureKinds...)
	if err := s.Validate(); err != nil {
		t.Fatalf("all five captures were refused: %v", err)
	}

	invented := session()
	invented.CapturesEnabled = []browser.ArtifactKind{"heatmap"}
	if err := invented.Validate(); err == nil {
		t.Fatal("an invented capture kind validated")
	}
	empty := session()
	empty.CapturesEnabled = []browser.ArtifactKind{""}
	if err := empty.Validate(); err == nil {
		t.Fatal("an empty capture kind validated")
	}
}

// O4. BRS-4: a takeover is the moment the audit trail stops describing an agent and starts
// describing a person. A record that cannot say who or when covers neither.
func TestSecurityATakeoverRecordsWhoWhenAndWhy(t *testing.T) {
	good := browser.Takeover{
		SessionID: "s-1", ActorID: "user-2",
		StartedAt: "2026-07-30T10:00:00Z", EndedAt: "2026-07-30T10:04:00Z",
		Reason: "solved a captcha",
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a complete takeover was refused: %v", err)
	}

	for name, mutate := range map[string]func(*browser.Takeover){
		"no session": func(t *browser.Takeover) { t.SessionID = "" },
		"no actor":   func(t *browser.Takeover) { t.ActorID = " " },
		"no start":   func(t *browser.Takeover) { t.StartedAt = "" },
		"no end":     func(t *browser.Takeover) { t.EndedAt = "" },
		"no reason":  func(t *browser.Takeover) { t.Reason = "" },
	} {
		tk := good
		mutate(&tk)
		if err := tk.Validate(); err == nil {
			t.Errorf("%s: an unauditable takeover validated", name)
		}
	}
}

// O5. BRS-5: quarantine is the zero state, and "no findings" is not "no scan".
func TestSecurityAnUncheckedDownloadIsNotReleased(t *testing.T) {
	var zero browser.DownloadState
	if zero != browser.DownloadQuarantined {
		t.Fatalf("the zero DownloadState is %q, want quarantined", zero)
	}

	// A check that never ran produces the same empty findings list as a clean one.
	_, err := browser.Release(download(), browser.PolicyCheck{})
	if err == nil {
		t.Fatal("a download was released without a policy check")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}

	// A check that ran and found something refuses, naming what it found.
	_, err = browser.Release(download(), browser.PolicyCheck{
		Ran: true, Findings: []string{"eicar-test-signature"},
	})
	if err == nil {
		t.Fatal("a download that failed its policy check was released")
	}
	if !strings.Contains(err.Error(), "eicar") {
		t.Errorf("error = %v; it must name the finding", err)
	}

	// An explicitly rejected download stays rejected whatever a later check says.
	rejected := download()
	rejected.State = browser.DownloadRejected
	if _, err := browser.Release(rejected, browser.PolicyCheck{Ran: true}); err == nil {
		t.Fatal("a rejected download was released by a clean re-check")
	}

	// A clean check on a quarantined file releases it.
	if _, err := browser.Release(download(), browser.PolicyCheck{Ran: true}); err != nil {
		t.Fatalf("a clean download was not released: %v", err)
	}
}

// O6. BRS-5 and INV-13's sibling case: a downloaded file is content from the internet.
//
// Releasing it without a class makes it indistinguishable from code the user wrote.
func TestSecurityAReleasedDownloadCarriesWebProvenance(t *testing.T) {
	class, err := browser.Release(download(), browser.PolicyCheck{Ran: true})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if class != taint.Web {
		t.Fatalf("a released download carries class %v, want Web", class)
	}
	// Web outranks the classes a released file might otherwise be mistaken for, so propagation
	// cannot launder it down.
	if taint.Propagate(class, taint.UserTrusted) != taint.Web {
		t.Fatal("mixing a downloaded file with trusted input lowered its class")
	}
	if class == taint.UserTrusted || class == taint.Generated {
		t.Fatal("a downloaded file is classed as locally authored")
	}

	// A refused release yields no usable class either — a caller that ignores the error does not
	// get a trusted one.
	refused, err := browser.Release(download(), browser.PolicyCheck{})
	if err == nil {
		t.Fatal("an unchecked download was released")
	}
	if refused == taint.UserTrusted {
		t.Fatal("a refused release returned the most trusted class")
	}

	// A download with no source has nothing to attribute the content to.
	anon := download()
	anon.SourceURL = " "
	if _, err := browser.Release(anon, browser.PolicyCheck{Ran: true}); err == nil {
		t.Fatal("a download with no source was released")
	}
}

// O7. BRS-6: an enabled worker and an explicitly listed profile.
func TestSecurityDesktopAutomationNeedsAnEnabledWorkerAndAnExplicitProfile(t *testing.T) {
	w := browser.WorkerEligibility{
		WorkerID: "w-1", DesktopAutomationEnabled: true,
		AllowedProfiles: []string{"kiosk", "qa"},
	}
	if err := browser.AllowDesktopAutomation(w, "kiosk"); err != nil {
		t.Fatalf("an eligible worker was refused its own profile: %v", err)
	}

	disabled := w
	disabled.DesktopAutomationEnabled = false
	if err := browser.AllowDesktopAutomation(disabled, "kiosk"); err == nil {
		t.Fatal("a worker nobody enabled ran desktop automation")
	}

	if err := browser.AllowDesktopAutomation(w, "unlisted"); err == nil {
		t.Fatal("a worker ran a profile it was not configured for")
	}
	if err := browser.AllowDesktopAutomation(w, " "); err == nil {
		t.Fatal("desktop automation ran with no profile named")
	}
	// The case the list membership check cannot cover: a configuration with a stray empty entry
	// would otherwise make the unnamed profile a wildcard. The first version of this test passed a
	// blank against a list that did not contain one, so the later "not configured" denial stood in
	// for the missing check and a mutant deleting it survived.
	strayEmpty := browser.WorkerEligibility{
		WorkerID: "w-1", DesktopAutomationEnabled: true,
		AllowedProfiles: []string{"kiosk", ""},
	}
	for _, blank := range []string{"", " "} {
		if err := browser.AllowDesktopAutomation(strayEmpty, blank); err == nil {
			t.Errorf("a stray empty entry in the profile list admitted the profile %q", blank)
		}
	}
	if err := browser.AllowDesktopAutomation(browser.WorkerEligibility{}, "kiosk"); err == nil {
		t.Fatal("an empty worker record ran desktop automation")
	}

	// The zero eligibility is not eligible.
	var zero browser.WorkerEligibility
	if zero.DesktopAutomationEnabled {
		t.Fatal("the zero WorkerEligibility enables desktop automation")
	}
}

// O8. BRS-6's profile list is not an allowlist: nil means nothing, not everything.
//
// "Eligible for desktop automation, profile unspecified" is not a state a deployment should be able
// to reach by omission, which is the opposite of how a nil allowlist reads elsewhere — and the
// difference is deliberate, because BRS-6 says *explicit* profiles.
func TestSecurityAWorkerWithNoListedProfilesRunsNothing(t *testing.T) {
	for name, profiles := range map[string][]string{
		"nil":   nil,
		"empty": {},
	} {
		w := browser.WorkerEligibility{
			WorkerID: "w-1", DesktopAutomationEnabled: true, AllowedProfiles: profiles,
		}
		if err := browser.AllowDesktopAutomation(w, "kiosk"); err == nil {
			t.Errorf("%s profile list: an enabled worker ran an unlisted profile", name)
		}
	}

	// One listed profile permits that one and no other, so the list is a list rather than a switch.
	one := browser.WorkerEligibility{
		WorkerID: "w-1", DesktopAutomationEnabled: true, AllowedProfiles: []string{"kiosk"},
	}
	if err := browser.AllowDesktopAutomation(one, "kiosk"); err != nil {
		t.Fatalf("the single listed profile was refused: %v", err)
	}
	if err := browser.AllowDesktopAutomation(one, "qa"); err == nil {
		t.Fatal("listing one profile permitted another")
	}
}
