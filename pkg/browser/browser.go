// Package browser admits browser and desktop automation sessions (BRS-1..BRS-6).
//
// Boundary: it decides whether a session may start, whether a download may leave quarantine, and
// whether desktop automation is permitted on a worker. It drives no browser, opens no page, and
// downloads nothing — a caller supplies what happened and this decides what it permits.
//
// Requirements: PRD §16.6 BRS-1 (browser sessions run in an isolated profile), BRS-2 (credentials
// are provided through controlled session brokering where permitted), BRS-3 (screenshots, video,
// DOM snapshots, console logs and network logs can be captured as artifacts), BRS-4 (user takeover
// is auditable), BRS-5 (browser downloads are quarantined until policy checked), BRS-6 (desktop
// automation is limited to eligible workers and explicit profiles). §35 also requires browser
// storage to be partitioned by organization and workspace policy. INV-2 governs BRS-2 and INV-13
// governs what a download contains.
//
// # Brokering means the model never sees the credential
//
// BRS-2 says credentials are provided through controlled session brokering. The point of brokering
// is not that the credential is handled carefully — it is that the credential never enters the
// context the model can read. A session that logs in by having the agent type a password into a
// form has satisfied every word of "controlled" and none of the requirement, because the password
// was in the agent's context to be typed.
//
// So a session carries a credential *reference* that the broker redeems out of band, and a session
// carrying material is refused.
//
// # A quarantined download is untrusted twice over
//
// BRS-5's quarantine is usually read as malware scanning. It is also INV-13: a file the agent
// downloaded is content from the internet, and releasing it into the workspace makes it
// indistinguishable from code the user wrote. So release requires both a policy check and a
// provenance class, and the class that comes out is Web — never lower, whatever the file is.
package browser

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// ArtifactKind is a BRS-3 capture.
type ArtifactKind string

const (
	CaptureScreenshot ArtifactKind = "screenshot"
	CaptureVideo      ArtifactKind = "video"
	CaptureDOM        ArtifactKind = "dom_snapshot"
	CaptureConsoleLog ArtifactKind = "console_log"
	CaptureNetworkLog ArtifactKind = "network_log"
)

// CaptureKinds are the five BRS-3 names.
var CaptureKinds = []ArtifactKind{
	CaptureScreenshot, CaptureVideo, CaptureDOM, CaptureConsoleLog, CaptureNetworkLog,
}

// Session is a browser automation session.
type Session struct {
	ID string `json:"id"`
	// OrganizationID and WorkspaceID partition storage. Both are required: §35 partitions browser
	// storage by organization *and* workspace policy, and a session missing either would share a
	// profile with whatever else has the same blank.
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	// ProfileID is the isolated profile the session runs in (BRS-1). Sessions never share one; see
	// ProfileKey for what "isolated" is derived from.
	ProfileID string `json:"profile_id"`
	// CredentialRefs are broker references (BRS-2). Never material — see the package comment.
	CredentialRefs []string `json:"credential_refs,omitempty"`
	// CapturesEnabled are the BRS-3 artifacts this session will record.
	CapturesEnabled []ArtifactKind `json:"captures_enabled,omitempty"`
}

// ProfileKey is the identity a profile must be unique on (BRS-1, §35).
//
// Derived from organization, workspace and profile rather than trusting a caller-supplied profile
// id to be unique. Two sessions in different organizations that both call their profile "default"
// must not share cookies, and "default" is what everything is called.
func (s Session) ProfileKey() string {
	return strings.Join([]string{s.OrganizationID, s.WorkspaceID, s.ProfileID}, "\x00")
}

// Isolated reports whether two sessions are in separate profiles.
func (s Session) Isolated(other Session) bool { return s.ProfileKey() != other.ProfileKey() }

// Validate enforces BRS-1, BRS-2 and the storage partition.
func (s Session) Validate() error {
	switch {
	case strings.TrimSpace(s.ID) == "":
		return field("a browser session has no id", "id")
	case strings.TrimSpace(s.OrganizationID) == "":
		return field(fmt.Sprintf("session %s names no organization", s.ID), "organization_id")
	case strings.TrimSpace(s.WorkspaceID) == "":
		// Partitioned by organization *and* workspace. A session missing either shares a profile
		// with whatever else has the same blank.
		return field(fmt.Sprintf("session %s names no workspace", s.ID), "workspace_id")
	case strings.TrimSpace(s.ProfileID) == "":
		return field(fmt.Sprintf(
			"session %s names no profile; BRS-1 requires an isolated one and the default profile is "+
				"whatever the last session left behind", s.ID), "profile_id")
	}
	for _, ref := range s.CredentialRefs {
		if strings.TrimSpace(ref) == "" {
			return field(fmt.Sprintf("session %s carries an empty credential reference", s.ID),
				"credential_refs")
		}
		if looksLikeMaterial(ref) {
			// INV-2. The point of brokering is that the credential never enters the context the
			// model can read; a session that logs in by typing a password has satisfied every word
			// of "controlled" and none of the requirement.
			return field(fmt.Sprintf(
				"session %s carries what looks like credential material rather than a broker reference; "+
					"BRS-2's brokering exists so the credential never reaches the model's context", s.ID),
				"credential_refs")
		}
	}
	for _, k := range s.CapturesEnabled {
		if !knownCapture(k) {
			return field(fmt.Sprintf("session %s enables the unrecognised capture %q", s.ID, k),
				"captures_enabled")
		}
	}
	return nil
}

func knownCapture(k ArtifactKind) bool {
	for _, known := range CaptureKinds {
		if known == k {
			return true
		}
	}
	return false
}

// looksLikeMaterial catches the obvious case of a value where a reference belongs.
//
// Narrow on purpose: it exists to catch the paste, not to certify that a string is not a
// credential. Nothing here can do the latter, and a check that claimed to would be believed.
func looksLikeMaterial(ref string) bool {
	s := strings.TrimSpace(ref)
	if len(s) > 40 && !strings.Contains(s, "/") && !strings.Contains(s, ".") {
		return true
	}
	lower := strings.ToLower(s)
	for _, prefix := range []string{"ghp_", "sk-", "aws_", "akia", "xoxb-", "-----begin", "password="} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Takeover is a user taking manual control of a session (BRS-4).
type Takeover struct {
	SessionID string `json:"session_id"`
	ActorID   string `json:"actor_id"`
	// StartedAt and EndedAt bound the manual period. Both are required: an open-ended takeover
	// records who started touching the session and never says when the agent's actions resume being
	// the agent's.
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
	// Reason explains why manual control was needed.
	Reason string `json:"reason"`
}

// Validate enforces BRS-4's auditability.
//
// Every field, because a takeover is the moment the audit trail stops describing an agent and
// starts describing a person, and a record that cannot say who or when covers neither.
func (t Takeover) Validate() error {
	switch {
	case strings.TrimSpace(t.SessionID) == "":
		return field("a takeover names no session", "session_id")
	case strings.TrimSpace(t.ActorID) == "":
		return field(fmt.Sprintf("the takeover of %s names no actor", t.SessionID), "actor_id")
	case strings.TrimSpace(t.StartedAt) == "":
		return field(fmt.Sprintf("the takeover of %s has no start", t.SessionID), "started_at")
	case strings.TrimSpace(t.EndedAt) == "":
		return field(fmt.Sprintf(
			"the takeover of %s has no end; the trail would never say when the agent's actions resume "+
				"being the agent's", t.SessionID), "ended_at")
	case strings.TrimSpace(t.Reason) == "":
		return field(fmt.Sprintf("the takeover of %s gives no reason", t.SessionID), "reason")
	}
	return nil
}

// DownloadState is where a downloaded file has got to (BRS-5).
type DownloadState string

const (
	// DownloadQuarantined is the zero value. A download record nobody updated is quarantined, which
	// is the only safe reading: "released" as a zero value would release a file the policy check
	// never ran on.
	DownloadQuarantined DownloadState = ""
	DownloadReleased    DownloadState = "released"
	DownloadRejected    DownloadState = "rejected"
)

// Download is a file the browser fetched.
type Download struct {
	SessionID string `json:"session_id"`
	Filename  string `json:"filename"`
	// SourceURL is where it came from, which is what makes it Web-class content.
	SourceURL string        `json:"source_url"`
	State     DownloadState `json:"state"`
}

// PolicyCheck is the caller's verdict on a quarantined file.
type PolicyCheck struct {
	// Ran records that a check actually happened. The zero value is false, so a Download released
	// without one is refused rather than passed — "no findings" and "no scan" produce the same
	// empty findings list.
	Ran      bool     `json:"ran"`
	Findings []string `json:"findings,omitempty"`
}

// Release decides whether a quarantined download may enter the workspace (BRS-5).
//
// Returns the provenance class the released file carries. It is always Web: a file the agent
// downloaded is content from the internet, and releasing it without a class makes it
// indistinguishable from code the user wrote (INV-13's sibling case).
func Release(d Download, check PolicyCheck) (taint.Class, error) {
	switch {
	case strings.TrimSpace(d.SessionID) == "":
		return taint.Unknown(), field("a download names no session", "session_id")
	case strings.TrimSpace(d.Filename) == "":
		return taint.Unknown(), field("a download has no filename", "filename")
	case strings.TrimSpace(d.SourceURL) == "":
		// Without a source there is nothing to attribute the content to, and the class would be a
		// guess.
		return taint.Unknown(), field(fmt.Sprintf(
			"the download %s names no source", d.Filename), "source_url")
	case d.State == DownloadRejected:
		return taint.Unknown(), denied(fmt.Sprintf(
			"the download %s was rejected", d.Filename), "download_quarantine")
	}

	if !check.Ran {
		// "No findings" and "no scan" produce the same empty list, and only one of them is a check.
		return taint.Unknown(), denied(fmt.Sprintf(
			"the download %s has not been policy checked", d.Filename), "download_quarantine")
	}
	if len(check.Findings) > 0 {
		sorted := append([]string(nil), check.Findings...)
		sort.Strings(sorted)
		return taint.Unknown(), denied(fmt.Sprintf(
			"the download %s failed its policy check: %s",
			d.Filename, strings.Join(sorted, ", ")), "download_quarantine")
	}
	return taint.Web, nil
}

// WorkerEligibility is what a worker offers for desktop automation (BRS-6).
type WorkerEligibility struct {
	WorkerID string `json:"worker_id"`
	// DesktopAutomationEnabled is the deployment's per-worker decision. The zero value is false, so
	// a worker nobody enabled is not eligible.
	DesktopAutomationEnabled bool `json:"desktop_automation_enabled"`
	// AllowedProfiles are the profiles this worker may run. BRS-6 says explicit profiles, so a nil
	// list is no profiles rather than every profile — the opposite of an allowlist's nil, and
	// deliberately so: "eligible for desktop automation, profile unspecified" is not a state a
	// deployment should be able to reach by omission.
	AllowedProfiles []string `json:"allowed_profiles"`
}

// AllowDesktopAutomation decides whether a worker may run desktop automation for a profile (BRS-6).
func AllowDesktopAutomation(w WorkerEligibility, profileID string) error {
	switch {
	case strings.TrimSpace(w.WorkerID) == "":
		return field("desktop automation names no worker", "worker_id")
	case strings.TrimSpace(profileID) == "":
		return field(fmt.Sprintf(
			"desktop automation on %s names no profile; BRS-6 requires an explicit one", w.WorkerID),
			"profile_id")
	case !w.DesktopAutomationEnabled:
		return denied(fmt.Sprintf(
			"worker %s is not eligible for desktop automation", w.WorkerID), "desktop_automation")
	}
	for _, p := range w.AllowedProfiles {
		if p == profileID {
			return nil
		}
	}
	// Reached when the list is nil as well as when the profile is simply absent, which is the
	// intent: an eligible worker with no profiles listed runs nothing.
	return denied(fmt.Sprintf(
		"worker %s is not configured for the profile %s", w.WorkerID, profileID),
		"desktop_automation")
}
