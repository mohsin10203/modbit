package sync_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/settings"
	modbitsync "github.com/modbit/modbit/pkg/sync"
)

// SYNC invariants (Y1–Y7). One test each; a test without a Y-number, or a Y-number without a test,
// is a gap.
//
//	Y1 SYNC-2: device, repository-local and session scopes never sync.
//	Y2 SET-7/INV-11: a critical-security setting never syncs.
//	Y3 SET-1: an unregistered key is withheld, because its security class is unknown.
//	Y4 SYNC-3: a disagreement is reported as a field-level diff carrying both values.
//	Y5 SYNC-3: nothing is resolved — no last-write-wins.
//	Y6 A key present on one side only is not a conflict.
//	Y7 Every withheld key carries a reason.

func def(key string, class settings.SecurityClass, scopes ...settings.Scope) settings.Definition {
	if len(scopes) == 0 {
		scopes = []settings.Scope{settings.ScopeUser}
	}
	return settings.Definition{
		Key: settings.Key(key), SecurityClass: class, Scopes: scopes,
	}
}

// Y1. SYNC-2 names device and repository-local settings as not synced by default.
//
// Deciding from the scope rather than a list of excluded keys is what makes this survive the next
// setting somebody adds: a hand-maintained denylist is correct the day it is written and wrong the
// first time it is not read.
func TestSecurityDeviceAndRepositoryLocalScopesNeverSync(t *testing.T) {
	for _, scope := range []settings.Scope{
		settings.ScopeDevice, settings.ScopeRepositoryLocal, settings.ScopeSession,
	} {
		e, err := modbitsync.Eligible(def("editor.theme", settings.SecurityNone), scope)
		if err != nil {
			t.Fatalf("Eligible: %v", err)
		}
		if e.Eligible {
			t.Errorf("a %s-authored setting was eligible to sync", scope)
		}
		if e.Reason == "" {
			t.Errorf("%s: no reason given", scope)
		}
	}

	// A user-authored setting of no consequence does sync, or the feature does nothing.
	e, err := modbitsync.Eligible(def("editor.theme", settings.SecurityNone), settings.ScopeUser)
	if err != nil {
		t.Fatalf("Eligible: %v", err)
	}
	if !e.Eligible {
		t.Fatalf("an ordinary user preference was refused: %s", e.Reason)
	}
}

// Y2. SET-7 and INV-11: a critical setting does not leave the device.
//
// A critical-class setting is not necessarily a secret, and this is the wrong place to be clever.
// Withholding one costs a preference somebody re-enters; the opposite mistake puts a secret on
// another machine.
func TestSecurityACriticalSettingNeverSyncs(t *testing.T) {
	e, err := modbitsync.Eligible(
		def("gateway.credential_ref", settings.SecurityCritical), settings.ScopeUser)
	if err != nil {
		t.Fatalf("Eligible: %v", err)
	}
	if e.Eligible {
		t.Fatal("a critical-security setting was eligible to sync")
	}
}

// Y3. SET-1 preserves unknown settings and reports them; syncing one would carry a value whose
// security class nobody can determine.
func TestSecurityAnUnregisteredKeyIsWithheld(t *testing.T) {
	got, err := modbitsync.Reconcile(
		map[settings.Key]settings.Definition{},
		[]modbitsync.Value{{Key: "mystery.flag", Value: true}},
		nil, nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(got.Withheld) != 1 {
		t.Fatalf("withheld = %v, want the unregistered key", got.Withheld)
	}
	// The reason must name the registry, not merely be non-empty. A mutation that dropped this
	// guard and let an unregistered key fall through to a zero Definition still withheld it — the
	// zero has no syncable scopes — so asserting only "withheld" passed either way. The specific
	// guard is what stops a future Definition whose zero value happens to be syncable from leaking
	// a key nobody classified.
	if reason := got.Withheld["mystery.flag"]; !strings.Contains(reason, "registry") {
		t.Fatalf("withheld reason = %q; it must say the setting is unregistered", reason)
	}
	if len(got.Agreed)+len(got.LocalOnly)+len(got.RemoteOnly)+len(got.Conflicts) != 0 {
		t.Fatal("an unregistered key was compared")
	}
}

// Y4, Y5. SYNC-3 asks for a field-level diff, and nothing here resolves it.
//
// Last-write-wins is the obvious implementation and satisfies neither half: it produces no diff, and
// a timestamp comparison is not a judgement about which value is right.
func TestSecurityAConflictCarriesBothValuesAndIsNotResolved(t *testing.T) {
	defs := map[settings.Key]settings.Definition{
		"editor.tab_width": def("editor.tab_width", settings.SecurityNone),
	}
	got, err := modbitsync.Reconcile(defs,
		[]modbitsync.Value{{Key: "editor.tab_width", Value: 2}},
		[]modbitsync.Value{{Key: "editor.tab_width", Value: 4}},
		nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(got.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(got.Conflicts))
	}
	c := got.Conflicts[0]
	if c.Local != 2 || c.Remote != 4 {
		t.Fatalf("conflict = %+v, want both sides carried", c)
	}
	if got.Resolved() {
		t.Fatal("a reconciliation with a conflict reported itself resolved")
	}
	// Neither value appears as agreed: nothing was picked.
	if len(got.Agreed) != 0 {
		t.Fatal("a conflicting key was reported as agreed; something resolved it")
	}
}

// Y6. A key on one side only is not a conflict.
//
// Nothing disagrees. Reporting it as a conflict would fill the list a user reads with entries that
// need no decision, which is how the list stops being read.
func TestAKeyOnOneSideOnlyIsNotAConflict(t *testing.T) {
	defs := map[settings.Key]settings.Definition{
		"a": def("a", settings.SecurityNone),
		"b": def("b", settings.SecurityNone),
	}
	got, err := modbitsync.Reconcile(defs,
		[]modbitsync.Value{{Key: "a", Value: 1}},
		[]modbitsync.Value{{Key: "b", Value: 2}},
		nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(got.Conflicts) != 0 {
		t.Fatalf("conflicts = %d for disjoint keys, want 0", len(got.Conflicts))
	}
	if len(got.LocalOnly) != 1 || len(got.RemoteOnly) != 1 {
		t.Fatalf("localOnly=%v remoteOnly=%v, want one each", got.LocalOnly, got.RemoteOnly)
	}
	if !got.Resolved() {
		t.Fatal("a reconciliation with no conflicts reported itself unresolved")
	}
}

// Y7. Every withheld key carries a reason, and an ineligible key is never compared.
//
// A user asking why a preference did not follow them to a new machine gets an answer rather than an
// absence — the same rule as LCD-3's degradation reason and MEM-4's withheld memory.
func TestSecurityEveryWithheldKeyExplainsItself(t *testing.T) {
	defs := map[settings.Key]settings.Definition{
		"device.gpu":      def("device.gpu", settings.SecurityNone, settings.ScopeDevice),
		"gateway.secret":  def("gateway.secret", settings.SecurityCritical),
		"editor.tabWidth": def("editor.tabWidth", settings.SecurityNone),
	}
	authored := map[settings.Key]settings.Scope{
		"device.gpu": settings.ScopeDevice,
	}
	got, err := modbitsync.Reconcile(defs,
		[]modbitsync.Value{
			{Key: "device.gpu", Value: "nvidia"},
			{Key: "gateway.secret", Value: "ref://vault/x"},
			{Key: "editor.tabWidth", Value: 2},
		},
		[]modbitsync.Value{
			{Key: "device.gpu", Value: "amd"},
			{Key: "gateway.secret", Value: "ref://vault/y"},
			{Key: "editor.tabWidth", Value: 4},
		}, authored)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	for _, k := range []settings.Key{"device.gpu", "gateway.secret"} {
		if got.Withheld[k] == "" {
			t.Errorf("%s was not withheld with a reason: %v", k, got.Withheld)
		}
	}
	// Only the ordinary preference reaches the diff, and the withheld ones are absent from it.
	if len(got.Conflicts) != 1 || got.Conflicts[0].Key != "editor.tabWidth" {
		t.Fatalf("conflicts = %+v, want only the syncable key", got.Conflicts)
	}
	for _, c := range got.Conflicts {
		if c.Key == "gateway.secret" {
			t.Fatal("a critical setting's values appeared in a diff")
		}
	}
}

// A setting authorable only at non-syncing scopes has nothing to sync.
//
// Reporting it eligible would produce an empty payload a caller reads as agreement.
func TestASettingOnlyAuthorableAtNonSyncingScopesIsIneligible(t *testing.T) {
	e, err := modbitsync.Eligible(
		def("worktree.path", settings.SecurityNone,
			settings.ScopeDevice, settings.ScopeRepositoryLocal),
		settings.ScopeUser)
	if err != nil {
		t.Fatalf("Eligible: %v", err)
	}
	if e.Eligible {
		t.Fatal("a setting authorable only at device and repository-local scopes was eligible")
	}
}
