// Package conformance is the shared tenant-isolation suite (R-TEN-01..R-TEN-06, INV-10).
//
// Boundary: it exercises a tenant-scoped surface against the isolation contract and returns a
// structured report. It knows nothing about what the surface stores or how it answers.
//
// Requirements: rules.md R-TEN-01..R-TEN-06; PRD INV-10 makes cross-organization or cross-Space
// leakage a release blocker.
//
// # Why a suite rather than a test per package
//
// R-TEN-06 requires every tenant-scoped surface to have an isolation test, and the obvious reading
// is "write one in each package". That produces as many definitions of isolation as there are
// packages, and the weakest one is the one an attacker finds. The `ChangeSource` suite exists for
// the same reason and found the same thing: three backends were going to be written, and stating
// the contract once was what stopped them each inventing their own idea of what Close means.
//
// So the obligations are stated here as cases, once, and every tenant-scoped surface answers them.
//
// # The case that is easy to get wrong
//
// T4. A surface can refuse correctly and still leak, because the refusal is where the detail lives:
// "run r-7 in org-4 already holds this" is a correct denial and three disclosures. Every package in
// this repository that got tenancy right got T1–T3 right on the first attempt and needed T4 pointed
// out, which is why it is a numbered case rather than a note.
package conformance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SuiteVersion is recorded in every report. A qualification run is only comparable against runs of
// the same suite version.
const SuiteVersion = 1

// Status is a case outcome.
type Status string

const (
	// StatusPass means the obligation held.
	StatusPass Status = "pass"
	// StatusFail means it did not.
	StatusFail Status = "fail"
	// StatusSkipped means the surface does not exercise the path the case covers.
	StatusSkipped Status = "skipped"
)

// Tenant identifies an isolation boundary. Both halves matter: INV-10 names organization *and*
// Space, and a surface that separated only organizations would leak between teams in one customer.
type Tenant struct {
	OrganizationID string
	SpaceID        string
}

// Surface is a tenant-scoped component under test.
//
// Query asks the surface for something on behalf of `asking`, about data owned by `owner`. It
// returns whatever the surface would return, and an error if it refuses.
//
// The two-tenant signature is the whole interface: a surface that could only be asked about its own
// tenant would pass every case by construction and prove nothing.
type Surface interface {
	// Name identifies the surface in the report.
	Name() string
	// Query performs a read on behalf of asking, against data owned by owner. `secret` is a value
	// the suite planted in the owner's data, so T2/T4 can check whether it escaped.
	Query(asking, owner Tenant, secret string) (result string, err error)
}

// Result is one case outcome.
type Result struct {
	Obligation string `json:"obligation"`
	Case       string `json:"case"`
	Status     Status `json:"status"`
	// Detail explains a failure. It never carries the planted secret, since a report is written to
	// logs.
	Detail string `json:"detail,omitempty"`
}

// Report is the evidence artifact for one surface.
type Report struct {
	SuiteVersion int       `json:"suite_version"`
	Surface      string    `json:"surface"`
	Results      []Result  `json:"results"`
	RanAt        time.Time `json:"ran_at"`
}

// Isolated reports whether every case passed. A skip does not fail the suite, but it is not a pass.
func (r Report) Isolated() bool {
	for _, res := range r.Results {
		if res.Status == StatusFail {
			return false
		}
	}
	return true
}

// Summary renders the report for an evidence line.
func (r Report) Summary() string {
	counts := map[Status]int{}
	for _, res := range r.Results {
		counts[res.Status]++
	}
	return fmt.Sprintf("%s: %d pass, %d fail, %d skipped",
		r.Surface, counts[StatusPass], counts[StatusFail], counts[StatusSkipped])
}

// The planted secret. Distinctive enough that a substring search cannot match by accident.
const plantedSecret = "TENANCY-CANARY-8f31c2"

// Run exercises a surface against T1–T5.
//
// T1 A caller reaches its own tenant's data.
// T2 A caller in another organization does not.
// T3 A caller in another Space of the same organization does not.
// T4 A refusal discloses nothing about the other tenant.
// T5 A caller with no tenancy is refused rather than defaulted.
func Run(s Surface) Report {
	report := Report{SuiteVersion: SuiteVersion, Surface: s.Name(), RanAt: time.Now()}
	add := func(obligation, name string, status Status, detail string) {
		report.Results = append(report.Results,
			Result{Obligation: obligation, Case: name, Status: status, Detail: detail})
	}

	owner := Tenant{OrganizationID: "org-owner", SpaceID: "space-owner"}
	otherOrg := Tenant{OrganizationID: "org-other", SpaceID: "space-owner"}
	otherSpace := Tenant{OrganizationID: "org-owner", SpaceID: "space-other"}

	// T1 — the control. Without it a surface that refuses everything passes T2 and T3 while being
	// broken, which is isolation achieved by not working.
	if result, err := s.Query(owner, owner, plantedSecret); err != nil {
		add("T1", "same tenant reaches its own data", StatusFail,
			fmt.Sprintf("a caller was refused access to its own tenant: %v", err))
	} else if !strings.Contains(result, plantedSecret) {
		add("T1", "same tenant reaches its own data", StatusFail,
			"a caller did not receive its own tenant's data, so the later refusals prove nothing")
	} else {
		add("T1", "same tenant reaches its own data", StatusPass, "")
	}

	// T2, T3 — the boundary, in both directions INV-10 names.
	for _, tc := range []struct {
		obligation, name string
		asking           Tenant
	}{
		{"T2", "another organization is refused", otherOrg},
		{"T3", "another Space is refused", otherSpace},
	} {
		result, err := s.Query(tc.asking, owner, plantedSecret)
		switch {
		case err == nil && strings.Contains(result, plantedSecret):
			add(tc.obligation, tc.name, StatusFail,
				"the caller received the other tenant's data")
		case err == nil && result != "":
			add(tc.obligation, tc.name, StatusFail,
				"the caller received a non-empty result from another tenant")
		default:
			add(tc.obligation, tc.name, StatusPass, "")
		}
	}

	// T4 — the case surfaces get wrong after getting T2 and T3 right. A refusal is where the detail
	// lives, and "org-owner already holds this" is a correct denial and a disclosure.
	_, err := s.Query(otherOrg, owner, plantedSecret)
	switch {
	case err == nil:
		add("T4", "the refusal discloses nothing", StatusSkipped,
			"the surface returned no error, so there is no refusal to inspect")
	case strings.Contains(err.Error(), plantedSecret):
		add("T4", "the refusal discloses nothing", StatusFail,
			"the refusal contained the other tenant's data")
	case strings.Contains(err.Error(), owner.OrganizationID) ||
		strings.Contains(err.Error(), owner.SpaceID):
		add("T4", "the refusal discloses nothing", StatusFail,
			"the refusal named the other tenant")
	default:
		add("T4", "the refusal discloses nothing", StatusPass, "")
	}

	// T5 — an unset tenancy must not be a wildcard. R-TEN-01 requires every tenant-owned entity to
	// carry an organization, so a caller without one cannot be matched against anything and must be
	// refused rather than treated as matching everything.
	if _, err := s.Query(Tenant{}, owner, plantedSecret); err == nil {
		add("T5", "an untenanted caller is refused", StatusFail,
			"a caller with no organization was served")
	} else {
		add("T5", "an untenanted caller is refused", StatusPass, "")
	}

	sort.SliceStable(report.Results, func(i, j int) bool {
		return report.Results[i].Obligation < report.Results[j].Obligation
	})
	return report
}

// Obligations returns the case identifiers, so a test can assert the suite still produces all of
// them — a case quietly dropped would leave the report reading Isolated while proving less.
func Obligations() []string { return []string{"T1", "T2", "T3", "T4", "T5"} }
