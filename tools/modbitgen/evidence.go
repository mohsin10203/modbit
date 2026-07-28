package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Capability evidence verification (R-TST-01, QA-A01).
//
// The registry already required every capability to cite tests. It did not check that the cited
// tests exist — so a renamed or deleted test left the capability citing evidence that is not there,
// and the registry went on reporting the capability as covered. A registry that can lie about its
// own evidence is worse than no registry: it is the "assertion without evidence" the platform rules
// prohibit, wearing the costume of a control.
//
// This closes it mechanically. Every `pkg/foo:TestBar` reference must resolve to a real test
// function in that package, and every non-Go reference must match a declared form so a typo cannot
// pass as an external suite.
//
// Parsing uses go/parser and go/ast only — never go/build or go/importer, which shell out (the same
// CTX-12 reasoning that constrains the symbol extractor).

// externalEvidencePrefixes are the non-Go evidence forms a capability may cite. Anything else that
// is not `package:TestName` is a typo, and a typo that silently passes is how the gate stops
// gating.
var externalEvidencePrefixes = []string{
	// A conformance suite run by `make test-conformance` rather than a single Go test.
	"conformance/",
	// An adversarial suite run by `make test-security` (R-TST-05).
	"security/",
}

// verifyCapabilityEvidence checks that every test a capability cites actually exists.
func verifyCapabilityEvidence(catalog *capabilityCatalog, root string) error {
	index, err := indexTestFunctions(root)
	if err != nil {
		return err
	}

	var missing []string
	for _, cap := range catalog.Capabilities {
		for _, ref := range cap.Tests {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			if external(ref) {
				continue
			}
			pkg, name, ok := strings.Cut(ref, ":")
			if !ok {
				return fmt.Errorf("%s: capability %q: test reference %q is neither %q nor a declared external form",
					cap.source, cap.ID, ref, "package:TestName")
			}
			if !strings.HasPrefix(name, "Test") {
				return fmt.Errorf("%s: capability %q: test reference %q does not name a Go test",
					cap.source, cap.ID, ref)
			}
			if _, found := index[pkg][name]; !found {
				missing = append(missing,
					fmt.Sprintf("%s: capability %q cites %s, which does not exist", cap.source, cap.ID, ref))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("capability evidence is missing:\n  %s", strings.Join(missing, "\n  "))
	}
	return nil
}

func external(ref string) bool {
	for _, prefix := range externalEvidencePrefixes {
		if strings.HasPrefix(ref, prefix) {
			return true
		}
	}
	return false
}

// indexTestFunctions maps a package directory to the test functions it declares.
//
// The key is the directory relative to the repository root, which is how capability records name a
// package — `pkg/index`, not the import path — so a reader can find the file without knowing the
// module path.
func indexTestFunctions(root string) (map[string]map[string]struct{}, error) {
	index := make(map[string]map[string]struct{})

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			// A test file that does not parse is a build failure the compiler will report far more
			// clearly; skipping keeps this gate's errors about evidence rather than syntax.
			return nil
		}

		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if index[rel] == nil {
			index[rel] = make(map[string]struct{})
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") {
				index[rel][fn.Name.Name] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("indexing test functions: %w", err)
	}
	return index, nil
}

// orphanedSecurityTests returns security tests no capability cites.
//
// A `TestSecurity...` test is an adversarial suite somebody wrote deliberately, and one no
// capability claims is evidence nobody is counting. This is reported rather than fatal: a security
// test may legitimately belong to a capability not yet in the registry, and failing the build for
// that would push authors toward not writing the test.
func orphanedSecurityTests(catalog *capabilityCatalog, root string) ([]string, error) {
	index, err := indexTestFunctions(root)
	if err != nil {
		return nil, err
	}
	cited := make(map[string]struct{})
	for _, cap := range catalog.Capabilities {
		for _, ref := range cap.Tests {
			cited[strings.TrimSpace(ref)] = struct{}{}
		}
	}

	var orphans []string
	for pkg, tests := range index {
		for name := range tests {
			if !strings.HasPrefix(name, "TestSecurity") {
				continue
			}
			if _, ok := cited[pkg+":"+name]; !ok {
				orphans = append(orphans, pkg+":"+name)
			}
		}
	}
	sort.Strings(orphans)
	return orphans, nil
}

// infrastructurePackages are tested packages that deliberately belong to no capability.
//
// The registry maps *product* capabilities to evidence, and ADR-0100 forbids inventing capability
// scope that the PRD does not define. These are cross-cutting infrastructure every capability stands
// on rather than capabilities in their own right, so an entry here is a decision, not an exemption — and listing them explicitly is what lets a *newly* unclaimed package be visible.
//
// Each needs a reason, because "add it to the allowlist" is how this check would otherwise be
// silenced one package at a time.
var infrastructurePackages = map[string]string{
	"pkg/id":      "typed identifiers; their prefix rules are asserted wherever a capability uses them",
	"pkg/modberr": "the error contract, frozen separately by errors-freeze and catalog.lock",
}

// unclaimedPackages returns packages that contain tests but that no capability cites at all.
//
// This is a different question from an uncited test, and a much sharper one. Roughly half the
// repository's tests are cited by nothing, and that is mostly fine — a unit test for an internal
// helper is not evidence for a product capability, and requiring a citation for each would dilute
// the registry into a second copy of the test list.
//
// A whole tested package that no capability claims is another matter: it means a body of behaviour
// exists that the registry cannot see. `pkg/event` sat in exactly that state — seventeen tests, no
// capability, and the orphan check silent because none of them were named `TestSecurity...`.
//
// Reported rather than fatal, for the same reason the security orphan check is.
func unclaimedPackages(catalog *capabilityCatalog, root string) ([]string, error) {
	index, err := indexTestFunctions(root)
	if err != nil {
		return nil, err
	}
	claimed := make(map[string]struct{})
	for _, cap := range catalog.Capabilities {
		for _, ref := range cap.Tests {
			if pkg, _, ok := strings.Cut(strings.TrimSpace(ref), ":"); ok {
				claimed[pkg] = struct{}{}
			}
		}
	}

	var unclaimed []string
	for pkg, tests := range index {
		if len(tests) == 0 {
			continue
		}
		if _, ok := claimed[pkg]; ok {
			continue
		}
		if _, ok := infrastructurePackages[pkg]; ok {
			continue
		}
		unclaimed = append(unclaimed, fmt.Sprintf("%s (%s)", pkg, plural(len(tests), "test")))
	}
	sort.Strings(unclaimed)
	return unclaimed, nil
}

// plural renders a count with a correctly inflected noun.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// countCitedTests counts the Go test references across the registry, for the check's summary line.
func countCitedTests(catalog *capabilityCatalog) int {
	n := 0
	for _, cap := range catalog.Capabilities {
		for _, ref := range cap.Tests {
			if ref = strings.TrimSpace(ref); ref != "" && !external(ref) {
				n++
			}
		}
	}
	return n
}
