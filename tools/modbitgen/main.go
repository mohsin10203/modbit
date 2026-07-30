// Command modbitgen generates typed Go and TypeScript from the contracts in contracts/.
//
// Boundary: contract parsing, validation, and code emission. It is the only component permitted
// to read contract YAML; production packages consume the generated Go and TypeScript so that no
// service parses a contract at runtime (rules.md R-CTR-01, R-CTR-02).
//
// Usage:
//
//	modbitgen -contracts ./contracts -root .            # generate everything
//	modbitgen -contracts ./contracts -root . -check settings      # validate only
//	modbitgen -contracts ./contracts -root . -check capabilities  # validate only
//
// Generation is idempotent: running it twice produces byte-identical output, which is what the
// `make generate-check` drift gate relies on (R-CTR-03).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	var (
		contractsDir = flag.String("contracts", "./contracts", "path to the contracts directory")
		rootDir      = flag.String("root", ".", "repository root that generated files are written under")
		checkOnly    = flag.String("check", "", "validate one contract family without writing: settings|events|errors|capabilities|errors-freeze")
		freezeErrors = flag.Bool("freeze-errors", false, "regenerate the error-contract lock file")
	)
	flag.Parse()

	if err := run(*contractsDir, *rootDir, *checkOnly, *freezeErrors); err != nil {
		fmt.Fprintf(os.Stderr, "modbitgen: %v\n", err)
		os.Exit(1)
	}
}

func run(contractsDir, rootDir, checkOnly string, freezeErrors bool) error {
	contractsDir = filepath.Clean(contractsDir)
	rootDir = filepath.Clean(rootDir)

	errCatalog, err := loadErrorCatalog(filepath.Join(contractsDir, "errors", "catalog.yaml"))
	if err != nil {
		return fmt.Errorf("errors: %w", err)
	}
	evtCatalog, err := loadEventCatalog(filepath.Join(contractsDir, "events", "catalog.yaml"))
	if err != nil {
		return fmt.Errorf("events: %w", err)
	}
	setCatalog, err := loadSettingsCatalog(filepath.Join(contractsDir, "settings"))
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	capCatalog, err := loadCapabilityCatalog(filepath.Join(contractsDir, "capabilities"))
	if err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}

	if err := capCatalog.validate(setCatalog, evtCatalog); err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}

	lockPath := filepath.Join(contractsDir, "errors", "catalog.lock")
	if freezeErrors {
		if err := writeIfChanged(lockPath, errCatalog.lockContent()); err != nil {
			return err
		}
		fmt.Printf("errors-freeze: locked %d codes\n", len(errCatalog.Codes))
		return nil
	}

	switch checkOnly {
	case "":
		// Generate everything below.
	case "settings":
		fmt.Printf("settings-schema-check: %d definitions across %d namespaces: ok\n",
			len(setCatalog.Definitions), len(setCatalog.Namespaces))
		return nil
	case "events":
		fmt.Printf("events-check: %d event types across %d families: ok\n",
			len(evtCatalog.Events), len(evtCatalog.Families))
		return nil
	case "errors":
		fmt.Printf("errors-check: %d error codes: ok\n", len(errCatalog.Codes))
		return nil
	case "errors-freeze":
		return errCatalog.checkFreeze(lockPath)
	case "capabilities":
		// R-TST-01: a capability that cites evidence must cite evidence that exists. Without this
		// the registry reports coverage it cannot support the moment a test is renamed.
		if err := verifyCapabilityEvidence(capCatalog, rootDir); err != nil {
			return err
		}
		orphans, err := orphanedSecurityTests(capCatalog, rootDir)
		if err != nil {
			return err
		}
		fmt.Printf("capability-check: %d capabilities, %d cited tests verified: ok\n",
			len(capCatalog.Capabilities), countCitedTests(capCatalog))
		if len(orphans) > 0 {
			// Reported, not fatal: a security test may belong to a capability not yet registered,
			// and failing the build for that would push authors toward not writing the test.
			fmt.Printf("capability-check: %s not cited by any capability:\n", plural(len(orphans), "security test"))
			for _, orphan := range orphans {
				fmt.Printf("  %s\n", orphan)
			}
		}
		unclaimed, err := unclaimedPackages(capCatalog, rootDir)
		if err != nil {
			return err
		}
		if len(unclaimed) > 0 {
			// A tested package no capability claims is behaviour the registry cannot see at all —
			// the state pkg/event was in, invisible because none of its tests were named
			// TestSecurity. Reported for the same reason as the orphan list above.
			fmt.Printf("capability-check: %s claimed by no capability:\n", plural(len(unclaimed), "tested package"))
			for _, pkg := range unclaimed {
				fmt.Printf("  %s\n", pkg)
			}
		}
		cited, total, thin, err := citationCoverage(capCatalog, rootDir)
		if err != nil {
			return err
		}
		// Printed always, not only when thin. "cited tests verified: ok" reads as completeness,
		// and the ratio is what says how much of the suite that covers.
		fmt.Printf("capability-check: citation coverage %d/%d tests (%d%%)\n",
			cited, total, int(float64(cited)/float64(max(total, 1))*100))
		if len(thin) > 0 {
			fmt.Printf("capability-check: %s claimed but under half cited:\n",
				plural(len(thin), "package"))
			for _, pkg := range thin {
				fmt.Printf("  %s\n", pkg)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown -check family %q", checkOnly)
	}

	writes := []struct {
		path    string
		content []byte
	}{
		{filepath.Join(rootDir, "pkg", "modberr", "codes_gen.go"), errCatalog.emitGo()},
		{filepath.Join(rootDir, "pkg", "event", "types_gen.go"), evtCatalog.emitGo()},
		{filepath.Join(rootDir, "pkg", "settings", "definitions_gen.go"), setCatalog.emitGo()},
		{filepath.Join(rootDir, "packages", "contracts", "src", "errors.ts"), errCatalog.emitTS()},
		{filepath.Join(rootDir, "packages", "contracts", "src", "events.ts"), evtCatalog.emitTS()},
		{filepath.Join(rootDir, "packages", "contracts", "src", "settings.ts"), setCatalog.emitTS()},
	}

	for _, w := range writes {
		content := w.content
		if filepath.Ext(w.path) == ".go" {
			formatted, err := formatGo(w.path, content)
			if err != nil {
				return fmt.Errorf("%s: %w", w.path, err)
			}
			content = formatted
		}
		if err := writeIfChanged(w.path, content); err != nil {
			return err
		}
	}

	fmt.Printf("modbitgen: %d error codes, %d event types, %d settings, %d capabilities\n",
		len(errCatalog.Codes), len(evtCatalog.Events), len(setCatalog.Definitions), len(capCatalog.Capabilities))
	return nil
}

// writeIfChanged avoids rewriting identical content so that file modification times stay stable
// across repeated `make generate` runs.
func writeIfChanged(path string, content []byte) error {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(content) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
