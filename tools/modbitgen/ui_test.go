package main

import (
	"testing"

	"github.com/modbit/modbit/pkg/settings"
)

// The generator duplicates the widget and initialism tables rather than importing pkg/settings,
// because the non-test generator importing the package it generates would make a clean-tree build
// circular: producing definitions_gen.go would require pkg/settings to compile, which requires
// definitions_gen.go.
//
// A *test* has no such problem — generation never runs tests — so this is where the duplication is
// kept honest. Without it the two tables drift silently, and the drift only surfaces when a key
// happens to use the affected word, which may be several releases later.

func TestGeneratorWidgetTableMatchesTheRuntime(t *testing.T) {
	types := map[string]settings.Type{
		"bool": settings.TypeBool, "int": settings.TypeInt, "number": settings.TypeNumber,
		"string": settings.TypeString, "enum": settings.TypeEnum,
		"string_list": settings.TypeStringList, "object": settings.TypeObject,
	}
	if len(widgetsForType) != len(types) {
		t.Fatalf("the generator knows %d types, the mapping under test covers %d",
			len(widgetsForType), len(types))
	}

	for name, typ := range types {
		allowed, known := widgetsForType[name]
		if !known {
			t.Errorf("the generator has no widgets for type %q", name)
			continue
		}
		// Every widget the generator permits must be one the runtime permits.
		for _, widget := range allowed {
			if !settings.WidgetAllowed(typ, settings.Widget(widget)) {
				t.Errorf("generator permits %q for %q; the runtime does not", widget, name)
			}
		}
		// And the defaults must agree, since that is what actually gets emitted.
		if got, want := defaultWidget(name), string(settings.DefaultWidget(typ)); got != want {
			t.Errorf("default widget for %q: generator %q, runtime %q", name, got, want)
		}
	}

	// An unknown type falls back the same way on both sides, so a type added to the contract before
	// the tables are updated renders rather than vanishing.
	if got, want := defaultWidget("nonexistent"), string(settings.DefaultWidget(settings.Type("nonexistent"))); got != want {
		t.Errorf("unknown-type fallback: generator %q, runtime %q", got, want)
	}
}

func TestGeneratorInitialismsMatchTheRuntime(t *testing.T) {
	// Every initialism the generator knows must derive identically in the runtime, whether or not a
	// registered key uses it today. Testing only the keys in the registry would let an unused entry
	// drift until the day somebody adds a key that needs it.
	for word := range generatorInitialisms {
		key := "namespace.group." + word
		if got, want := deriveLabel(key), settings.DeriveLabel(settings.Key(key)); got != want {
			t.Errorf("deriveLabel(%q): generator %q, runtime %q", key, got, want)
		}
	}

	// And in the other direction: a word the runtime treats as an initialism must be one the
	// generator does too, or the generated file disagrees with the package that reads it.
	for _, word := range []string{
		"api", "cpu", "dlp", "gpu", "id", "ide", "mb", "mcp", "sso", "ttl", "ui", "url", "vcs",
	} {
		key := "namespace.group." + word
		if got, want := deriveLabel(key), settings.DeriveLabel(settings.Key(key)); got != want {
			t.Errorf("deriveLabel(%q): generator %q, runtime %q", key, got, want)
		}
	}
}

func TestGeneratorGroupDerivationMatchesTheRuntime(t *testing.T) {
	for _, key := range []string{
		"agent.approval.duration", "agent.default_mode", "context.indexing.max_file_bytes",
		"a.b", "a.b.c.d",
	} {
		if got, want := deriveGroup(key), settings.DeriveGroup(settings.Key(key)); got != want {
			t.Errorf("deriveGroup(%q): generator %q, runtime %q", key, got, want)
		}
	}
}
