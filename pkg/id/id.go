// Package id implements Modbit's opaque, prefixed, non-sequential identifiers.
//
// Boundary: identifier construction, parsing, and prefix registration only. This package does not
// know what an entity is, does not touch storage, and never encodes meaning into an identifier
// body.
//
// Requirements: rules.md R-ID-01 (CSPRNG, opaque, prefixed, non-sequential), R-ID-02 (prefixes
// registered once, never reused), R-ID-05 (no parsing for meaning, no ordering assumptions).
//
// Wire format:
//
//	<prefix>_<26 characters of lowercase Crockford base32>
//
// The body encodes 128 bits of entropy. Crockford base32 is used because it excludes the
// visually ambiguous characters I, L, O, and U, which matters for identifiers that appear in
// approval cards, audit exports, and support transcripts.
package id

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// entropyBytes is the number of random bytes in an identifier body. 16 bytes (128 bits) makes
// collision probability negligible at any plausible Modbit volume without making identifiers
// unwieldy in a UI.
const entropyBytes = 16

// bodyLen is ceil(entropyBytes*8/5): the number of base32 characters needed for the body.
const bodyLen = 26

// crockford is the Crockford base32 alphabet in lowercase, excluding I, L, O, and U.
const crockford = "0123456789abcdefghjkmnpqrstvwxyz"

// Errors returned by Parse. Callers translate these into MODBIT_INVALID_ARGUMENT at the API
// boundary; this package deliberately does not depend on the error-code catalog so that the
// catalog generator may itself use identifiers.
var (
	ErrEmpty            = errors.New("id: empty identifier")
	ErrMissingSeparator = errors.New("id: identifier has no prefix separator")
	ErrUnknownPrefix    = errors.New("id: prefix is not registered")
	ErrBadBodyLength    = errors.New("id: identifier body has the wrong length")
	ErrBadBodyCharacter = errors.New("id: identifier body contains a character outside the alphabet")
	ErrPrefixMismatch   = errors.New("id: identifier prefix does not match the expected prefix")
)

// Prefix names an entity family. Prefixes are registered exactly once, at package
// initialization, and are never reused for a different entity (R-ID-02).
type Prefix string

// ID is an opaque Modbit identifier. The zero value is invalid.
//
// Never derive meaning from an ID beyond its prefix, and never assume ordering between two IDs:
// bodies are random, so lexical order carries no temporal information (R-ID-05).
type ID string

var registry = struct {
	mu     sync.RWMutex
	byName map[Prefix]string // prefix -> human description, for diagnostics and docs
}{byName: make(map[Prefix]string)}

// Register records a prefix and its entity description. It panics on an invalid or duplicate
// prefix because every call site is a package-level declaration evaluated at process start:
// a collision is a programmer error that must not reach a running service (R-GO-08).
func Register(p Prefix, description string) Prefix {
	if err := validatePrefix(p); err != nil {
		panic(fmt.Sprintf("id: cannot register prefix %q: %v", p, err))
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing, ok := registry.byName[p]; ok {
		panic(fmt.Sprintf("id: prefix %q already registered for %q (R-ID-02: prefixes are never reused)", p, existing))
	}
	registry.byName[p] = description
	return p
}

// Registered reports whether p has been registered.
func Registered(p Prefix) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, ok := registry.byName[p]
	return ok
}

// Prefixes returns every registered prefix with its description. The result is a copy.
func Prefixes() map[Prefix]string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make(map[Prefix]string, len(registry.byName))
	for k, v := range registry.byName {
		out[k] = v
	}
	return out
}

func validatePrefix(p Prefix) error {
	if p == "" {
		return errors.New("prefix is empty")
	}
	if len(p) > 12 {
		return errors.New("prefix exceeds 12 characters")
	}
	for _, r := range p {
		if r < 'a' || r > 'z' {
			return errors.New("prefix must be lowercase a-z")
		}
	}
	return nil
}

// Generator produces identifiers from an entropy source.
//
// Production code uses the package-level New, which draws from crypto/rand. Tests construct a
// Generator over a deterministic reader so that identifiers in golden files are stable
// (R-TST-03).
type Generator struct {
	entropy io.Reader
}

// NewGenerator returns a Generator drawing from entropy. A nil reader means crypto/rand.
func NewGenerator(entropy io.Reader) *Generator {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &Generator{entropy: entropy}
}

// defaultGenerator is immutable after initialization and holds no run or tenant state, so it does
// not violate R-GO-06.
var defaultGenerator = NewGenerator(nil)

// New returns a new identifier for p, drawing from the process CSPRNG.
//
// It returns an error only when the entropy source fails, which a caller must treat as fatal for
// the request rather than falling back to a weaker source.
func New(p Prefix) (ID, error) { return defaultGenerator.New(p) }

// MustNew is New for package-level fixtures and tests. It panics on failure.
func MustNew(p Prefix) ID {
	v, err := New(p)
	if err != nil {
		panic(fmt.Sprintf("id: %v", err))
	}
	return v
}

// New returns a new identifier for p.
func (g *Generator) New(p Prefix) (ID, error) {
	if !Registered(p) {
		return "", fmt.Errorf("%w: %q", ErrUnknownPrefix, p)
	}
	buf := make([]byte, entropyBytes)
	if _, err := io.ReadFull(g.entropy, buf); err != nil {
		return "", fmt.Errorf("id: entropy source failed: %w", err)
	}
	var sb strings.Builder
	sb.Grow(len(p) + 1 + bodyLen)
	sb.WriteString(string(p))
	sb.WriteByte('_')
	sb.WriteString(encode(buf))
	return ID(sb.String()), nil
}

// encode renders src as lowercase Crockford base32, most significant bit first, padded to
// bodyLen characters. The final character carries the 3 leftover bits of a 128-bit value.
func encode(src []byte) string {
	out := make([]byte, bodyLen)
	var acc uint16 // holds up to 12 pending bits
	var bits uint
	pos := 0
	for _, b := range src {
		acc = acc<<8 | uint16(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[pos] = crockford[(acc>>bits)&0x1f]
			pos++
		}
	}
	if bits > 0 {
		out[pos] = crockford[(acc<<(5-bits))&0x1f]
		pos++
	}
	for ; pos < bodyLen; pos++ {
		out[pos] = crockford[0]
	}
	return string(out)
}

// Parse validates s and returns it as an ID. It checks that the prefix is registered and that the
// body has the correct length and alphabet. It does not check that the entity exists.
func Parse(s string) (ID, error) {
	if s == "" {
		return "", ErrEmpty
	}
	sep := strings.IndexByte(s, '_')
	if sep <= 0 || sep == len(s)-1 {
		return "", fmt.Errorf("%w: %q", ErrMissingSeparator, s)
	}
	p := Prefix(s[:sep])
	if !Registered(p) {
		return "", fmt.Errorf("%w: %q", ErrUnknownPrefix, p)
	}
	body := s[sep+1:]
	if len(body) != bodyLen {
		return "", fmt.Errorf("%w: got %d, want %d", ErrBadBodyLength, len(body), bodyLen)
	}
	for i := 0; i < len(body); i++ {
		if strings.IndexByte(crockford, body[i]) < 0 {
			return "", fmt.Errorf("%w: index %d", ErrBadBodyCharacter, i)
		}
	}
	return ID(s), nil
}

// ParseAs validates s and additionally requires it to carry the prefix want. Use this at every
// boundary that accepts an identifier for a known entity, so that a run id cannot be supplied
// where an approval id is expected.
func ParseAs(s string, want Prefix) (ID, error) {
	parsed, err := Parse(s)
	if err != nil {
		return "", err
	}
	if parsed.Prefix() != want {
		return "", fmt.Errorf("%w: got %q, want %q", ErrPrefixMismatch, parsed.Prefix(), want)
	}
	return parsed, nil
}

// String returns the wire representation.
func (i ID) String() string { return string(i) }

// IsZero reports whether i is the unset zero value.
func (i ID) IsZero() bool { return i == "" }

// Prefix returns the entity prefix, or the empty prefix when i is malformed.
func (i ID) Prefix() Prefix {
	sep := strings.IndexByte(string(i), '_')
	if sep <= 0 {
		return ""
	}
	return Prefix(i[:sep])
}

// HasPrefix reports whether i carries prefix p.
func (i ID) HasPrefix(p Prefix) bool { return i.Prefix() == p }
