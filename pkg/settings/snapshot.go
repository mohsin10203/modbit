package settings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Snapshot is an immutable, content-addressed set of effective settings bound to a run.
//
// Runs execute against a snapshot rather than live settings so that a mid-run change cannot alter
// the policy a run is already operating under; changes apply only to new runs (INV-6, R-SET-10).
type Snapshot struct {
	ID id.ID `json:"id"`
	// Digest is the SHA-256 of the canonical serialization. Two snapshots with identical effective
	// values share a digest, which is what lets a worker verify it received the settings the lease
	// was signed for.
	Digest string `json:"digest"`
	// Values holds the effective value per key.
	Values map[Key]any `json:"values"`
	// Locks records which keys are locked and by which scope, so a client can render a lock without
	// re-running resolution.
	Locks map[Key]Scope `json:"locks,omitempty"`
	// Sources records the winning scope per key.
	Sources map[Key]Scope `json:"sources"`
	// SchemaVersions records the namespace schema version each value was resolved under, so a
	// snapshot replayed after a migration can be interpreted correctly (SET-3).
	SchemaVersions map[string]int `json:"schema_versions"`
	// Diagnostics carries anything the resolver had to correct. A snapshot with error diagnostics is
	// still produced: refusing to record the problem would hide it.
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// NewSnapshot freezes a resolution result into a snapshot.
func NewSnapshot(result Result, generator *id.Generator) (Snapshot, error) {
	if generator == nil {
		generator = id.NewGenerator(nil)
	}
	snapshotID, err := generator.New(id.SettingsSnapshot)
	if err != nil {
		return Snapshot{}, modberr.Wrap(err, modberr.CodeInternal, "allocate settings snapshot identifier")
	}

	s := Snapshot{
		ID:             snapshotID,
		Values:         make(map[Key]any, len(result.Resolutions)),
		Locks:          make(map[Key]Scope),
		Sources:        make(map[Key]Scope, len(result.Resolutions)),
		SchemaVersions: make(map[string]int),
		Diagnostics:    append([]Diagnostic(nil), result.Diagnostics...),
	}
	for key, res := range result.Resolutions {
		s.Values[key] = res.Value
		s.Sources[key] = res.Source
		if res.Locked {
			s.Locks[key] = res.LockedBy
		}
		// A namespace's schema version is uniform across its keys; the max guards against a
		// partially migrated registry reporting an older version than it resolved under.
		ns := res.Definition.Namespace
		if res.Definition.SchemaVersion > s.SchemaVersions[ns] {
			s.SchemaVersions[ns] = res.Definition.SchemaVersion
		}
	}

	digest, err := s.computeDigest()
	if err != nil {
		return Snapshot{}, err
	}
	s.Digest = digest
	return s, nil
}

// canonicalForm is the digest input: values, locks, sources, and schema versions with sorted keys.
// The snapshot identifier and diagnostics are excluded so that two independently produced
// snapshots of the same effective settings compare equal.
type canonicalForm struct {
	Values         map[string]any    `json:"values"`
	Locks          map[string]string `json:"locks"`
	Sources        map[string]string `json:"sources"`
	SchemaVersions map[string]int    `json:"schema_versions"`
}

func (s Snapshot) computeDigest() (string, error) {
	form := canonicalForm{
		Values:         make(map[string]any, len(s.Values)),
		Locks:          make(map[string]string, len(s.Locks)),
		Sources:        make(map[string]string, len(s.Sources)),
		SchemaVersions: s.SchemaVersions,
	}
	for k, v := range s.Values {
		form.Values[string(k)] = v
	}
	for k, v := range s.Locks {
		form.Locks[string(k)] = string(v)
	}
	for k, v := range s.Sources {
		form.Sources[string(k)] = string(v)
	}
	// encoding/json sorts map keys, so this serialization is stable across processes and runs.
	encoded, err := json.Marshal(form)
	if err != nil {
		return "", modberr.Wrap(err, modberr.CodeInternal, "serialize settings snapshot")
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Verify recomputes the digest and reports whether the snapshot is intact. A worker calls this on
// the settings it received before honouring a lease.
func (s Snapshot) Verify() error {
	digest, err := s.computeDigest()
	if err != nil {
		return err
	}
	if digest != s.Digest {
		return modberr.New(modberr.CodeConflict, "settings snapshot digest does not match its contents").
			WithDetail("resource_type", "settings_snapshot")
	}
	return nil
}

// Bool returns a boolean value. It reports an error rather than a zero value when the key is
// absent or the type is wrong, so a caller cannot mistake "unset" for "false" on a security
// setting.
func (s Snapshot) Bool(k Key) (bool, error) {
	v, ok := s.Values[k]
	if !ok {
		return false, missingKey(k)
	}
	b, ok := v.(bool)
	if !ok {
		return false, wrongType(k, "bool")
	}
	return b, nil
}

// Int returns an integer value.
func (s Snapshot) Int(k Key) (int64, error) {
	v, ok := s.Values[k]
	if !ok {
		return 0, missingKey(k)
	}
	n, ok := asInt64(v)
	if !ok {
		return 0, wrongType(k, "int")
	}
	return n, nil
}

// String returns a string or enum value.
func (s Snapshot) String(k Key) (string, error) {
	v, ok := s.Values[k]
	if !ok {
		return "", missingKey(k)
	}
	str, ok := v.(string)
	if !ok {
		return "", wrongType(k, "string")
	}
	return str, nil
}

// StringList returns a copy of a list value.
func (s Snapshot) StringList(k Key) ([]string, error) {
	v, ok := s.Values[k]
	if !ok {
		return nil, missingKey(k)
	}
	list, ok := v.([]string)
	if !ok {
		return nil, wrongType(k, "string_list")
	}
	out := make([]string, len(list))
	copy(out, list)
	return out, nil
}

// Object returns a deep copy of an object value.
func (s Snapshot) Object(k Key) (map[string]any, error) {
	v, ok := s.Values[k]
	if !ok {
		return nil, missingKey(k)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, wrongType(k, "object")
	}
	return cloneObject(obj), nil
}

// Keys returns every key in the snapshot, sorted.
func (s Snapshot) Keys() []Key {
	out := make([]Key, 0, len(s.Values))
	for k := range s.Values {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func missingKey(k Key) error {
	return modberr.Newf(modberr.CodeSettingUnknown, "settings snapshot has no value for %q", k).
		WithDetail("setting_key", string(k))
}

func wrongType(k Key, want string) error {
	return modberr.Newf(modberr.CodeSettingInvalid, "setting %q is not a %s", k, want).
		WithDetail("setting_key", string(k)).
		WithDetail("expected_type", want)
}
