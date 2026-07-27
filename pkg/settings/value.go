package settings

import (
	"fmt"
	"sort"

	"github.com/modbit/modbit/pkg/modberr"
)

// coerce normalizes a value decoded from JSON, YAML, or a typed client into the canonical Go
// representation for the definition's type.
//
// Canonical representations: bool, int64, float64, string, []string, map[string]any. Normalizing
// once, at ingestion, is what keeps `any` confined to this file (R-GO-07): every other function in
// this package may assume the canonical form.
//
// A value that cannot be coerced is an error, never a silent fallback (SET-2).
func coerce(d Definition, raw any) (any, error) {
	invalid := func(reason string) error {
		return modberr.Newf(modberr.CodeSettingInvalid, "setting %q: %s", d.Key, reason).
			WithDetail("setting_key", string(d.Key)).
			WithDetail("expected_type", string(d.Type))
	}

	switch d.Type {
	case TypeBool:
		v, ok := raw.(bool)
		if !ok {
			return nil, invalid("expected a boolean")
		}
		return v, nil

	case TypeInt:
		n, ok := asInt64(raw)
		if !ok {
			return nil, invalid("expected an integer")
		}
		if d.Min != nil && n < *d.Min {
			return nil, invalid(fmt.Sprintf("value %d is below the minimum %d", n, *d.Min))
		}
		if d.Max != nil && n > *d.Max {
			return nil, invalid(fmt.Sprintf("value %d is above the maximum %d", n, *d.Max))
		}
		return n, nil

	case TypeNumber:
		f, ok := asFloat64(raw)
		if !ok {
			return nil, invalid("expected a number")
		}
		if d.Min != nil && f < float64(*d.Min) {
			return nil, invalid(fmt.Sprintf("value %v is below the minimum %d", f, *d.Min))
		}
		if d.Max != nil && f > float64(*d.Max) {
			return nil, invalid(fmt.Sprintf("value %v is above the maximum %d", f, *d.Max))
		}
		return f, nil

	case TypeString:
		v, ok := raw.(string)
		if !ok {
			return nil, invalid("expected a string")
		}
		return v, nil

	case TypeEnum:
		v, ok := raw.(string)
		if !ok {
			return nil, invalid("expected a string")
		}
		for _, member := range d.Enum {
			if member == v {
				return v, nil
			}
		}
		return nil, invalid(fmt.Sprintf("value %q is not one of the permitted values", v))

	case TypeStringList:
		list, err := asStringSlice(raw)
		if err != nil {
			return nil, invalid(err.Error())
		}
		return list, nil

	case TypeObject:
		switch v := raw.(type) {
		case nil:
			return map[string]any{}, nil
		case map[string]any:
			return cloneObject(v), nil
		default:
			return nil, invalid("expected an object")
		}
	}
	return nil, invalid(fmt.Sprintf("unknown type %q", d.Type))
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		// JSON has no integer type; accept a float that is exactly integral and reject 1.5 rather
		// than truncating it, which would silently change a budget or a limit.
		if t == float64(int64(t)) {
			return int64(t), true
		}
	case float32:
		if float64(t) == float64(int64(t)) {
			return int64(t), true
		}
	}
	return 0, false
}

func asFloat64(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case float32:
		return float64(t), true
	case float64:
		return t, true
	}
	return 0, false
}

func asStringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return []string{}, nil
	case []string:
		out := make([]string, len(t))
		copy(out, t)
		return out, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("expected a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("expected a list of strings")
}

func cloneObject(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if nested, ok := v.(map[string]any); ok {
			out[k] = cloneObject(nested)
			continue
		}
		out[k] = v
	}
	return out
}

// valuesEqual compares two canonical values. It is used for restrictive-order lookup and for
// deciding whether a lower scope actually attempted to change a locked value.
func valuesEqual(a, b any) bool {
	switch x := a.(type) {
	case []string:
		y, ok := b.([]string)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, present := y[k]
			if !present || !valuesEqual(xv, yv) {
				return false
			}
		}
		return true
	}
	// Numeric literals arrive as int64 from contracts and float64 from JSON; compare numerically so
	// that 4 and 4.0 are the same value.
	if xf, ok := asFloat64(a); ok {
		if yf, ok := asFloat64(b); ok {
			return xf == yf
		}
		return false
	}
	return a == b
}

// dedupePreservingOrder returns values with duplicates removed, keeping first occurrence.
func dedupePreservingOrder(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// sortedUnique returns the sorted set union of values.
func sortedUnique(values []string) []string {
	out := dedupePreservingOrder(values)
	sort.Strings(out)
	return out
}

// intersectAllowlists intersects allowlists, treating Wildcard as the universal set.
//
// The wildcard rule is what makes "intersection" usable in practice: a scope that has no opinion
// carries ["*"], so adding a scope never accidentally empties the allowlist.
func intersectAllowlists(lists [][]string) []string {
	var acc []string
	started := false
	for _, list := range lists {
		if containsWildcard(list) {
			continue
		}
		if !started {
			acc = dedupePreservingOrder(list)
			started = true
			continue
		}
		present := make(map[string]struct{}, len(list))
		for _, v := range list {
			present[v] = struct{}{}
		}
		next := acc[:0]
		for _, v := range acc {
			if _, ok := present[v]; ok {
				next = append(next, v)
			}
		}
		acc = next
	}
	if !started {
		return []string{Wildcard}
	}
	sort.Strings(acc)
	return acc
}

func containsWildcard(list []string) bool {
	for _, v := range list {
		if v == Wildcard {
			return true
		}
	}
	return false
}

// deepMergeObjects merges objects with the closest preference winning per leaf. contributions are
// ordered highest precedence first, so the merge applies them in reverse.
func deepMergeObjects(contributions []map[string]any) map[string]any {
	out := map[string]any{}
	for i := len(contributions) - 1; i >= 0; i-- {
		mergeInto(out, contributions[i])
	}
	return out
}

func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if nested, ok := v.(map[string]any); ok {
			existing, _ := dst[k].(map[string]any)
			if existing == nil {
				existing = map[string]any{}
			}
			mergeInto(existing, nested)
			dst[k] = existing
			continue
		}
		dst[k] = v
	}
}
