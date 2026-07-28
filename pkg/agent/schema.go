package agent

import (
	"encoding/json"
	"slices"
	"strconv"

	"github.com/modbit/modbit/pkg/modberr"
)

// BasicValidator checks a tool input against the subset of JSON Schema tool schemas actually use.
//
// Full JSON Schema is a specification, not a function, and adopting a validator is a dependency
// decision under R-GO-09. This covers object type, required properties, property types, enums, and
// additionalProperties — and **refuses what it cannot check** rather than passing it, which is the
// only safe default for something standing between a model's output and a policy decision.
//
// A schema using a construct this does not understand is a registration-time problem, not a
// call-time one, so Supports reports it and a caller can gate on it.
type BasicValidator struct{}

var _ SchemaValidator = BasicValidator{}

// supportedKeywords is what this validator understands. Anything else in a schema is refused, so a
// constraint the author wrote and this cannot enforce never silently does nothing.
var supportedKeywords = []string{
	"type", "properties", "required", "additionalProperties", "enum", "description", "items",
	"title", "$schema",
}

// Validate implements SchemaValidator.
func (v BasicValidator) Validate(schema, input json.RawMessage) error {
	var doc map[string]any
	if err := json.Unmarshal(schema, &doc); err != nil {
		return modberr.Wrap(err, modberr.CodeInvalidArgument, "tool schema is not a JSON object")
	}
	var value any
	if len(input) == 0 {
		value = map[string]any{}
	} else if err := json.Unmarshal(input, &value); err != nil {
		return modberr.Wrap(err, modberr.CodeInvalidArgument, "tool input is not valid JSON")
	}
	return validateAgainst(doc, value, "")
}

// Supports reports whether every construct in a schema is one this validator enforces.
func (v BasicValidator) Supports(schema json.RawMessage) error {
	var doc map[string]any
	if err := json.Unmarshal(schema, &doc); err != nil {
		return modberr.Wrap(err, modberr.CodeInvalidArgument, "tool schema is not a JSON object")
	}
	return supported(doc, "")
}

func supported(schema map[string]any, path string) error {
	for keyword := range schema {
		if !slices.Contains(supportedKeywords, keyword) {
			return modberr.Newf(modberr.CodeInvalidArgument,
				"schema keyword %q at %q is not enforced by the basic validator", keyword, at(path)).
				WithDetail("field", "input_schema").
				WithDetail("constraint", keyword)
		}
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	for name, raw := range properties {
		child, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if err := supported(child, join(path, name)); err != nil {
			return err
		}
	}
	return nil
}

func validateAgainst(schema map[string]any, value any, path string) error {
	fail := func(msg string) error {
		return modberr.Newf(modberr.CodeInvalidArgument, "%s: %s", at(path), msg).
			WithDetail("field", "input")
	}

	if want, ok := schema["type"].(string); ok {
		if got := jsonTypeOf(value); got != want && !(want == "number" && got == "integer") {
			return fail("expected " + want + ", got " + got)
		}
	}

	if allowed, ok := schema["enum"].([]any); ok {
		matched := false
		for _, candidate := range allowed {
			if equalJSON(candidate, value) {
				matched = true
				break
			}
		}
		if !matched {
			// The permitted values are not echoed: a schema's enum can name resources, and an error
			// is written to logs (R-ERR-02).
			return fail("value is not one of the permitted values")
		}
	}

	object, isObject := value.(map[string]any)
	if !isObject {
		return nil
	}

	if required, ok := schema["required"].([]any); ok {
		for _, raw := range required {
			name, ok := raw.(string)
			if !ok {
				continue
			}
			if _, present := object[name]; !present {
				return fail("missing required property " + strconv.Quote(name))
			}
		}
	}

	properties, _ := schema["properties"].(map[string]any)
	if allow, ok := schema["additionalProperties"].(bool); ok && !allow {
		for name := range object {
			if _, declared := properties[name]; !declared {
				// Refusing an undeclared property matters more here than in ordinary validation: the
				// input comes from a model, and a tool that quietly ignores an extra field lets a
				// prompt injection carry an argument the schema author never anticipated.
				return fail("property " + strconv.Quote(name) + " is not declared in the schema")
			}
		}
	}

	for name, raw := range properties {
		child, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		present, exists := object[name]
		if !exists {
			continue
		}
		if err := validateAgainst(child, present, join(path, name)); err != nil {
			return err
		}
	}
	return nil
}

func jsonTypeOf(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if v == float64(int64(v)) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func equalJSON(a, b any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}

func at(path string) string {
	if path == "" {
		return "input"
	}
	return "input." + path
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// itoa renders a schema version for Definition.Qualified.
func itoa(n int) string { return strconv.Itoa(n) }
