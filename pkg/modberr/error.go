// Package modberr implements Modbit's structured error model.
//
// Boundary: error construction, classification, and wire serialization. It owns the stable
// MODBIT_* code space and the rule that error details never carry sensitive values. It does not
// log, does not decide retry policy, and does not map to transport frameworks.
//
// Requirements: api-and-events-v5.1.md §6 (error model); rules.md R-ERR-01 (stable code across
// every process boundary), R-ERR-02 (no secrets, prompts, completions, tool output, headers,
// tokens, or cookies in details).
//
// # Two representations, deliberately different
//
// Error implements two views of the same failure:
//
//   - Error() is the operator view. It includes the wrapped cause chain and is safe only for
//     structured logs and traces that the platform already redacts.
//   - MarshalJSON is the wire view. It contains the code, the developer-authored message, the
//     retryable flag, the correlation id, and allowlisted details — and never the cause chain.
//
// Keeping these apart is what stops an upstream driver message, a provider response body, or a
// filesystem path from reaching an API client through an error.
package modberr

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/id"
)

// Code is a stable Modbit error code. Values come from the generated catalog in codes_gen.go.
type Code string

// Spec is the catalog entry for a Code.
type Spec struct {
	Code        Code
	HTTPStatus  int
	Retryable   bool
	Description string
	// DetailKeys is the allowlist of detail keys this code may carry. WithDetail refuses anything
	// absent from this list, which is the mechanical control behind R-ERR-02.
	DetailKeys []string
	Deprecated bool
}

// reservedDetailKey records the names of detail keys that were rejected. Only key names are
// recorded, never values, so a rejected secret cannot leak through the diagnostic itself.
const reservedDetailKey = "unregistered_detail_keys"

// Error is a Modbit error.
//
// Values are treated as immutable: the With* methods return a modified copy so an error may be
// shared across goroutines without synchronization.
type Error struct {
	code          Code
	message       string
	correlationID id.ID
	details       map[string]string
	cause         error
}

var _ error = (*Error)(nil)

// Lookup returns the catalog spec for c.
func Lookup(c Code) (Spec, bool) {
	s, ok := specs[c]
	return s, ok
}

// Codes returns every registered code, sorted. Used by conformance tests and documentation.
func Codes() []Code {
	out := make([]Code, 0, len(specs))
	for c := range specs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// New returns an Error carrying code and a developer-authored message.
//
// The message is part of the API surface: write it for the caller, not for the implementer, and
// never interpolate untrusted or sensitive content into it. Unknown codes degrade to
// CodeInternal rather than producing an uncatalogued code on the wire.
func New(code Code, message string) *Error {
	if _, ok := specs[code]; !ok {
		return &Error{
			code:    CodeInternal,
			message: message,
			details: map[string]string{"uncatalogued_code": string(code)},
		}
	}
	return &Error{code: code, message: message}
}

// Newf is New with a format string. The same message rules apply: format only values that are
// safe to return to an API client.
func Newf(code Code, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

// Wrap classifies cause under code while preserving it for errors.Is and errors.As.
//
// The cause appears in Error() but never in MarshalJSON.
func Wrap(cause error, code Code, message string) *Error {
	if cause == nil {
		return nil
	}
	e := New(code, message)
	e.cause = cause
	return e
}

// Wrapf is Wrap with a format string.
func Wrapf(cause error, code Code, format string, args ...any) *Error {
	if cause == nil {
		return nil
	}
	return Wrap(cause, code, fmt.Sprintf(format, args...))
}

func (e *Error) clone() *Error {
	out := &Error{
		code:          e.code,
		message:       e.message,
		correlationID: e.correlationID,
		cause:         e.cause,
	}
	if len(e.details) > 0 {
		out.details = make(map[string]string, len(e.details)+1)
		for k, v := range e.details {
			out.details[k] = v
		}
	}
	return out
}

// Error returns the operator view, including the cause chain. Do not return this string to an API
// client; use MarshalJSON.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(string(e.code))
	if e.message != "" {
		b.WriteString(": ")
		b.WriteString(e.message)
	}
	if e.cause != nil {
		b.WriteString(": ")
		b.WriteString(e.cause.Error())
	}
	return b.String()
}

// Unwrap exposes the wrapped cause to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.cause }

// Code returns the stable error code.
func (e *Error) Code() Code { return e.code }

// Message returns the developer-authored message.
func (e *Error) Message() string { return e.message }

// Retryable reports whether the catalog marks this code retryable.
//
// A retryable code is permission to retry within an attempt budget, never permission to retry
// without one (R-ERR-03).
func (e *Error) Retryable() bool {
	if s, ok := specs[e.code]; ok {
		return s.Retryable
	}
	return false
}

// HTTPStatus returns the catalog HTTP status for this code.
func (e *Error) HTTPStatus() int {
	if s, ok := specs[e.code]; ok {
		return s.HTTPStatus
	}
	return 500
}

// CorrelationID returns the correlation identifier, or the zero ID.
func (e *Error) CorrelationID() id.ID { return e.correlationID }

// Details returns a copy of the attached detail map.
func (e *Error) Details() map[string]string {
	out := make(map[string]string, len(e.details))
	for k, v := range e.details {
		out[k] = v
	}
	return out
}

// WithCorrelation returns a copy carrying the correlation identifier. A value whose prefix is not
// `cor` is ignored rather than surfaced, since a mismatched identifier in an error response is
// itself an information leak.
func (e *Error) WithCorrelation(correlationID id.ID) *Error {
	if !correlationID.HasPrefix(id.Correlation) {
		return e
	}
	out := e.clone()
	out.correlationID = correlationID
	return out
}

// WithDetail returns a copy carrying key=value, provided key is allowlisted for this code in
// contracts/errors/catalog.yaml.
//
// An unregistered key is dropped and its *name* is recorded under "unregistered_detail_keys". The
// value is discarded unread, so an accidental secret never enters the error. Dropping loudly
// rather than silently means the mistake is visible in tests and traces without the payload ever
// being retained.
func (e *Error) WithDetail(key, value string) *Error {
	out := e.clone()
	if out.details == nil {
		out.details = make(map[string]string, 2)
	}
	if !e.detailKeyAllowed(key) {
		out.details[reservedDetailKey] = appendCSV(out.details[reservedDetailKey], key)
		return out
	}
	out.details[key] = value
	return out
}

// WithDetails applies WithDetail for each entry. Keys are applied in sorted order so that the
// recorded rejection list is deterministic.
func (e *Error) WithDetails(kv map[string]string) *Error {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := e
	for _, k := range keys {
		out = out.WithDetail(k, kv[k])
	}
	return out
}

func (e *Error) detailKeyAllowed(key string) bool {
	s, ok := specs[e.code]
	if !ok {
		return false
	}
	for _, allowed := range s.DetailKeys {
		if allowed == key {
			return true
		}
	}
	return false
}

func appendCSV(existing, value string) string {
	if existing == "" {
		return value
	}
	for _, present := range strings.Split(existing, ",") {
		if present == value {
			return existing
		}
	}
	return existing + "," + value
}

// wireError is the serialized shape from api-and-events-v5.1.md §6.
type wireError struct {
	Code          string            `json:"code"`
	Message       string            `json:"message"`
	Retryable     bool              `json:"retryable"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
}

type wireEnvelope struct {
	Error wireError `json:"error"`
}

// MarshalJSON renders the wire view. The cause chain is deliberately excluded (R-ERR-02).
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireEnvelope{Error: wireError{
		Code:          string(e.code),
		Message:       e.message,
		Retryable:     e.Retryable(),
		CorrelationID: e.correlationID.String(),
		Details:       e.details,
	}})
}

// UnmarshalJSON reconstructs an Error received from another Modbit process. Details survive the
// round trip even when the local catalog does not recognize a key, so a newer peer's diagnostics
// are not silently discarded by an older reader (R-CTR-05).
func (e *Error) UnmarshalJSON(data []byte) error {
	var env wireEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	e.code = Code(env.Error.Code)
	e.message = env.Error.Message
	e.details = env.Error.Details
	e.correlationID = ""
	if env.Error.CorrelationID != "" {
		if parsed, err := id.ParseAs(env.Error.CorrelationID, id.Correlation); err == nil {
			e.correlationID = parsed
		}
	}
	return nil
}

// CodeOf returns the Modbit code carried by err, walking the wrap chain.
//
// A non-Modbit error reports CodeInternal: an unclassified failure is never presented as a
// well-understood one.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.code
	}
	if err == nil {
		return ""
	}
	return CodeInternal
}

// Is reports whether err carries code.
func Is(err error, code Code) bool { return CodeOf(err) == code }

// IsRetryable reports whether err carries a retryable code.
func IsRetryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable()
	}
	return false
}

// HTTPStatusOf returns the HTTP status for err, defaulting to 500.
func HTTPStatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.HTTPStatus()
	}
	return 500
}

// As is a typed convenience over errors.As.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
