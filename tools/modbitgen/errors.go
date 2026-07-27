package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// errorCatalog mirrors contracts/errors/catalog.yaml.
type errorCatalog struct {
	Version int         `yaml:"version"`
	Codes   []errorCode `yaml:"codes"`
}

type errorCode struct {
	Code        string   `yaml:"code"`
	HTTPStatus  int      `yaml:"http_status"`
	Retryable   bool     `yaml:"retryable"`
	Description string   `yaml:"description"`
	DetailKeys  []string `yaml:"detail_keys"`
	Deprecated  bool     `yaml:"deprecated"`
}

func loadErrorCatalog(path string) (*errorCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c errorCatalog
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *errorCatalog) validate() error {
	if c.Version == 0 {
		return fmt.Errorf("catalog version is required")
	}
	if len(c.Codes) == 0 {
		return fmt.Errorf("catalog defines no codes")
	}
	seenCode := make(map[string]struct{}, len(c.Codes))
	for _, e := range c.Codes {
		if !strings.HasPrefix(e.Code, "MODBIT_") {
			return fmt.Errorf("code %q must start with MODBIT_ (R-ERR-01)", e.Code)
		}
		if e.Code != strings.ToUpper(e.Code) {
			return fmt.Errorf("code %q must be upper case", e.Code)
		}
		if _, dup := seenCode[e.Code]; dup {
			return fmt.Errorf("duplicate code %q", e.Code)
		}
		seenCode[e.Code] = struct{}{}
		if e.HTTPStatus < 100 || e.HTTPStatus > 599 {
			return fmt.Errorf("code %q: http_status %d out of range", e.Code, e.HTTPStatus)
		}
		if strings.TrimSpace(e.Description) == "" {
			return fmt.Errorf("code %q: description is required", e.Code)
		}
		seenKey := make(map[string]struct{}, len(e.DetailKeys))
		for _, k := range e.DetailKeys {
			if k != strings.ToLower(k) || strings.ContainsAny(k, " .-") {
				return fmt.Errorf("code %q: detail key %q must be lower_snake_case", e.Code, k)
			}
			if _, dup := seenKey[k]; dup {
				return fmt.Errorf("code %q: duplicate detail key %q", e.Code, k)
			}
			seenKey[k] = struct{}{}
			// R-ERR-02 is enforced mechanically by the allowlist, but a key whose *name* invites a
			// secret is rejected here so the mistake never reaches review.
			for _, banned := range []string{"secret", "token", "password", "credential", "cookie", "authorization", "prompt", "completion", "api_key"} {
				if strings.Contains(k, banned) {
					return fmt.Errorf("code %q: detail key %q contains %q; error details never carry sensitive values (R-ERR-02)", e.Code, k, banned)
				}
			}
		}
	}
	return nil
}

func (c *errorCatalog) emitGo() []byte {
	var b strings.Builder
	b.WriteString(generatedGoHeader("modberr", "contracts/errors/catalog.yaml"))

	fmt.Fprintf(&b, "// CatalogVersion is the version of contracts/errors/catalog.yaml this file was generated from.\nconst CatalogVersion = %d\n\n", c.Version)

	b.WriteString("// Stable Modbit error codes. Codes are append-only and never reused (R-ERR-01).\nconst (\n")
	for _, e := range c.Codes {
		b.WriteString(wrapComment(e.Description, "\t", 100))
		if e.Deprecated {
			b.WriteString("\t//\n\t// Deprecated: retained for wire compatibility.\n")
		}
		fmt.Fprintf(&b, "\t%s Code = %s\n\n", "Code"+goIdent(strings.TrimPrefix(e.Code, "MODBIT_")), goQuote(e.Code))
	}
	b.WriteString(")\n\n")

	b.WriteString("// specs is the generated code registry consulted by New, Wrap, and WithDetail.\nvar specs = map[Code]Spec{\n")
	for _, e := range c.Codes {
		fmt.Fprintf(&b, "\t%s: {\n", "Code"+goIdent(strings.TrimPrefix(e.Code, "MODBIT_")))
		fmt.Fprintf(&b, "\t\tCode:        %s,\n", goQuote(e.Code))
		fmt.Fprintf(&b, "\t\tHTTPStatus:  %d,\n", e.HTTPStatus)
		fmt.Fprintf(&b, "\t\tRetryable:   %t,\n", e.Retryable)
		fmt.Fprintf(&b, "\t\tDescription: %s,\n", goQuote(e.Description))
		fmt.Fprintf(&b, "\t\tDetailKeys:  %s,\n", goStringSlice(e.DetailKeys))
		fmt.Fprintf(&b, "\t\tDeprecated:  %t,\n", e.Deprecated)
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func (c *errorCatalog) emitTS() []byte {
	var b strings.Builder
	b.WriteString(generatedTSHeader("contracts/errors/catalog.yaml"))

	fmt.Fprintf(&b, "export const ERROR_CATALOG_VERSION = %d;\n\n", c.Version)

	b.WriteString("export const ErrorCode = {\n")
	for _, e := range c.Codes {
		b.WriteString(wrapComment(e.Description, "  ", 100))
		fmt.Fprintf(&b, "  %s: %s,\n", tsConstName(strings.TrimPrefix(e.Code, "MODBIT_")), goQuote(e.Code))
	}
	b.WriteString("} as const;\n\n")
	b.WriteString("export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];\n\n")

	b.WriteString("export interface ErrorSpec {\n  readonly code: ErrorCode;\n  readonly httpStatus: number;\n  readonly retryable: boolean;\n  readonly description: string;\n  readonly detailKeys: readonly string[];\n  readonly deprecated: boolean;\n}\n\n")

	b.WriteString("export const ERROR_SPECS: Readonly<Record<ErrorCode, ErrorSpec>> = {\n")
	for _, e := range c.Codes {
		fmt.Fprintf(&b, "  [ErrorCode.%s]: {\n", tsConstName(strings.TrimPrefix(e.Code, "MODBIT_")))
		fmt.Fprintf(&b, "    code: %s,\n", goQuote(e.Code))
		fmt.Fprintf(&b, "    httpStatus: %d,\n", e.HTTPStatus)
		fmt.Fprintf(&b, "    retryable: %t,\n", e.Retryable)
		fmt.Fprintf(&b, "    description: %s,\n", goQuote(e.Description))
		fmt.Fprintf(&b, "    detailKeys: %s,\n", tsLiteral(toAnySlice(e.DetailKeys)))
		fmt.Fprintf(&b, "    deprecated: %t,\n", e.Deprecated)
		b.WriteString("  },\n")
	}
	b.WriteString("} as const;\n")
	return []byte(b.String())
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
