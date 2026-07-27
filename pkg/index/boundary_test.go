package index_test

import (
	"os/exec"
	"strings"
	"testing"
)

// V10, enforced rather than asserted.
//
// Embedding a chunk is egress of repository content, and dev-06 requires embedding calls to route
// through the Model Gateway like all inference so they pass the credential boundary (INV-2), DLP
// inspection (INV-3), and cost metering. The Embedder port exists for that reason. A port is only
// worth having if nothing can go around it, and the way it gets gone around is somebody adding an
// HTTP client to this package for one urgent case.
//
// A comment saying "do not import net/http" is a convention. This is the same statement in a form
// that fails.
//
// The indexer has a second reason to hold this line: it is the one component that opens every file
// in a repository, so a network capability here is the difference between a bug and an exfiltration
// primitive.
func TestSecurityIndexPackageCannotReachTheNetwork(t *testing.T) {
	forbidden := map[string]string{
		"net":          "raw sockets",
		"net/http":     "an HTTP client",
		"net/url":      "URL handling, which only a network caller needs",
		"net/rpc":      "RPC",
		"crypto/tls":   "a TLS client",
		"os/exec":      "subprocess execution, which is also how CTX-12 gets violated",
		"database/sql": "a database client",
		"net/smtp":     "an SMTP client",
		// CTX-12: indexing must not execute repository code. Go's own tooling makes that easy to
		// violate by accident — go/build shells out through os/exec, and go/importer can invoke a
		// compiler — so symbol extraction is confined to go/parser and go/ast, which only read bytes.
		"go/build":                               "package loading, which shells out to the go command (CTX-12)",
		"go/importer":                            "type-checker importers, which can invoke a compiler (CTX-12)",
		"plugin":                                 "loading code at runtime",
		"github.com/modbit/modbit/pkg/gateway":   "the gateway directly, bypassing the Embedder port",
		"github.com/modbit/modbit/pkg/inference": "provider adapters directly",
	}

	// -deps gives the full transitive set, so a dependency that reaches the network on this
	// package's behalf is caught too.
	out, err := exec.Command("go", "list", "-deps", "github.com/modbit/modbit/pkg/index").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg = strings.TrimSpace(pkg)
		if why, bad := forbidden[pkg]; bad {
			t.Errorf("pkg/index depends on %q, which brings %s.\n"+
				"Embedding and every other egress must route through the Model Gateway via the "+
				"Embedder port, so it passes the credential boundary, DLP, and cost metering.", pkg, why)
		}
	}
}
