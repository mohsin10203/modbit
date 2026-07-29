// Command modbit-model-gateway is the Model Gateway deployable (SDD §4.4).
//
// It exists as its own process because INV-1 and INV-2 require it to. INV-1 puts every hosted model
// call through a Modbit Model Gateway; INV-2 forbids provider credentials from entering the IDE,
// extension host, agent context, worker, sandbox, browser host, plugin, hook or MCP server. A
// `pkg/gateway` linked into any of those satisfies INV-1 and breaks INV-2, because the credential
// then lives in that address space. No amount of care inside the library changes which process holds
// the secret, so the boundary has to be a process boundary. SDD §4.4 says the same thing as
// architecture: "separate security identity and egress boundary".
//
// This is the first deployable in the repository. Everything before it was a library.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Environ()); err != nil {
		// The error is printed rather than logged through a framework because there is no framework
		// yet, and because modberr redacts what must not be printed.
		fmt.Fprintf(os.Stderr, "modbit-model-gateway: %v\n", err)
		os.Exit(1)
	}
}

// run wires the process and is separated from main so it is testable.
func run(environ []string) error {
	broker, err := newEnvBroker(environ, scrubEnv)
	if err != nil {
		return err
	}
	fmt.Printf("modbit-model-gateway: %s ready\n", broker)
	return nil
}
