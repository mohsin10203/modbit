// Command modbit-model-gateway is the Model Gateway deployable (SDD §4.4).
//
// It exists as its own process because INV-1 and INV-2 require it to. INV-1 puts every hosted model
// call through a Modbit Model Gateway; INV-2 forbids provider credentials from entering the IDE,
// extension host, agent context, worker, sandbox, browser host, plugin, hook or MCP server. A
// `pkg/gateway` linked into any of those satisfies INV-1 and breaks INV-2, because the credential
// then lives in that address space. No amount of care inside the library changes which process
// holds the secret, so the boundary has to be a process boundary. SDD §4.4 says the same thing as
// architecture: "separate security identity and egress boundary".
//
// This is the first deployable in the repository. Everything before it was a library.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// defaultAddr binds loopback rather than every interface.
//
// INV-2 makes this the process holding provider credentials, so reaching it must be a deliberate
// deployment decision rather than a default. A gateway that listened on 0.0.0.0 out of the box
// would be exposed by anything that forgot to configure it.
const defaultAddr = "127.0.0.1:8722"

// shutdownGrace bounds how long in-flight requests have once a signal arrives.
const shutdownGrace = 10 * time.Second

func main() {
	if err := run(context.Background(), os.Environ(), os.Getenv("MODBIT_GATEWAY_ADDR"), nil); err != nil {
		// Printed rather than logged through a framework because there is no framework yet, and
		// because modberr redacts what must not be printed.
		fmt.Fprintf(os.Stderr, "modbit-model-gateway: %v\n", err)
		os.Exit(1)
	}
}

// run wires the process and serves until the context is cancelled or a signal arrives.
//
// It is separated from main, and takes its environment and address as arguments, so a test can
// drive the whole startup path rather than the pieces around it.
//
// ready, when non-nil, is called with the bound address once the listener is open and before
// serving begins. It exists so a test can make a real request instead of sleeping: a lifecycle test
// that cancels without ever connecting proves the shutdown path and nothing about serving, which is
// the decorative-probe mistake this repository has now paid for twice.
func run(ctx context.Context, environ []string, addr string, ready func(net.Addr)) error {
	broker, err := newEnvBroker(environ, scrubEnv)
	if err != nil {
		return err
	}
	if addr == "" {
		addr = defaultAddr
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler: (&server{broker: broker}).routes(),
		// A gateway holding credentials should not be held open by a slow client.
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("modbit-model-gateway: %s listening on %s\n", broker, listener.Addr())
	if ready != nil {
		ready(listener.Addr())
	}

	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(listener) }()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
