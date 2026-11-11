// Command hkm-realtime is the WebSocket edge for the HKM realtime plugin.
//
// WHAT IT IS AND WHAT IT DELIBERATELY IS NOT
// ------------------------------------------
// It terminates WebSocket connections, holds them, and fans out events it
// receives from NATS. It contains NO authorization rule, NO database, NO
// session parser and no knowledge of the application's domain — every decision
// about who may see which channel is asked of the PHP application over NATS
// request/reply, so that rule has exactly one implementation, in the place that
// can query the data it depends on.
//
// That is the whole architectural point. A Go edge that re-implemented the
// authorizer would be a second place for a channel to be considered readable,
// and the two would drift.
//
// WHY A SEPARATE PROCESS AT ALL
// -----------------------------
// `hkm cli realtime:serve` (PHP on OpenSwoole) does the same job and is the
// right answer for most deployments — it is one process, it needs no second
// language, and its authorizer runs in-process with no round trip. This exists
// for the case where connection COUNT is the constraint: a goroutine per
// connection is a few kilobytes, so one of these holds six figures of idle
// sockets on modest memory.
//
// Both speak the identical client protocol, so swapping one for the other is a
// deployment change and not a client change.
//
//	hkm-realtime -version
//	WEBSOCKET_ORIGINS=https://app.example.com hkm-realtime
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/AlfaCode-Team/hkm-realtime/internal/authz"
	"github.com/AlfaCode-Team/hkm-realtime/internal/bus"
	"github.com/AlfaCode-Team/hkm-realtime/internal/channel"
	"github.com/AlfaCode-Team/hkm-realtime/internal/config"
	"github.com/AlfaCode-Team/hkm-realtime/internal/server"
)

// version is overridden at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	jsonLog := flag.Bool("json-log", false, "log as JSON lines instead of text")
	flag.Parse()

	if *showVersion {
		fmt.Printf("hkm-realtime %s\n", version)

		return
	}

	log := newLogger(*jsonLog)

	if err := run(log); err != nil {
		log.Error("hkm-realtime exited", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		// Returned rather than logged-and-continued. The one setting that can
		// fail here is WEBSOCKET_ORIGINS, and a server that starts with an
		// empty allowlist refuses every connection while looking healthy —
		// which is indistinguishable from an application where nothing is
		// happening.
		return err
	}

	log.Info("hkm-realtime starting",
		"version", version,
		"listen", cfg.Listen,
		"path", cfg.Path,
		"origins", cfg.Origins,
		"nats", cfg.NatsURL,
		"bus", cfg.BusSubject,
		"authorize", cfg.AuthSubject,
		"maxConnections", cfg.MaxConnections,
		"maxChannels", cfg.MaxChannels)

	if !cfg.RequireOrigin {
		log.Warn("websocket.origin.not_required",
			"effect", "a connection with NO Origin header is accepted. Correct for a native client, "+
				"which must then authenticate by token, and wrong for a browser-only deployment: it "+
				"removes the hijacking defence for any client that simply omits the header")
	}

	nc, err := connectNats(cfg)
	if err != nil {
		// Refused rather than started. Without the bus there is no event to
		// deliver and no authorizer to ask, so the server would accept
		// connections and deny every subscription — looking healthy and
		// delivering nothing, which is the failure this whole design exists to
		// make impossible.
		return fmt.Errorf("the realtime edge cannot run without NATS: %w", err)
	}
	defer nc.Drain() //nolint:errcheck // best effort on the way out

	authorizer := authz.New(nc, cfg.AuthSubject, cfg.AuthorizeTimeout)
	rt := server.New(cfg, authorizer, log)

	subscription, err := nc.Subscribe(cfg.BusSubject, func(message *nats.Msg) {
		envelope, dropped := bus.Parse(message.Data, channel.Normalise)
		if dropped != "" {
			// Bus input is DATA. A shared NATS instance carries other
			// services' messages, so a malformed one is the ordinary case and
			// not an attack; it is dropped at debug rather than logged as an
			// error that would bury the real ones.
			log.Debug("websocket.bus.dropped", "reason", dropped, "bytes", len(message.Data))

			return
		}

		rt.Deliver(envelope)
	})
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", cfg.BusSubject, err)
	}
	defer subscription.Unsubscribe() //nolint:errcheck // best effort

	httpServer := &http.Server{
		Addr:    cfg.Listen,
		Handler: rt.Handler(),
		// No WriteTimeout: it would cap the lifetime of a hijacked WebSocket
		// connection, which is the one thing this server exists to hold open.
		// ReadHeaderTimeout still bounds a slowloris on the UPGRADE request,
		// which is the part that is still ordinary HTTP.
		ReadHeaderTimeout: 10 * time.Second,
	}

	health := healthServer(cfg, rt, log)

	errs := make(chan error, 2)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("the websocket listener stopped: %w", err)
		}
	}()

	if health != nil {
		go func() {
			if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("websocket.health.stopped", "error", err)
			}
		}()
	}

	log.Info("hkm-realtime ready", "listen", cfg.Listen+cfg.Path)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errs:
		return err
	case sig := <-stop:
		log.Info("hkm-realtime draining", "signal", sig.String(), "connections", rt.Registry().Count())
	}

	// Drain in order: stop accepting, then close the live sockets with 1001
	// Going Away so clients reconnect immediately instead of waiting out a
	// backoff on a TCP reset.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_ = httpServer.Shutdown(shutdownCtx)

	if health != nil {
		_ = health.Shutdown(shutdownCtx)
	}

	rt.Shutdown(shutdownCtx)

	log.Info("hkm-realtime stopped")

	return nil
}

func connectNats(cfg config.Config) (*nats.Conn, error) {
	options := []nats.Option{
		nats.Name("hkm-realtime/" + version),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		// Jittered, because every edge of a restarted bus reconnects at the
		// same instant otherwise and a synchronised retry storm is how an
		// instance that just came back goes down again.
		nats.ReconnectJitter(500*time.Millisecond, 2*time.Second),
	}

	if cfg.NatsToken != "" {
		options = append(options, nats.Token(cfg.NatsToken))
	} else if cfg.NatsUser != "" {
		options = append(options, nats.UserInfo(cfg.NatsUser, cfg.NatsPass))
	}

	return nats.Connect(cfg.NatsURL, options...)
}

// healthServer exposes counters on a SEPARATE loopback listener.
//
// Separate because the WebSocket port is the one a reverse proxy publishes to
// the internet, and connection counts plus channel names describe the
// application's event surface to anyone who can read them. Loopback by default
// for the same reason.
func healthServer(cfg config.Config, rt *server.Server, log *slog.Logger) *http.Server {
	if cfg.HealthListen == "" {
		return nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("GET /statsz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"version":%q,"connections":%d,"channels":%d,"droppedSlowConsumers":%d}`+"\n",
			version, rt.Registry().Count(), rt.Registry().Channels(), rt.Registry().Dropped())
	})

	log.Info("hkm-realtime health listener", "listen", cfg.HealthListen)

	return &http.Server{Addr: cfg.HealthListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

func newLogger(asJSON bool) *slog.Logger {
	level := slog.LevelInfo

	if os.Getenv("WEBSOCKET_DEBUG") != "" {
		level = slog.LevelDebug
	}

	if asJSON {
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
