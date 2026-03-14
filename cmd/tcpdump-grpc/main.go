package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tcpdump-grpc/internal/capture"
	"github.com/tcpdump-grpc/internal/server"
)

func main() {
	var (
		listenAddr     = flag.String("listen", ":50051", "gRPC listen address")
		tlsCert        = flag.String("tls-cert", "", "TLS certificate file")
		tlsKey         = flag.String("tls-key", "", "TLS key file")
		maxDuration    = flag.Uint("max-duration", 300, "Max capture duration in seconds")
		defaultDuration = flag.Uint("default-duration", 60, "Default capture duration in seconds")
		maxConcurrent  = flag.Int("max-concurrent", 10, "Max concurrent captures")
		ratePerIP      = flag.Int("rate-per-ip", 3, "Max concurrent captures per client IP")
		tcpdumpPath    = flag.String("tcpdump-path", "/usr/bin/tcpdump", "Path to tcpdump binary")
		allowedIfaces  = flag.String("allowed-interfaces", "", "Comma-separated allowed interfaces (empty=all)")
		logJSON        = flag.Bool("log-json", false, "JSON structured logging")
	)
	flag.Parse()

	// Set up structured logging
	var handler slog.Handler
	if *logJSON {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)

	// Parse allowed interfaces
	var ifaces []string
	if *allowedIfaces != "" {
		for _, s := range strings.Split(*allowedIfaces, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				ifaces = append(ifaces, s)
			}
		}
	}

	cfg := server.Config{
		ListenAddr: *listenAddr,
		TLSCertFile: *tlsCert,
		TLSKeyFile:  *tlsKey,
		CaptureLimits: capture.Limits{
			MaxDurationSeconds: uint32(*maxDuration),
			DefaultDuration:    uint32(*defaultDuration),
			MaxSnapLen:         65535,
			AllowedInterfaces:  ifaces,
			TcpdumpPath:        *tcpdumpPath,
		},
		MaxConcurrent:  *maxConcurrent,
		RateLimitPerIP: *ratePerIP,
	}

	srv := server.New(cfg, logger)

	// Graceful shutdown on SIGTERM/SIGINT
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		os.Exit(0)
	}()

	if err := srv.Serve(); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
