package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/tcpdump-grpc/proto/capture"
)

func main() {
	var (
		serverAddr = flag.String("server", "localhost:50051", "gRPC server address")
		bpfFilter  = flag.String("filter", "", "BPF filter expression")
		iface      = flag.String("interface", "", "Network interface")
		duration   = flag.Uint("duration", 30, "Capture duration in seconds")
		maxPkts    = flag.Uint64("max-packets", 0, "Max packets (0=unlimited)")
		textOutput = flag.Bool("text", true, "Text output (false=raw pcap)")
		verbosity  = flag.Uint("verbosity", 0, "Verbosity level (0-3)")
		noResolve  = flag.Bool("no-resolve", true, "Don't resolve hostnames")
		useTLS     = flag.Bool("tls", false, "Use TLS")
		tlsCA      = flag.String("tls-ca", "", "TLS CA certificate file")
		validateOnly = flag.Bool("validate", false, "Only validate the filter, don't capture")
		listIfaces = flag.Bool("list-interfaces", false, "List available interfaces")
		pcapFile     = flag.String("write", "", "Write pcap data to file (binary mode only)")
		procNetStats = flag.Bool("proc-net-stats", false, "Dump /proc/net stats from server")
		procNetFiles = flag.String("proc-net-files", "", "Comma-separated /proc/net files (empty=all)")
	)
	flag.Parse()

	// Connect to server
	var dialOpts []grpc.DialOption
	if *useTLS {
		var tlsConfig tls.Config
		if *tlsCA != "" {
			// Load custom CA
			// In production you'd load the CA cert here
			_ = tlsCA
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(
			credentials.NewTLS(&tlsConfig),
		))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(*serverAddr, dialOpts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewCaptureServiceClient(conn)

	// Handle Ctrl-C gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\ninterrupted — stopping capture")
		cancel()
	}()

	// List interfaces mode
	if *listIfaces {
		resp, err := client.ListInterfaces(ctx, &pb.ListInterfacesRequest{})
		if err != nil {
			log.Fatalf("list interfaces: %v", err)
		}
		for _, iface := range resp.Interfaces {
			state := "DOWN"
			if iface.Up {
				state = "UP"
			}
			fmt.Printf("%-20s %s  %v\n", iface.Name, state, iface.Addresses)
		}
		return
	}

	// Proc net stats mode
	if *procNetStats {
		var files []string
		if *procNetFiles != "" {
			for _, f := range strings.Split(*procNetFiles, ",") {
				f = strings.TrimSpace(f)
				if f != "" {
					files = append(files, f)
				}
			}
		}
		resp, err := client.GetProcNetStats(ctx, &pb.ProcNetStatsRequest{
			Files: files,
		})
		if err != nil {
			log.Fatalf("proc net stats: %v", err)
		}
		for _, entry := range resp.Entries {
			fmt.Printf("=== /proc/net/%s ===\n", entry.Name)
			if entry.Error != "" {
				fmt.Fprintf(os.Stderr, "  ERROR: %s\n", entry.Error)
			} else {
				fmt.Print(entry.Content)
				if !strings.HasSuffix(entry.Content, "\n") {
					fmt.Println()
				}
			}
			fmt.Println()
		}
		return
	}

	// Validate-only mode
	if *validateOnly {
		resp, err := client.ValidateFilter(ctx, &pb.ValidateFilterRequest{
			BpfFilter: *bpfFilter,
		})
		if err != nil {
			log.Fatalf("validate: %v", err)
		}
		if resp.Valid {
			fmt.Println("Filter is valid")
		} else {
			fmt.Fprintf(os.Stderr, "Invalid filter: %s\n", resp.Error)
			os.Exit(1)
		}
		return
	}

	// Open pcap output file if requested
	var pcapOut *os.File
	if *pcapFile != "" && !*textOutput {
		pcapOut, err = os.Create(*pcapFile)
		if err != nil {
			log.Fatalf("create pcap file: %v", err)
		}
		defer pcapOut.Close()
	}

	// Start capture
	fmt.Fprintf(os.Stderr, "Starting capture (filter=%q, duration=%ds)...\n", *bpfFilter, *duration)
	startTime := time.Now()

	stream, err := client.StartCapture(ctx, &pb.CaptureRequest{
		BpfFilter:       *bpfFilter,
		Interface:       *iface,
		DurationSeconds: uint32(*duration),
		MaxPackets:      *maxPkts,
		TextOutput:      *textOutput,
		Verbosity:       uint32(*verbosity),
		NoResolve:       *noResolve,
	})
	if err != nil {
		log.Fatalf("start capture: %v", err)
	}

	// Read stream
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				break // We cancelled
			}
			log.Fatalf("recv: %v", err)
		}

		switch p := resp.Payload.(type) {
		case *pb.CaptureResponse_TextLine:
			fmt.Println(p.TextLine)

		case *pb.CaptureResponse_PcapData:
			if pcapOut != nil {
				pcapOut.Write(p.PcapData)
			} else {
				os.Stdout.Write(p.PcapData)
			}

		case *pb.CaptureResponse_Status:
			level := "INFO"
			switch p.Status.Level {
			case pb.StatusMessage_WARNING:
				level = "WARN"
			case pb.StatusMessage_ERROR:
				level = "ERROR"
			}
			fmt.Fprintf(os.Stderr, "[%s] %s\n", level, p.Status.Message)

			if p.Status.Stats != nil {
				s := p.Status.Stats
				fmt.Fprintf(os.Stderr,
					"  packets=%d dropped=%d bytes=%d duration=%.1fs\n",
					s.PacketsCaptured, s.PacketsDropped,
					s.BytesCaptured, s.DurationSeconds,
				)
			}
		}
	}

	elapsed := time.Since(startTime)
	fmt.Fprintf(os.Stderr, "Capture session ended after %s\n", elapsed.Round(time.Millisecond))
}
