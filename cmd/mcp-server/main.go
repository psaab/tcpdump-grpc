package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/tcpdump-grpc/proto/capture"
)

func main() {
	var (
		serverAddr  = flag.String("server", "localhost:50051", "tcpdump-grpc server address")
		useTLS      = flag.Bool("tls", false, "Use TLS to connect to gRPC server")
		tlsInsecure = flag.Bool("insecure", false, "Skip TLS certificate verification")
		maxLines    = flag.Int("max-lines", 500, "Maximum text lines to return from a capture")
	)
	flag.Parse()

	// Connect to the gRPC backend
	var dialOpts []grpc.DialOption
	if *useTLS || *tlsInsecure {
		tlsCfg := &tls.Config{InsecureSkipVerify: *tlsInsecure}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(*serverAddr, dialOpts...)
	if err != nil {
		log.Fatalf("connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewCaptureServiceClient(conn)

	// Create the MCP server
	s := server.NewMCPServer(
		"tcpdump-grpc",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	// ── Tool: capture ────────────────────────────────────────
	s.AddTool(
		mcp.NewTool("capture",
			mcp.WithDescription(
				"Capture network packets using tcpdump on the remote server. "+
					"Returns decoded text lines. For long captures, use a short duration "+
					"and specific BPF filter to keep output manageable.",
			),
			mcp.WithString("bpf_filter",
				mcp.Description(
					"BPF filter expression (tcpdump syntax). Examples: "+
						"\"tcp port 80\", \"host 10.0.0.1\", \"udp port 53\", "+
						"\"tcp port 443 and host 10.0.0.1\". Empty means capture all.",
				),
			),
			mcp.WithString("interface",
				mcp.Description("Network interface to capture on (e.g. \"eth0\"). Empty for server default. Use list_interfaces to discover available interfaces."),
			),
			mcp.WithNumber("duration_seconds",
				mcp.Description("Capture duration in seconds (default: 10, max: 300). Keep short to avoid large outputs."),
			),
			mcp.WithNumber("max_packets",
				mcp.Description("Stop after this many packets (0 = unlimited, duration-bound)."),
			),
			mcp.WithNumber("verbosity",
				mcp.Description("Decode verbosity: 0 = default, 1 = -v, 2 = -vv, 3 = -vvv."),
			),
			mcp.WithBoolean("no_resolve",
				mcp.Description("Don't resolve hostnames (recommended for performance). Default: true."),
			),
		),
		makeCaptureHandler(client, *maxLines),
	)

	// ── Tool: validate_filter ────────────────────────────────
	s.AddTool(
		mcp.NewTool("validate_filter",
			mcp.WithDescription("Validate a BPF filter expression without starting a capture. Checks syntax and compiles the filter."),
			mcp.WithString("bpf_filter",
				mcp.Required(),
				mcp.Description("The BPF filter expression to validate."),
			),
		),
		makeValidateHandler(client),
	)

	// ── Tool: list_interfaces ────────────────────────────────
	s.AddTool(
		mcp.NewTool("list_interfaces",
			mcp.WithDescription("List network interfaces available for packet capture on the remote server."),
		),
		makeListInterfacesHandler(client),
	)

	// ── Tool: proc_net_stats ─────────────────────────────────
	s.AddTool(
		mcp.NewTool("proc_net_stats",
			mcp.WithDescription(
				"Read /proc/net pseudo-files from the remote server for network diagnostics. "+
					"Returns contents of files like dev, tcp, udp, snmp, netstat, sockstat, etc.",
			),
			mcp.WithArray("files",
				mcp.Description(
					"Specific /proc/net file names to read (e.g. [\"dev\", \"tcp\", \"snmp\"]). "+
						"Empty array returns all known files (27 files). "+
						"Common choices: dev (interface counters), tcp/tcp6 (connections), "+
						"snmp/snmp6 (protocol stats), netstat (extended TCP stats), "+
						"sockstat (socket summary), softnet_stat (per-CPU stats), route, arp.",
				),
				mcp.WithStringItems(),
			),
		),
		makeProcNetHandler(client),
	)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

func makeCaptureHandler(client pb.CaptureServiceClient, maxLines int) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		bpfFilter := req.GetString("bpf_filter", "")
		iface := req.GetString("interface", "")
		duration := uint32(req.GetFloat("duration_seconds", 10))
		maxPackets := uint64(req.GetFloat("max_packets", 0))
		verbosity := uint32(req.GetFloat("verbosity", 1))
		noResolve := req.GetBool("no_resolve", true)

		// Clamp duration for MCP use to keep responses reasonable
		if duration > 60 {
			duration = 60
		}
		if duration == 0 {
			duration = 10
		}

		captureCtx, cancel := context.WithTimeout(ctx, time.Duration(duration+10)*time.Second)
		defer cancel()

		stream, err := client.StartCapture(captureCtx, &pb.CaptureRequest{
			BpfFilter:       bpfFilter,
			Interface:       iface,
			DurationSeconds: duration,
			MaxPackets:      maxPackets,
			TextOutput:      true,
			Verbosity:       verbosity,
			NoResolve:       noResolve,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("start capture: %v", err)), nil
		}

		var lines []string
		var stats *pb.CaptureStats
		truncated := false

		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				if captureCtx.Err() != nil {
					break
				}
				return mcp.NewToolResultError(fmt.Sprintf("recv: %v", err)), nil
			}

			switch p := resp.Payload.(type) {
			case *pb.CaptureResponse_TextLine:
				if len(lines) < maxLines {
					lines = append(lines, p.TextLine)
				} else if !truncated {
					truncated = true
				}
			case *pb.CaptureResponse_Status:
				if p.Status.Stats != nil {
					stats = p.Status.Stats
				}
			}
		}

		var b strings.Builder

		if len(lines) == 0 {
			b.WriteString("No packets captured matching the filter.\n")
		} else {
			for _, line := range lines {
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}

		if truncated {
			fmt.Fprintf(&b, "\n--- output truncated at %d lines ---\n", maxLines)
		}

		if stats != nil {
			fmt.Fprintf(&b, "\n--- Capture Stats ---\n")
			fmt.Fprintf(&b, "Packets captured: %d\n", stats.PacketsCaptured)
			fmt.Fprintf(&b, "Packets dropped:  %d\n", stats.PacketsDropped)
			fmt.Fprintf(&b, "Bytes captured:   %d\n", stats.BytesCaptured)
			fmt.Fprintf(&b, "Duration:         %.1fs\n", stats.DurationSeconds)
		}

		return mcp.NewToolResultText(b.String()), nil
	}
}

func makeValidateHandler(client pb.CaptureServiceClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		bpfFilter, err := req.RequireString("bpf_filter")
		if err != nil {
			return mcp.NewToolResultError("bpf_filter is required"), nil
		}

		resp, err := client.ValidateFilter(ctx, &pb.ValidateFilterRequest{
			BpfFilter: bpfFilter,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("validate: %v", err)), nil
		}

		if resp.Valid {
			return mcp.NewToolResultText(fmt.Sprintf("Filter %q is valid.", bpfFilter)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Filter %q is invalid: %s", bpfFilter, resp.Error)), nil
	}
}

func makeListInterfacesHandler(client pb.CaptureServiceClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		resp, err := client.ListInterfaces(ctx, &pb.ListInterfacesRequest{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list interfaces: %v", err)), nil
		}

		var b strings.Builder
		for _, iface := range resp.Interfaces {
			state := "DOWN"
			if iface.Up {
				state = "UP"
			}
			fmt.Fprintf(&b, "%-20s %-6s %s\n", iface.Name, state, strings.Join(iface.Addresses, ", "))
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

func makeProcNetHandler(client pb.CaptureServiceClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract files array from arguments
		var files []string
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if rawFiles, ok := args["files"]; ok {
				if arr, ok := rawFiles.([]interface{}); ok {
					for _, v := range arr {
						if s, ok := v.(string); ok {
							files = append(files, s)
						}
					}
				}
			}
		}

		resp, err := client.GetProcNetStats(ctx, &pb.ProcNetStatsRequest{
			Files: files,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("proc net stats: %v", err)), nil
		}

		var b strings.Builder
		for _, entry := range resp.Entries {
			fmt.Fprintf(&b, "=== /proc/net/%s ===\n", entry.Name)
			if entry.Error != "" {
				fmt.Fprintf(&b, "ERROR: %s\n", entry.Error)
			} else {
				b.WriteString(entry.Content)
				if !strings.HasSuffix(entry.Content, "\n") {
					b.WriteByte('\n')
				}
			}
			b.WriteByte('\n')
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}
