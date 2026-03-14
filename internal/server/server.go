package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/tcpdump-grpc/internal/capture"
	"github.com/tcpdump-grpc/internal/filter"
	"github.com/tcpdump-grpc/internal/procnet"
	pb "github.com/tcpdump-grpc/proto/capture"
)

// Config holds gRPC server configuration.
type Config struct {
	ListenAddr     string
	TLSCertFile    string
	TLSKeyFile     string
	CaptureLimits  capture.Limits
	MaxConcurrent  int
	RateLimitPerIP int
}

// Server implements the CaptureService gRPC service.
type Server struct {
	pb.UnimplementedCaptureServiceServer

	engine *capture.Engine
	logger *slog.Logger
	config Config

	// Per-IP concurrency tracking
	ipCounts sync.Map
}

// New creates a new gRPC capture server.
func New(cfg Config, logger *slog.Logger) *Server {
	return &Server{
		engine: capture.NewEngine(cfg.CaptureLimits, logger, cfg.MaxConcurrent),
		logger: logger,
		config: cfg,
	}
}

// StartCapture implements the streaming capture RPC.
func (s *Server) StartCapture(req *pb.CaptureRequest, stream pb.CaptureService_StartCaptureServer) error {
	ctx := stream.Context()
	clientIP := s.clientIP(ctx)

	s.logger.Info("capture request",
		"client", clientIP,
		"filter", req.BpfFilter,
		"interface", req.Interface,
		"duration", req.DurationSeconds,
		"text_output", req.TextOutput,
	)

	// Per-IP rate limiting
	if err := s.acquireIPSlot(clientIP); err != nil {
		return status.Errorf(codes.ResourceExhausted, "%v", err)
	}
	defer s.releaseIPSlot(clientIP)

	// Validate and build capture config
	cfg, err := s.engine.ValidateAndBuild(
		ctx,
		req.Interface,
		req.BpfFilter,
		req.DurationSeconds,
		req.SnapLen,
		req.MaxPackets,
		req.TextOutput,
		req.Verbosity,
		req.NoResolve,
	)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Send initial status
	var seq atomic.Uint64
	sendErr := stream.Send(&pb.CaptureResponse{
		Payload: &pb.CaptureResponse_Status{
			Status: &pb.StatusMessage{
				Level:   pb.StatusMessage_INFO,
				Message: fmt.Sprintf("starting capture on %s (duration: %s)", cfg.Interface, cfg.Duration),
			},
		},
		Sequence: seq.Add(1),
	})
	if sendErr != nil {
		return sendErr
	}

	// Output handler streams data to the gRPC client.
	// When ctx is cancelled (client disconnect), the engine kills tcpdump.
	handler := func(data []byte, isText bool) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var resp *pb.CaptureResponse
		if isText {
			resp = &pb.CaptureResponse{
				Payload:  &pb.CaptureResponse_TextLine{TextLine: string(data)},
				Sequence: seq.Add(1),
			}
		} else {
			resp = &pb.CaptureResponse{
				Payload:  &pb.CaptureResponse_PcapData{PcapData: data},
				Sequence: seq.Add(1),
			}
		}
		return stream.Send(resp)
	}

	stats, runErr := s.engine.Run(ctx, cfg, handler)

	// Build final stats message
	var captureStats *pb.CaptureStats
	if stats != nil {
		captureStats = &pb.CaptureStats{
			PacketsCaptured: stats.PacketsCaptured,
			PacketsDropped:  stats.PacketsDropped,
			DurationSeconds: stats.Duration.Seconds(),
			BytesCaptured:   stats.BytesCaptured,
		}
	}

	finalMsg := "capture complete"
	level := pb.StatusMessage_INFO
	if runErr != nil && ctx.Err() == nil {
		finalMsg = fmt.Sprintf("capture ended with error: %v", runErr)
		level = pb.StatusMessage_ERROR
	}
	if ctx.Err() != nil {
		finalMsg = "capture terminated (client disconnect or timeout)"
		level = pb.StatusMessage_WARNING
	}

	// Best-effort final status (client may already be gone)
	_ = stream.Send(&pb.CaptureResponse{
		Payload: &pb.CaptureResponse_Status{
			Status: &pb.StatusMessage{
				Level:   level,
				Message: finalMsg,
				Stats:   captureStats,
			},
		},
		Sequence: seq.Add(1),
	})

	if stats != nil {
		s.logger.Info("capture finished",
			"client", clientIP,
			"packets", stats.PacketsCaptured,
			"bytes", stats.BytesCaptured,
			"duration", stats.Duration,
		)
	}

	if runErr != nil && ctx.Err() == nil {
		return status.Errorf(codes.Internal, "capture error: %v", runErr)
	}
	return nil
}

// ValidateFilter checks a BPF filter without starting a capture.
func (s *Server) ValidateFilter(ctx context.Context, req *pb.ValidateFilterRequest) (*pb.ValidateFilterResponse, error) {
	if _, err := filter.Sanitize(req.BpfFilter); err != nil {
		return &pb.ValidateFilterResponse{Valid: false, Error: err.Error()}, nil
	}
	if err := filter.Compile(ctx, req.BpfFilter); err != nil {
		return &pb.ValidateFilterResponse{Valid: false, Error: err.Error()}, nil
	}
	return &pb.ValidateFilterResponse{Valid: true}, nil
}

// ListInterfaces returns available network interfaces.
func (s *Server) ListInterfaces(_ context.Context, _ *pb.ListInterfacesRequest) (*pb.ListInterfacesResponse, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list interfaces: %v", err)
	}

	var result []*pb.NetworkInterface
	for _, iface := range ifaces {
		ni := &pb.NetworkInterface{
			Name: iface.Name,
			Up:   iface.Flags&net.FlagUp != 0,
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.Addresses = append(ni.Addresses, addr.String())
			}
		}
		result = append(result, ni)
	}

	return &pb.ListInterfacesResponse{Interfaces: result}, nil
}

// GetProcNetStats reads /proc/net pseudo-files and returns their contents.
func (s *Server) GetProcNetStats(_ context.Context, req *pb.ProcNetStatsRequest) (*pb.ProcNetStatsResponse, error) {
	entries := procnet.ReadFiles(req.Files)

	resp := &pb.ProcNetStatsResponse{
		Entries: make([]*pb.ProcNetFile, 0, len(entries)),
	}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &pb.ProcNetFile{
			Name:    e.Name,
			Content: e.Content,
			Error:   e.Error,
		})
	}

	s.logger.Info("proc net stats request",
		"files_requested", len(req.Files),
		"files_returned", len(resp.Entries),
	)

	return resp, nil
}

// Serve starts the gRPC server.
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.MaxRecvMsgSize(1 * 1024 * 1024),
		grpc.MaxSendMsgSize(16 * 1024 * 1024),
	}

	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
		s.logger.Info("TLS enabled")
	} else {
		s.logger.Warn("TLS disabled — do NOT run this in production without TLS")
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterCaptureServiceServer(grpcServer, s)
	reflection.Register(grpcServer)

	s.logger.Info("gRPC server listening", "addr", s.config.ListenAddr)
	return grpcServer.Serve(lis)
}

func (s *Server) clientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if addr, ok := p.Addr.(*net.TCPAddr); ok {
			return addr.IP.String()
		}
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			return host
		}
		return p.Addr.String()
	}
	return "unknown"
}

func (s *Server) acquireIPSlot(ip string) error {
	if s.config.RateLimitPerIP <= 0 {
		return nil
	}
	val, _ := s.ipCounts.LoadOrStore(ip, &atomic.Int64{})
	counter := val.(*atomic.Int64)
	current := counter.Add(1)
	if current > int64(s.config.RateLimitPerIP) {
		counter.Add(-1)
		return fmt.Errorf("too many concurrent captures from %s (limit: %d)", ip, s.config.RateLimitPerIP)
	}
	return nil
}

func (s *Server) releaseIPSlot(ip string) {
	if s.config.RateLimitPerIP <= 0 {
		return
	}
	if val, ok := s.ipCounts.Load(ip); ok {
		counter := val.(*atomic.Int64)
		if counter.Add(-1) <= 0 {
			s.ipCounts.Delete(ip)
		}
	}
}
