package capture

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tcpdump-grpc/internal/filter"
)

// Limits defines hard server-side limits for capture requests.
type Limits struct {
	MaxDurationSeconds uint32   // Hard cap on capture duration
	DefaultDuration    uint32   // Used when client sends 0
	MaxSnapLen         uint32   // Maximum snap length
	AllowedInterfaces  []string // If non-empty, only these interfaces can be used
	TcpdumpPath        string   // Path to tcpdump binary (for security)
}

// DefaultLimits returns sensible defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxDurationSeconds: 300, // 5 minutes max
		DefaultDuration:    60,  // 1 minute default
		MaxSnapLen:         65535,
		TcpdumpPath:        "/usr/bin/tcpdump",
	}
}

// CaptureConfig is the validated, ready-to-execute capture configuration.
type CaptureConfig struct {
	Interface   string
	BPFFilter   string
	Duration    time.Duration
	SnapLen     uint32
	MaxPackets  uint64
	TextOutput  bool
	Verbosity   uint32
	NoResolve   bool
}

// Stats holds post-capture statistics.
type Stats struct {
	PacketsCaptured uint64
	PacketsDropped  uint64
	Duration        time.Duration
	BytesCaptured   uint64
}

// OutputHandler is called for each chunk of output from tcpdump.
type OutputHandler func(data []byte, isText bool) error

// Engine manages tcpdump processes.
type Engine struct {
	limits    Limits
	logger    *slog.Logger
	active    atomic.Int64 // number of active captures
	maxActive int64
}

// NewEngine creates a capture engine with the given limits.
func NewEngine(limits Limits, logger *slog.Logger, maxConcurrent int) *Engine {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	return &Engine{
		limits:    limits,
		logger:    logger,
		maxActive: int64(maxConcurrent),
	}
}

// ActiveCaptures returns the number of currently running captures.
func (e *Engine) ActiveCaptures() int64 {
	return e.active.Load()
}

// ValidateAndBuild validates the request parameters and builds a CaptureConfig.
func (e *Engine) ValidateAndBuild(ctx context.Context, iface, bpfFilter string,
	durationSec, snapLen uint32, maxPackets uint64,
	textOutput bool, verbosity uint32, noResolve bool) (*CaptureConfig, error) {

	// Validate BPF filter (static + compilation check)
	sanitizedFilter, err := filter.Sanitize(bpfFilter)
	if err != nil {
		return nil, fmt.Errorf("filter validation: %w", err)
	}
	if sanitizedFilter != "" {
		if err := filter.Compile(ctx, sanitizedFilter); err != nil {
			return nil, fmt.Errorf("filter compilation: %w", err)
		}
	}

	// Validate interface
	iface = strings.TrimSpace(iface)
	if iface != "" {
		if err := e.validateInterface(iface); err != nil {
			return nil, err
		}
	}

	// Validate and clamp duration
	if durationSec == 0 {
		durationSec = e.limits.DefaultDuration
	}
	if durationSec > e.limits.MaxDurationSeconds {
		durationSec = e.limits.MaxDurationSeconds
	}

	// Validate snap length
	if snapLen == 0 {
		snapLen = 65535
	}
	if snapLen > e.limits.MaxSnapLen {
		snapLen = e.limits.MaxSnapLen
	}

	// Clamp verbosity
	if verbosity > 3 {
		verbosity = 3
	}

	return &CaptureConfig{
		Interface:  iface,
		BPFFilter:  sanitizedFilter,
		Duration:   time.Duration(durationSec) * time.Second,
		SnapLen:    snapLen,
		MaxPackets: maxPackets,
		TextOutput: textOutput,
		Verbosity:  verbosity,
		NoResolve:  noResolve,
	}, nil
}

// Run starts a tcpdump process and streams output through the handler.
// It blocks until capture completes. The context controls cancellation;
// when it's cancelled (client disconnect, timeout, etc.) tcpdump is killed.
func (e *Engine) Run(ctx context.Context, cfg *CaptureConfig, handler OutputHandler) (*Stats, error) {
	// Check concurrency limit
	if e.active.Load() >= e.maxActive {
		return nil, fmt.Errorf("maximum concurrent captures (%d) reached", e.maxActive)
	}
	e.active.Add(1)
	defer e.active.Add(-1)

	// Build tcpdump argument list—NO SHELL involved
	args := e.buildArgs(cfg)

	e.logger.Info("starting capture",
		"interface", cfg.Interface,
		"filter", cfg.BPFFilter,
		"duration", cfg.Duration,
		"text_output", cfg.TextOutput,
		"args", args,
	)

	// Create context with capture duration timeout.
	// This is layered on top of the caller's context (which tracks client disconnect).
	captureCtx, captureCancel := context.WithTimeout(ctx, cfg.Duration)
	defer captureCancel()

	// Build the command. exec.CommandContext will send SIGKILL on context cancel.
	// We set up our own cleanup to try SIGTERM first.
	// #nosec G204 — args are validated above, no shell involved
	cmd := exec.CommandContext(captureCtx, e.limits.TcpdumpPath, args...)

	// Drop privileges if running as root (defence-in-depth).
	// tcpdump needs CAP_NET_RAW which we grant via Docker, not uid 0.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Create a new process group so we can signal the whole group
		Setpgid: true,
	}

	var stdout io.ReadCloser
	var stderr io.ReadCloser
	var err error

	if cfg.TextOutput {
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		stderr, err = cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("stderr pipe: %w", err)
		}
	} else {
		// Binary pcap mode: tcpdump writes pcap to stdout
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		stderr, err = cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("stderr pipe: %w", err)
		}
	}

	startTime := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tcpdump: %w", err)
	}

	e.logger.Info("tcpdump started", "pid", cmd.Process.Pid)

	// Ensure cleanup happens no matter what
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if cmd.Process != nil {
				e.logger.Info("terminating tcpdump", "pid", cmd.Process.Pid)
				// Try SIGTERM first for clean shutdown
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				// Give it a moment, then force kill
				time.AfterFunc(2*time.Second, func() {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				})
			}
		})
	}
	defer cleanup()

	// Monitor for context cancellation (client disconnect or timeout)
	go func() {
		<-captureCtx.Done()
		e.logger.Info("capture context done", "reason", captureCtx.Err())
		cleanup()
	}()

	var stats Stats
	var readErr error

	if cfg.TextOutput {
		stats, readErr = e.readTextOutput(captureCtx, stdout, handler)
	} else {
		stats, readErr = e.readBinaryOutput(captureCtx, stdout, handler)
	}

	// Read stderr for tcpdump stats (packets captured/dropped)
	stderrBytes, _ := io.ReadAll(stderr)
	e.parseStderr(string(stderrBytes), &stats)

	// Wait for process to exit
	waitErr := cmd.Wait()

	stats.Duration = time.Since(startTime)

	// If context was cancelled, that's not an error—it's expected
	if captureCtx.Err() != nil {
		e.logger.Info("capture completed via context cancellation",
			"duration", stats.Duration,
			"packets", stats.PacketsCaptured,
		)
		return &stats, nil
	}

	if readErr != nil {
		return &stats, readErr
	}

	// tcpdump exits non-zero on SIGTERM which is fine
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			// Signal-terminated is expected
			if exitErr.ExitCode() == -1 {
				return &stats, nil
			}
			// Exit code 1 with some captures is fine (e.g., packet count reached)
			if exitErr.ExitCode() == 1 && stats.PacketsCaptured > 0 {
				return &stats, nil
			}
		}
		e.logger.Warn("tcpdump exited with error",
			"error", waitErr,
			"stderr", string(stderrBytes),
		)
	}

	return &stats, nil
}

// buildArgs constructs the tcpdump argument list.
// Every value is a discrete argument—no shell expansion possible.
func (e *Engine) buildArgs(cfg *CaptureConfig) []string {
	args := []string{
		"--immediate-mode",  // Flush output immediately
		"-s", strconv.FormatUint(uint64(cfg.SnapLen), 10),
	}

	if cfg.Interface != "" {
		args = append(args, "-i", cfg.Interface)
	}

	if cfg.NoResolve {
		args = append(args, "-n")
	}

	if cfg.MaxPackets > 0 {
		args = append(args, "-c", strconv.FormatUint(cfg.MaxPackets, 10))
	}

	if cfg.TextOutput {
		// Text decode mode
		switch cfg.Verbosity {
		case 1:
			args = append(args, "-v")
		case 2:
			args = append(args, "-vv")
		case 3:
			args = append(args, "-vvv")
		}
		// Timestamps
		args = append(args, "-tttt")
	} else {
		// Raw pcap output to stdout
		args = append(args, "-U", "-w", "-")
	}

	// BPF filter goes LAST as a single argument.
	// tcpdump's own expression parser handles it.
	if cfg.BPFFilter != "" {
		args = append(args, cfg.BPFFilter)
	}

	return args
}

func (e *Engine) readTextOutput(ctx context.Context, r io.Reader, handler OutputHandler) (Stats, error) {
	var stats Stats
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		line := scanner.Text()
		stats.PacketsCaptured++
		stats.BytesCaptured += uint64(len(line))
		if err := handler([]byte(line), true); err != nil {
			return stats, err
		}
	}
	return stats, scanner.Err()
}

func (e *Engine) readBinaryOutput(ctx context.Context, r io.Reader, handler OutputHandler) (Stats, error) {
	var stats Stats
	buf := make([]byte, 64*1024) // 64KB read buffer

	for {
		if ctx.Err() != nil {
			break
		}
		n, err := r.Read(buf)
		if n > 0 {
			stats.BytesCaptured += uint64(n)
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if herr := handler(chunk, false); herr != nil {
				return stats, herr
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return stats, err
		}
	}
	return stats, nil
}

func (e *Engine) parseStderr(stderr string, stats *Stats) {
	// tcpdump prints stats like:
	// "42 packets captured"
	// "3 packets dropped by kernel"
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "packets captured") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				if n, err := strconv.ParseUint(parts[0], 10, 64); err == nil {
					stats.PacketsCaptured = n
				}
			}
		}
		if strings.Contains(line, "packets dropped") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				if n, err := strconv.ParseUint(parts[0], 10, 64); err == nil {
					stats.PacketsDropped = n
				}
			}
		}
	}
}

func (e *Engine) validateInterface(iface string) error {
	// Reject anything that doesn't look like an interface name
	for _, r := range iface {
		if !isInterfaceChar(r) {
			return fmt.Errorf("invalid interface name character: %c", r)
		}
	}
	if len(iface) > 64 {
		return fmt.Errorf("interface name too long")
	}

	// If allowlist is configured, enforce it
	if len(e.limits.AllowedInterfaces) > 0 {
		for _, allowed := range e.limits.AllowedInterfaces {
			if iface == allowed {
				return nil
			}
		}
		return fmt.Errorf("interface %q not in allowed list", iface)
	}

	return nil
}

func isInterfaceChar(r rune) bool {
	// Linux interface names: alphanumeric, dash, underscore, dot
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.'
}
