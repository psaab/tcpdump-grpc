package filter

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// MaxFilterLength is the hard limit on BPF filter string length.
const MaxFilterLength = 2048

// dangerousPatterns catches obvious attempts to inject shell metacharacters.
// This is defence-in-depth; the real protection is never using a shell.
var dangerousPatterns = regexp.MustCompile(`[;&|` + "`" + `$(){}\[\]\\!><]`)

// allowedFilterChars defines the character set that can appear in a BPF filter.
// BPF filter syntax uses: alphanumerics, spaces, dots, colons, slashes,
// hyphens, commas, single-quotes (for MAC addrs), and comparison operators.
func isAllowedChar(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case ' ', '.', ':', '/', '-', ',', '\'', '"',
		'=', '!', '<', '>', '(', ')', '[', ']',
		'&', '|', '+', '*', '?', '^', '@', '#':
		// Note: we're more restrictive below with dangerousPatterns
		// but this defines the absolute outer bound.
		return true
	}
	return false
}

// Sanitize performs static validation of a BPF filter string.
// Returns the cleaned filter or an error explaining what's wrong.
func Sanitize(filter string) (string, error) {
	// Trim whitespace
	filter = strings.TrimSpace(filter)

	// Empty filter is valid (capture everything)
	if filter == "" {
		return "", nil
	}

	// Length check
	if len(filter) > MaxFilterLength {
		return "", fmt.Errorf("filter exceeds maximum length of %d characters", MaxFilterLength)
	}

	// Reject null bytes
	if strings.ContainsRune(filter, 0) {
		return "", fmt.Errorf("filter contains null bytes")
	}

	// Reject newlines (could confuse argument parsing)
	if strings.ContainsAny(filter, "\n\r") {
		return "", fmt.Errorf("filter contains newline characters")
	}

	// Reject shell metacharacters as defence-in-depth.
	// Even though we use exec.Command (no shell), reject these to make
	// the intent clear and prevent mistakes if code is refactored later.
	if dangerousPatterns.MatchString(filter) {
		return "", fmt.Errorf("filter contains disallowed characters; " +
			"BPF filters should not contain shell metacharacters like ; & | ` $ etc")
	}

	// Normalize internal whitespace
	fields := strings.Fields(filter)
	filter = strings.Join(fields, " ")

	return filter, nil
}

// Compile uses tcpdump itself to validate the BPF filter by running
// `tcpdump -d <filter>` which compiles the filter to BPF bytecode
// and dumps it. This catches syntax errors without capturing packets.
//
// IMPORTANT: This uses exec.Command with the filter as a single argument,
// NOT passed through a shell. tcpdump parses the filter expression itself.
func Compile(ctx context.Context, filter string) error {
	if filter == "" {
		return nil
	}

	// Apply static checks first
	sanitized, err := Sanitize(filter)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// tcpdump -d compiles the filter and dumps BPF bytecode.
	// The filter is passed as a SINGLE argument—tcpdump's own parser
	// handles the expression. No shell is involved.
	//
	// #nosec G204 — filter is validated by Sanitize() above
	cmd := exec.CommandContext(ctx, "tcpdump", "-d", sanitized)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("invalid BPF filter: %s", strings.TrimSpace(string(output)))
	}

	return nil
}
