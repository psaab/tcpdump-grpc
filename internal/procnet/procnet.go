package procnet

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Known /proc/net files that contain useful network statistics.
// Ordered roughly by diagnostic importance.
var KnownFiles = []string{
	"dev",
	"tcp",
	"tcp6",
	"udp",
	"udp6",
	"snmp",
	"snmp6",
	"netstat",
	"sockstat",
	"sockstat6",
	"softnet_stat",
	"route",
	"arp",
	"icmp",
	"icmp6",
	"igmp",
	"igmp6",
	"raw",
	"raw6",
	"unix",
	"protocols",
	"netlink",
	"packet",
	"ptype",
	"psched",
	"xfrm_stat",
	"fib_triestat",
}

const procNetDir = "/proc/net"

// Entry represents one /proc/net file read result.
type Entry struct {
	Name    string
	Content string
	Error   string
}

// ReadFiles reads the requested /proc/net files.
// If names is empty, all KnownFiles are read.
func ReadFiles(names []string) []Entry {
	if len(names) == 0 {
		names = KnownFiles
	}

	// Deduplicate and validate
	seen := make(map[string]bool, len(names))
	var filtered []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		filtered = append(filtered, name)
	}
	sort.Strings(filtered)

	entries := make([]Entry, 0, len(filtered))
	for _, name := range filtered {
		e := Entry{Name: name}

		// Prevent directory traversal
		clean := filepath.Clean(name)
		if strings.Contains(clean, "/") || strings.Contains(clean, "..") {
			e.Error = "invalid file name"
			entries = append(entries, e)
			continue
		}

		path := filepath.Join(procNetDir, clean)
		data, err := os.ReadFile(path)
		if err != nil {
			e.Error = fmt.Sprintf("read error: %v", err)
		} else {
			e.Content = string(data)
		}
		entries = append(entries, e)
	}
	return entries
}
