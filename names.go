package sshcommands

import (
	"runtime"
	"strings"
)

// windowsReservedNames are device names that Windows refuses as file names,
// with or without extension (e.g. "NUL", "con.txt").
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// ValidDownloadPattern returns false if pattern contains path components (no /, \, ..).
func ValidDownloadPattern(pattern string) bool {
	return ValidRemoteFileName(pattern)
}

// ValidRemoteFileName returns false if name is empty or ".", contains path
// components, "..", or control characters (0x00-0x1f, 0x7f).
// Use for any remote or local filename that is joined to a base directory.
func ValidRemoteFileName(name string) bool {
	if name == "" || name == "." || strings.Contains(name, "..") ||
		strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validLocalFileName reports whether name can safely be created in a local
// directory. On Windows it additionally rejects reserved device names,
// characters Windows does not allow and a trailing dot or space.
func validLocalFileName(name string, windows bool) bool {
	if !ValidRemoteFileName(name) {
		return false
	}
	if !windows {
		return true
	}
	if strings.ContainsAny(name, `<>:"|?*`) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	base, _, _ := strings.Cut(name, ".")
	return !windowsReservedNames[strings.ToUpper(strings.TrimSpace(base))]
}

// isWindows is true when local files are created on Windows.
var isWindows = runtime.GOOS == "windows"
