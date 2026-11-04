package sshcommands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Size limits for files read into memory.
const (
	maxPrivateKeySize = 1 << 20  // 1 MiB; real keys are a few KiB
	maxKnownHostsSize = 16 << 20 // 16 MiB
	maxRemoteEntries  = 200000   // directory entries accepted from the server
)

// tempUploadPrefix marks remote files that are still being uploaded. Sync
// removes leftovers with this prefix, Download ignores them for wildcards.
const tempUploadPrefix = ".sshcmd-upload-"

// isTempUploadName reports whether name is a temporary upload file.
func isTempUploadName(name string) bool {
	return strings.HasPrefix(name, tempUploadPrefix)
}

// checkFileSize returns an error when the file at p is larger than limit.
func checkFileSize(p string, limit int64) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.Size() > limit {
		return fmt.Errorf("file %s too large: %d bytes (limit %d)", p, fi.Size(), limit)
	}
	return nil
}

// readLimited reads the file at p, failing when it exceeds limit bytes.
func readLimited(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) // #nosec G304 -- path is supplied by the caller
	if err != nil {
		return nil, err
	}
	defer closeQuietly(f)
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file %s too large (limit %d bytes)", p, limit)
	}
	return data, nil
}

// closeChecked closes c and stores its error in *errp unless an earlier error
// is already set. Use it for handles that were written to.
func closeChecked(c io.Closer, errp *error) {
	if cerr := c.Close(); cerr != nil && *errp == nil {
		*errp = cerr
	}
}

// closeQuietly closes c and ignores the error (read-only handles, connections).
func closeQuietly(c io.Closer) {
	_ = c.Close()
}

// cleanRemoteDir validates and normalizes a remote directory (slash-separated).
// An empty directory is rejected so that operations never default to "/".
func cleanRemoteDir(dir string) (string, error) {
	d := strings.TrimSpace(filepath.ToSlash(dir))
	if d == "" {
		return "", errors.New("remote directory required")
	}
	return path.Clean(d), nil
}

// joinRemote joins a cleaned remote directory and a validated file name.
func joinRemote(dir, name string) string {
	return path.Join(dir, name)
}
