package sshcommands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
)

// maxLocalNameVariants bounds the search for a free local file name.
const maxLocalNameVariants = 100

// ErrDownloadTooLarge is returned when a remote file exceeds
// DownloadOptions.MaxSize.
var ErrDownloadTooLarge = errors.New("remote file exceeds DownloadOptions.MaxSize")

// DownloadOptions controls DownloadWithOptions. The zero value is the secure
// default used by Download.
type DownloadOptions struct {
	// AllowLegacyDecryption decrypts files without the current format header
	// in the legacy format (written before 0.3.0, no integrity check). Only
	// enable it to migrate old backups: an attacker with write access to the
	// server can then modify such files undetected.
	AllowLegacyDecryption bool
	// MaxSize limits the size of each remote file in bytes; 0 = unlimited.
	MaxSize int64
}

// Download downloads files matching pattern from remoteDir into destDir with
// default DownloadOptions. See DownloadWithOptions.
func Download(opts *Opts, pattern, destDir, remoteDir, aesPassword string, log Logger) ([]string, error) {
	return DownloadWithOptions(opts, pattern, destDir, remoteDir, aesPassword, DownloadOptions{}, log)
}

// DownloadWithOptions downloads files matching pattern from remoteDir into
// destDir (required). Pattern may be a literal filename or contain wildcards
// (*, ?); no path components. aesPassword empty = no decryption (surrounding
// whitespace is ignored); with a password every file must be encrypted in the
// current format (ErrNotEncrypted otherwise, see AllowLegacyDecryption).
// Existing local files are never overwritten: the file is saved as
// "<name>.lokal" (or "<name>.lokal.N"). Returns the list of local paths written.
func DownloadWithOptions(opts *Opts, pattern, destDir, remoteDir, aesPassword string, dopts DownloadOptions, log Logger) ([]string, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if !ValidDownloadPattern(pattern) {
		return nil, errors.New("pattern must not contain path components or control characters")
	}
	dir, err := cleanRemoteDir(remoteDir)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(destDir) == "" {
		return nil, errors.New("local destination directory required")
	}
	if dopts.MaxSize < 0 {
		return nil, errors.New("DownloadOptions.MaxSize must not be negative")
	}
	destDir = filepath.FromSlash(destDir)
	literal := !strings.ContainsAny(pattern, "*?")
	if literal && !validLocalFileName(pattern, isWindows) {
		return nil, fmt.Errorf("file name %q cannot be created locally", pattern)
	}
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(sshClient)
	defer closeQuietly(sftpClient)
	params := decodeParams{password: normalizeAESPassword(aesPassword), allowLegacy: dopts.AllowLegacyDecryption}

	toDownload := []string{pattern}
	if !literal {
		toDownload, err = matchRemote(sftpClient, dir, pattern, log)
		if err != nil {
			return nil, err
		}
	}
	var saved []string
	for _, name := range toDownload {
		params.name = name
		localPath, err := downloadOne(sftpClient, joinRemote(dir, name), destDir, params, dopts.MaxSize, log)
		if err != nil {
			return saved, fmt.Errorf("%q: %w", name, err)
		}
		saved = append(saved, localPath)
	}
	return saved, nil
}

// matchRemote returns the names in dir matching pattern, skipping invalid,
// temporary and locally not creatable names.
func matchRemote(c *sftp.Client, dir, pattern string, log Logger) ([]string, error) {
	remoteList, err := listRemote(c, dir)
	if err != nil {
		return nil, fmt.Errorf("list remote: %w", err)
	}
	var names []string
	for _, e := range remoteList {
		if isTempUploadName(e.Name) {
			continue
		}
		ok, err := matchName(pattern, e.Name)
		if err != nil {
			return nil, fmt.Errorf("pattern: %w", err)
		}
		if !ok {
			continue
		}
		if !validLocalFileName(e.Name, isWindows) {
			if log != nil {
				log.Warn("skip download: invalid file name from server: %q", e.Name)
			}
			continue
		}
		names = append(names, e.Name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no file on remote matches: %q", pattern)
	}
	return names, nil
}

// matchName matches name against a wildcard pattern (* and ?); path.Match
// behaves identically on all operating systems.
func matchName(pattern, name string) (bool, error) {
	return path.Match(pattern, name)
}

// downloadOne fetches remotePath into a temporary file in destDir and, on
// success, moves it to a free local name. On error nothing is left behind.
func downloadOne(c *sftp.Client, remotePath, destDir string, p decodeParams, maxSize int64, log Logger) (localPath string, err error) {
	src, err := c.Open(remotePath)
	if err != nil {
		return "", fmt.Errorf("remote open: %w", err)
	}
	defer closeQuietly(src)
	info, err := src.Stat()
	if err != nil {
		return "", fmt.Errorf("remote stat: %w", err)
	}
	var r io.Reader = src
	if maxSize > 0 {
		if info.Size() > maxSize {
			return "", ErrDownloadTooLarge
		}
		r = &maxReader{r: src, remaining: maxSize}
	}

	tmp, err := os.CreateTemp(destDir, "."+p.name+".part-*")
	if err != nil {
		return "", fmt.Errorf("local create: %w", err)
	}
	tmpName := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmpName)
		}
	}()
	if err := decodeRemote(r, info.Size(), tmp, p, log); err != nil {
		closeQuietly(tmp)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("local write: %w", err)
	}
	final, err := reserveLocalPath(destDir, p.name)
	if err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, final); err != nil {
		_ = os.Remove(final)
		return "", fmt.Errorf("local rename: %w", err)
	}
	done = true
	return final, nil
}

// maxReader fails with ErrDownloadTooLarge once more than remaining bytes are
// read (the server may send more data than its stat result announced).
type maxReader struct {
	r         io.Reader
	remaining int64
}

func (m *maxReader) Read(p []byte) (int, error) {
	if m.remaining < 0 {
		return 0, ErrDownloadTooLarge
	}
	if int64(len(p)) > m.remaining+1 {
		p = p[:m.remaining+1]
	}
	n, err := m.r.Read(p)
	m.remaining -= int64(n)
	if m.remaining < 0 {
		return n, ErrDownloadTooLarge
	}
	return n, err
}

// reserveLocalPath atomically creates an empty placeholder for the first free
// name of name, name.lokal, name.lokal.2, … in dir and returns its path.
func reserveLocalPath(dir, name string) (string, error) {
	for i := 0; i < maxLocalNameVariants; i++ {
		candidate := name
		switch {
		case i == 1:
			candidate = name + ".lokal"
		case i > 1:
			candidate = name + ".lokal." + strconv.Itoa(i)
		}
		p := filepath.Join(dir, candidate)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- name validated by validLocalFileName
		if err == nil {
			closeQuietly(f)
			return p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("local create: %w", err)
		}
	}
	return "", fmt.Errorf("no free local file name for %q (tried %d variants)", name, maxLocalNameVariants)
}
