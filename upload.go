package sshcommands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func normalizeRemotePath(remotePath string) string {
	remotePath = filepath.ToSlash(remotePath)
	return path.Clean("/" + strings.TrimPrefix(remotePath, "/"))
}

// MkdirAllRemote creates remotePath and any missing parent directories via SFTP.
func MkdirAllRemote(client *ssh.Client, remotePath string, log Logger) error {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp client: %w", err)
	}
	defer closeQuietly(sftpClient)

	remotePath = normalizeRemotePath(remotePath)
	if err := sftpClient.MkdirAll(remotePath); err != nil {
		return fmt.Errorf("sftp mkdir %s: %w", remotePath, err)
	}
	if log != nil {
		log.Info("remote directory created: %q", remotePath)
	}
	return nil
}

// UploadFileIfNewer uploads localPath to remotePath when the remote file is
// missing, has a different size, or the local file is newer (compared in whole
// seconds). Remote parent directories are created as needed, the upload goes
// to a temporary name first and the remote mtime is set to the local mtime.
func UploadFileIfNewer(client *ssh.Client, localPath, remotePath string, log Logger) error {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp client: %w", err)
	}
	defer closeQuietly(sftpClient)

	localPath = filepath.FromSlash(localPath)
	remotePath = normalizeRemotePath(remotePath)
	localInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat local file: %w", err)
	}
	if ri, err := sftpClient.Stat(remotePath); err == nil {
		loc := LocalFile{Name: localInfo.Name(), ModTime: localInfo.ModTime(), Size: localInfo.Size()}
		rem := RemoteEntry{Name: ri.Name(), ModTime: ri.ModTime(), Size: ri.Size()}
		if !needsUpload(loc, rem, true, false) {
			if log != nil {
				log.Info("remote file already current: %q", filepath.Base(localPath))
			}
			return nil
		}
	}
	if log != nil {
		log.Info("uploading %q to %q", filepath.Base(localPath), remotePath)
	}
	remoteDir := path.Dir(remotePath)
	if err := sftpClient.MkdirAll(remoteDir); err != nil {
		return fmt.Errorf("sftp mkdir %s: %w", remoteDir, err)
	}
	if err := putFile(sftpClient, localPath, remotePath, localInfo.ModTime(), "", log); err != nil {
		return err
	}
	if log != nil {
		log.Info("uploaded %q", filepath.Base(localPath))
	}
	return nil
}

// putFile uploads localPath to remotePath via a temporary name in the same
// directory, so an aborted transfer never leaves a partial file under the
// final name. aesPassword non-empty encrypts the data. modTime (if not zero)
// is set as remote mtime.
func putFile(c *sftp.Client, localPath, remotePath string, modTime time.Time, aesPassword string, log Logger) error {
	src, err := os.Open(filepath.FromSlash(localPath)) // #nosec G304
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer closeQuietly(src)

	name := path.Base(remotePath)
	tmp := path.Join(path.Dir(remotePath), tempUploadPrefix+name)
	if err := writeRemote(c, tmp, src, aesPassword, name); err != nil {
		_ = c.Remove(tmp)
		return fmt.Errorf("write remote: %w", err)
	}
	if !modTime.IsZero() {
		if err := c.Chtimes(tmp, time.Now(), modTime); err != nil && log != nil {
			log.Warn("could not preserve remote file timestamp: %v", err)
		}
	}
	if err := renameReplace(c, tmp, remotePath); err != nil {
		_ = c.Remove(tmp)
		return fmt.Errorf("rename to %s: %w", remotePath, err)
	}
	return nil
}

// writeRemote creates p on the server and copies (or encrypts, bound to
// name) src into it. The close error is reported, since buffered writes can
// fail there.
func writeRemote(c *sftp.Client, p string, src io.Reader, aesPassword, name string) (err error) {
	dst, err := c.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer closeChecked(dst, &err)
	if aesPassword == "" {
		_, err = io.Copy(dst, src)
		return err
	}
	return streamEncryptUpload(src, dst, aesPassword, name)
}

// renameReplace renames from to to, replacing an existing target. It prefers
// the atomic posix-rename extension and falls back to remove + rename.
func renameReplace(c *sftp.Client, from, to string) error {
	if err := c.PosixRename(from, to); err == nil {
		return nil
	}
	if err := c.Remove(to); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return c.Rename(from, to)
}
