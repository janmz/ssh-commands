package sshcommands

import (
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
	defer sftpClient.Close()

	remotePath = normalizeRemotePath(remotePath)
	if err := sftpClient.MkdirAll(remotePath); err != nil {
		return fmt.Errorf("sftp mkdir %s: %w", remotePath, err)
	}
	if log != nil {
		log.Info("remote directory created: %s", remotePath)
	}
	return nil
}

// UploadFileIfNewer uploads localPath to remotePath when the local file is newer
// than the remote file or the remote file is missing. Remote parent directories
// are created as needed and the remote mtime is set to the local mtime.
func UploadFileIfNewer(client *ssh.Client, localPath, remotePath string, log Logger) error {
	localPath = filepath.FromSlash(localPath)
	remotePath = normalizeRemotePath(remotePath)
	if log != nil {
		log.Info("uploading %s to %s", localPath, remotePath)
	}

	localInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat local file: %w", err)
	}

	if remoteModTime, err := remoteFileModTime(client, remotePath); err == nil {
		if !localInfo.ModTime().After(remoteModTime) {
			if log != nil {
				log.Info("remote file already current: %s", filepath.Base(localPath))
			}
			return nil
		}
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp client: %w", err)
	}
	defer sftpClient.Close()

	localFile, err := os.Open(localPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer localFile.Close()

	remoteDir := normalizeRemotePath(filepath.Dir(remotePath))
	if err := sftpClient.MkdirAll(remoteDir); err != nil {
		return fmt.Errorf("sftp mkdir %s: %w", remoteDir, err)
	}

	remoteFile, err := sftpClient.OpenFile(remotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open remote file: %w", err)
	}
	defer remoteFile.Close()

	if _, err := io.Copy(remoteFile, localFile); err != nil {
		return fmt.Errorf("copy to remote: %w", err)
	}
	if err := sftpClient.Chtimes(remotePath, time.Now(), localInfo.ModTime()); err != nil && log != nil {
		log.Warn("could not preserve remote file timestamp: %v", err)
	}
	if log != nil {
		log.Info("uploaded %s", filepath.Base(localPath))
	}
	return nil
}

func remoteFileModTime(client *ssh.Client, remotePath string) (time.Time, error) {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return time.Time{}, err
	}
	defer sftpClient.Close()

	info, err := sftpClient.Stat(remotePath)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}
