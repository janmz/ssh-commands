package sshcommands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
)

// ValidDownloadPattern returns false if pattern contains path components (no /, \, ..).
func ValidDownloadPattern(pattern string) bool {
	if pattern == "" || strings.Contains(pattern, "..") {
		return false
	}
	return filepath.Base(pattern) == pattern &&
		!strings.Contains(pattern, "/") && !strings.Contains(pattern, "\\")
}

// Download downloads files matching pattern from remoteDir into destDir.
// Pattern may be a literal filename or contain wildcards (*, ?). No path components.
// aesPassword empty = no decryption. Returns the list of local paths written.
func Download(opts *Opts, pattern, destDir, remoteDir, aesPassword string, log Logger) ([]string, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("remote not configured: set Host in Opts")
	}
	if !ValidDownloadPattern(pattern) {
		return nil, fmt.Errorf("pattern must not contain path components")
	}
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	defer sshClient.Close()
	defer sftpClient.Close()
	remoteDir = filepath.ToSlash(remoteDir)
	destDir = filepath.FromSlash(destDir)
	remoteList, err := listRemote(sftpClient, remoteDir)
	if err != nil {
		return nil, fmt.Errorf("list remote: %w", err)
	}
	var toDownload []string
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		for _, e := range remoteList {
			ok, err := filepath.Match(pattern, e.Name)
			if err != nil {
				return nil, fmt.Errorf("pattern: %w", err)
			}
			if ok {
				toDownload = append(toDownload, e.Name)
			}
		}
		if len(toDownload) == 0 {
			return nil, fmt.Errorf("no file on remote matches: %s", pattern)
		}
	} else {
		toDownload = []string{pattern}
	}
	var saved []string
	for _, name := range toDownload {
		localPath := filepath.Join(destDir, name)
		if _, err := os.Stat(localPath); err == nil {
			localPath = filepath.Join(destDir, name+".lokal")
		}
		if err := getOneFile(sftpClient, remoteDir, name, localPath, strings.TrimSpace(aesPassword), log); err != nil {
			return saved, fmt.Errorf("%s: %w", name, err)
		}
		saved = append(saved, localPath)
	}
	return saved, nil
}

func getOneFile(client *sftp.Client, remoteDir, remoteName, localPath, aesPassword string, log Logger) error {
	remotePath := remoteDir + "/" + remoteName
	src, err := client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("remote open: %w", err)
	}
	defer src.Close()
	header := make([]byte, saltLen+nonceLen)
	n, err := io.ReadFull(src, header)
	if err != nil && err != io.EOF {
		return fmt.Errorf("remote read: %w", err)
	}
	decrypt := aesPassword != "" && n == saltLen+nonceLen && (header[0] != 'P' || header[1] != 'K')
	if decrypt {
		if log != nil {
			log.Info("remote file decrypted: %s", remoteName)
		}
		dst, err := os.Create(localPath)
		if err != nil {
			return fmt.Errorf("local create: %w", err)
		}
		defer dst.Close()
		if err := streamDecryptDownload(src, dst, header[0:saltLen], header[saltLen:saltLen+nonceLen], aesPassword); err != nil {
			return fmt.Errorf("decrypt/write: %w", err)
		}
		return nil
	}
	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("local create: %w", err)
	}
	defer dst.Close()
	if n > 0 {
		if _, err := dst.Write(header[:n]); err != nil {
			return err
		}
	}
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}
