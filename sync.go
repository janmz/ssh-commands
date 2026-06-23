package sshcommands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
)

// Sync uploads local files that are missing or newer on the remote, and deletes
// remote files that are not in localFiles. remoteDir is created if needed.
// aesPassword empty = no encryption.
func Sync(opts *Opts, localFiles []LocalFile, remoteDir, aesPassword string, log Logger) error {
	if len(localFiles) == 0 && opts.Host == "" {
		return nil
	}
	if opts.Host == "" {
		return nil
	}
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	defer sshClient.Close()
	defer sftpClient.Close()
	remoteDir = filepath.ToSlash(remoteDir)
	if err := sftpClient.MkdirAll(remoteDir); err != nil && !os.IsExist(err) {
		if log != nil {
			log.Warn("sftp mkdir %s: %v", remoteDir, err)
		}
	}
	remoteList, err := listRemote(sftpClient, remoteDir)
	if err != nil {
		return fmt.Errorf("list remote: %w", err)
	}
	encrypt := strings.TrimSpace(aesPassword) != ""
	if log != nil {
		if encrypt {
			log.Info("remote: AES encryption on")
		} else {
			log.Info("remote: no AES encryption")
		}
	}
	remoteMap := make(map[string]RemoteEntry)
	for _, e := range remoteList {
		remoteMap[e.Name] = e
	}
	for _, loc := range localFiles {
		rem, exists := remoteMap[loc.Name]
		needUpload := !exists || loc.ModTime.After(rem.ModTime)
		if encrypt && exists {
			expectedSize := loc.Size + EncryptionOverhead
			if rem.Size != expectedSize {
				needUpload = true
			}
		}
		if needUpload {
			remotePath := remoteDir + "/" + loc.Name
			if err := uploadFile(sftpClient, loc.Path, remotePath, encrypt, aesPassword); err != nil {
				return fmt.Errorf("upload %s: %w", loc.Name, err)
			}
			if log != nil {
				log.Info("uploaded %s to remote", loc.Name)
			}
		}
	}
	for _, rem := range remoteList {
		if !localHasName(localFiles, rem.Name) {
			remotePath := remoteDir + "/" + rem.Name
			if err := sftpClient.Remove(remotePath); err != nil {
				if log != nil {
					log.Warn("remote remove %s: %v", rem.Name, err)
				}
				continue
			}
			if log != nil {
				log.Info("removed from remote (not in local): %s", rem.Name)
			}
		}
	}
	return nil
}

func localHasName(list []LocalFile, name string) bool {
	for _, e := range list {
		if e.Name == name {
			return true
		}
	}
	return false
}

func uploadFile(client *sftp.Client, localPath, remotePath string, encrypt bool, aesPassword string) error {
	src, err := os.Open(filepath.FromSlash(localPath))
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := client.Create(remotePath)
	if err != nil {
		return err
	}
	defer dst.Close()
	if !encrypt {
		_, err = io.Copy(dst, src)
		return err
	}
	return streamEncryptUpload(src, dst, aesPassword)
}
