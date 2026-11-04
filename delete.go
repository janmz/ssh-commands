package sshcommands

import (
	"fmt"
	"path/filepath"
)

// Delete removes the given file names from remoteDir.
// Names containing path components or ".." are rejected with an error.
func Delete(opts *Opts, remoteDir string, names []string, log Logger) error {
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return err
	}
	defer sshClient.Close()
	defer sftpClient.Close()
	remoteDir = filepath.ToSlash(remoteDir)
	for _, name := range names {
		if !ValidRemoteFileName(name) {
			return fmt.Errorf("invalid remote file name (path traversal): %q", name)
		}
		remotePath := remoteDir + "/" + name
		if err := sftpClient.Remove(remotePath); err != nil {
			if log != nil {
				log.Warn("remote remove %s: %v", name, err)
			}
			continue
		}
		if log != nil {
			log.Info("removed from remote: %s", name)
		}
	}
	return nil
}
