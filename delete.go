package sshcommands

import (
	"errors"
	"fmt"
)

// Delete removes the given file names from remoteDir. All names are validated
// before connecting; names containing path components or ".." are rejected
// and nothing is deleted. Failed removals are collected and returned together
// (errors.Join) after all names were tried.
func Delete(opts *Opts, remoteDir string, names []string, log Logger) error {
	if err := opts.validate(); err != nil {
		return err
	}
	dir, err := cleanRemoteDir(remoteDir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if !ValidRemoteFileName(name) {
			return fmt.Errorf("invalid remote file name (path traversal): %q", name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return err
	}
	defer closeQuietly(sshClient)
	defer closeQuietly(sftpClient)
	var errs []error
	for _, name := range names {
		if err := sftpClient.Remove(joinRemote(dir, name)); err != nil {
			if log != nil {
				log.Warn("remote remove %q: %v", name, err)
			}
			errs = append(errs, fmt.Errorf("remove %q: %w", name, err))
			continue
		}
		if log != nil {
			log.Info("removed from remote: %q", name)
		}
	}
	return errors.Join(errs...)
}
