package sshcommands

import (
	"errors"
	"fmt"
	"os"

	"github.com/pkg/sftp"
)

// List returns all non-directory entries in remoteDir (name, modtime, size).
// A missing directory yields an empty list.
func List(opts *Opts, remoteDir string, log Logger) ([]RemoteEntry, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	dir, err := cleanRemoteDir(remoteDir)
	if err != nil {
		return nil, err
	}
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(sshClient)
	defer closeQuietly(sftpClient)
	return listRemote(sftpClient, dir)
}

// listRemote lists the files (no directories) in remoteDir, at most
// maxRemoteEntries entries.
func listRemote(client *sftp.Client, remoteDir string) ([]RemoteEntry, error) {
	entries, err := client.ReadDir(remoteDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(entries) > maxRemoteEntries {
		return nil, fmt.Errorf("remote directory %s has %d entries (limit %d)", remoteDir, len(entries), maxRemoteEntries)
	}
	list := make([]RemoteEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		list = append(list, RemoteEntry{
			Name:    e.Name(),
			ModTime: e.ModTime(),
			Size:    e.Size(),
		})
	}
	return list, nil
}
