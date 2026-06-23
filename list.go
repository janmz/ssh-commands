package sshcommands

import (
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
)

// List returns all non-directory entries in remoteDir (name, modtime, size).
func List(opts *Opts, remoteDir string, log Logger) ([]RemoteEntry, error) {
	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return nil, err
	}
	defer sshClient.Close()
	defer sftpClient.Close()
	remoteDir = filepath.ToSlash(remoteDir)
	return listRemote(sftpClient, remoteDir)
}

func listRemote(client *sftp.Client, remoteDir string) ([]RemoteEntry, error) {
	entries, err := client.ReadDir(remoteDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list []RemoteEntry
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
