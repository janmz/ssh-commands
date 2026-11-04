package sshcommands

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Sync uploads local files that are missing, newer or of a different size on
// the remote, and deletes remote files that are not in localFiles (including
// leftovers of aborted uploads). remoteDir is created if needed.
// aesPassword empty = no encryption (surrounding whitespace is ignored).
//
// All names are validated before connecting. An empty localFiles list is
// rejected because it would delete every file in remoteDir; use Delete to
// remove files explicitly.
func Sync(opts *Opts, localFiles []LocalFile, remoteDir, aesPassword string, log Logger) error {
	if err := opts.validate(); err != nil {
		return err
	}
	dir, err := cleanRemoteDir(remoteDir)
	if err != nil {
		return err
	}
	if len(localFiles) == 0 {
		return errors.New("local file list is empty: refusing to delete all remote files (use Delete instead)")
	}
	localNames, err := validateLocalFiles(localFiles)
	if err != nil {
		return err
	}
	aesPassword = normalizeAESPassword(aesPassword)
	encrypt := aesPassword != ""

	sftpClient, sshClient, err := NewSFTPClient(opts, log)
	if err != nil {
		return err
	}
	defer closeQuietly(sshClient)
	defer closeQuietly(sftpClient)

	if err := sftpClient.MkdirAll(dir); err != nil && !os.IsExist(err) && log != nil {
		log.Warn("sftp mkdir %q: %v", dir, err)
	}
	remoteList, err := listRemote(sftpClient, dir)
	if err != nil {
		return fmt.Errorf("list remote: %w", err)
	}
	if log != nil {
		if encrypt {
			log.Info("remote: AES encryption on")
		} else {
			log.Info("remote: no AES encryption")
		}
	}
	remoteMap := make(map[string]RemoteEntry, len(remoteList))
	for _, e := range remoteList {
		remoteMap[e.Name] = e
	}
	for _, loc := range localFiles {
		rem, exists := remoteMap[loc.Name]
		if !needsUpload(loc, rem, exists, encrypt) {
			continue
		}
		if err := putFile(sftpClient, loc.Path, joinRemote(dir, loc.Name), loc.ModTime, aesPassword, log); err != nil {
			return fmt.Errorf("upload %s: %w", loc.Name, err)
		}
		if log != nil {
			log.Info("uploaded %q to remote", loc.Name)
		}
	}
	for _, rem := range remoteList {
		if !ValidRemoteFileName(rem.Name) {
			if log != nil {
				log.Warn("skip remote remove: invalid name from server: %q", rem.Name)
			}
			continue
		}
		if _, keep := localNames[rem.Name]; keep {
			continue
		}
		if err := sftpClient.Remove(joinRemote(dir, rem.Name)); err != nil {
			if log != nil {
				log.Warn("remote remove %q: %v", rem.Name, err)
			}
			continue
		}
		if log != nil {
			if isTempUploadName(rem.Name) {
				log.Info("removed leftover of aborted upload: %q", rem.Name)
			} else {
				log.Info("removed from remote (not in local): %q", rem.Name)
			}
		}
	}
	return nil
}

// validateLocalFiles checks all names (path traversal, reserved temp prefix,
// duplicates) and paths, and returns the set of names.
func validateLocalFiles(files []LocalFile) (map[string]struct{}, error) {
	names := make(map[string]struct{}, len(files))
	for _, f := range files {
		if !ValidRemoteFileName(f.Name) {
			return nil, fmt.Errorf("invalid local file name (path traversal): %q", f.Name)
		}
		if isTempUploadName(f.Name) {
			return nil, fmt.Errorf("invalid local file name (reserved prefix %q): %q", tempUploadPrefix, f.Name)
		}
		if strings.TrimSpace(f.Path) == "" {
			return nil, fmt.Errorf("local file %q: path is empty", f.Name)
		}
		if _, dup := names[f.Name]; dup {
			return nil, fmt.Errorf("duplicate local file name: %q", f.Name)
		}
		names[f.Name] = struct{}{}
	}
	return names, nil
}

// needsUpload decides whether loc must be (re-)uploaded given the remote entry
// rem (exists=false when missing). A different size (taking the encryption
// overhead into account) or a newer local mtime triggers an upload. The local
// mtime is truncated to seconds because SFTP stores whole seconds.
func needsUpload(loc LocalFile, rem RemoteEntry, exists, encrypt bool) bool {
	if !exists {
		return true
	}
	want := loc.Size
	if encrypt {
		want += EncryptionOverhead
	}
	if rem.Size != want {
		return true
	}
	return loc.ModTime.Truncate(time.Second).After(rem.ModTime)
}
