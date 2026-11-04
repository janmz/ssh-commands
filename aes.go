package sshcommands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Encrypted stream format (version 3, written by this package):
//
//	magic "SSHC" | version 0x03 | PBKDF2 iterations (uint32 BE) | salt(16) | nonce(16)
//	| AES-256-CTR ciphertext | HMAC-SHA256(32)
//
// PBKDF2-SHA256 derives 64 bytes from password and salt: the first 32 are the
// AES key, the last 32 the HMAC key. The HMAC covers the header, the remote
// file name (uint16 BE length + bytes) and the ciphertext, so a wrong
// password, a modified file and a renamed/swapped file are all detected.
//
// The legacy format (salt | nonce | ciphertext, no magic, no MAC) written by
// versions before 0.3.0 is only decrypted when explicitly allowed
// (DownloadOptions.AllowLegacyDecryption).
const (
	saltLen    = 16
	nonceLen   = 16
	aesKeyLen  = 32
	macKeyLen  = 32
	macLen     = sha256.Size
	pbkdf2Iter = 600000 // written into new files

	// Accepted iteration range when reading: the lower bound prevents a
	// downgraded header, the upper bound a CPU exhaustion via a forged header.
	minPBKDF2Iter = 100000
	maxPBKDF2Iter = 10000000

	legacyPBKDF2Iter = 100000
	formatVersion    = 3
	magicLen         = 4
	iterLen          = 4
	headerLen        = magicLen + 1 + iterLen + saltLen + nonceLen
	legacyHeaderLen  = saltLen + nonceLen
)

// fileMagic identifies encrypted streams written by this package.
var fileMagic = []byte("SSHC")

// EncryptionOverhead is the number of bytes added to an encrypted stream
// (header plus MAC).
const EncryptionOverhead = headerLen + macLen

// ErrDecryptIntegrity is returned when an encrypted file fails its integrity
// check (wrong AES password, corrupted/modified data or renamed file).
var ErrDecryptIntegrity = errors.New("encrypted data failed integrity check: wrong AES password, corrupted or renamed file")

// ErrNotEncrypted is returned by Download when an AES password is given but
// the remote file is not in the current encrypted format.
var ErrNotEncrypted = errors.New("remote file is not encrypted in the current format (legacy files need DownloadOptions.AllowLegacyDecryption)")

// normalizeAESPassword is applied by Sync and Download alike so that
// encryption and decryption always use the same key material.
func normalizeAESPassword(pw string) string {
	return strings.TrimSpace(pw)
}

// deriveKeys returns the AES and HMAC keys for password, salt and iterations.
func deriveKeys(password string, salt []byte, iter int) (encKey, macKey []byte) {
	k := pbkdf2.Key([]byte(password), salt, iter, aesKeyLen+macKeyLen, sha256.New)
	return k[:aesKeyLen], k[aesKeyLen:]
}

// maxBoundNameLen is the longest file name that can be bound into the MAC.
const maxBoundNameLen = 0xFFFF

// newMAC returns an HMAC already fed with header and the bound file name.
// Callers ensure len(name) <= maxBoundNameLen.
func newMAC(macKey, header []byte, name string) hash.Hash {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(header)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(name))) // #nosec G115 -- bounded by maxBoundNameLen
	mac.Write(l[:])
	mac.Write([]byte(name))
	return mac
}

// streamEncryptUpload encrypts src into dst using the current format; name is
// the remote file name the data is bound to (at most 65535 bytes).
func streamEncryptUpload(src io.Reader, dst io.Writer, password, name string) error {
	if len(name) > maxBoundNameLen {
		return errors.New("file name too long for encryption")
	}
	header := make([]byte, headerLen)
	copy(header, fileMagic)
	header[magicLen] = formatVersion
	binary.BigEndian.PutUint32(header[magicLen+1:], pbkdf2Iter)
	salt := header[magicLen+1+iterLen : magicLen+1+iterLen+saltLen]
	nonce := header[magicLen+1+iterLen+saltLen:]
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("rand salt: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rand nonce: %w", err)
	}
	encKey, macKey := deriveKeys(password, salt, pbkdf2Iter)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	mac := newMAC(macKey, header, name)
	if _, err := dst.Write(header); err != nil {
		return err
	}
	w := &cipher.StreamWriter{S: cipher.NewCTR(block, nonce), W: io.MultiWriter(dst, mac)}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	_, err = dst.Write(mac.Sum(nil))
	return err
}

// hasMagic reports whether header starts with the package magic (any version).
func hasMagic(header []byte) bool {
	return len(header) >= magicLen+1 && bytes.Equal(header[:magicLen], fileMagic)
}

// decryptCurrent decrypts a current-format stream. header holds the first
// headerLen bytes, src the rest of a stream of totalSize bytes. Plaintext is
// written to dst before the MAC is checked, so dst must be discarded on error.
func decryptCurrent(src io.Reader, totalSize int64, header []byte, dst io.Writer, password, name string) error {
	if len(header) != headerLen || totalSize < EncryptionOverhead {
		return errors.New("encrypted file truncated")
	}
	if len(name) > maxBoundNameLen {
		return errors.New("file name too long for decryption")
	}
	if header[magicLen] != formatVersion {
		return fmt.Errorf("unsupported encryption format version %d", header[magicLen])
	}
	iter := binary.BigEndian.Uint32(header[magicLen+1:])
	if iter < minPBKDF2Iter || iter > maxPBKDF2Iter {
		return fmt.Errorf("encrypted file header invalid: PBKDF2 iterations %d out of range", iter)
	}
	salt := header[magicLen+1+iterLen : magicLen+1+iterLen+saltLen]
	nonce := header[magicLen+1+iterLen+saltLen:]
	encKey, macKey := deriveKeys(password, salt, int(iter))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	mac := newMAC(macKey, header, name)
	ctLen := totalSize - EncryptionOverhead
	r := io.TeeReader(io.LimitReader(src, ctLen), mac)
	w := &cipher.StreamWriter{S: cipher.NewCTR(block, nonce), W: dst}
	n, err := io.Copy(w, r)
	if err != nil {
		return err
	}
	if n != ctLen {
		return errors.New("encrypted file truncated")
	}
	tag := make([]byte, macLen)
	if _, err := io.ReadFull(src, tag); err != nil {
		return errors.New("encrypted file truncated")
	}
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return ErrDecryptIntegrity
	}
	return nil
}

// decryptLegacy decrypts the legacy format (salt | nonce | ciphertext) without
// any integrity check.
func decryptLegacy(src io.Reader, dst io.Writer, salt, nonce []byte, password string) error {
	key := pbkdf2.Key([]byte(password), salt, legacyPBKDF2Iter, aesKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	w := &cipher.StreamWriter{S: cipher.NewCTR(block, nonce), W: dst}
	_, err = io.Copy(w, src)
	return err
}

// decodeParams controls decodeRemote.
type decodeParams struct {
	password    string // normalized AES password; empty = no decryption
	name        string // remote file name (bound into the MAC, used in logs)
	allowLegacy bool   // decrypt files without magic in the legacy format
}

// decodeRemote writes the content of a remote file (src, totalSize bytes) to
// dst. Without a password the data is copied unchanged. With a password the
// file must be in the current format; only with allowLegacy are other files
// decrypted in the legacy format (ZIP files, starting with "PK", and files
// shorter than the legacy header are then copied unchanged).
func decodeRemote(src io.Reader, totalSize int64, dst io.Writer, p decodeParams, log Logger) error {
	header := make([]byte, headerLen)
	n, err := io.ReadFull(src, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("remote read: %w", err)
	}
	header = header[:n]
	if p.password == "" {
		if hasMagic(header) && log != nil {
			log.Warn("remote file %q is encrypted but no AES password was given; saving it unchanged", p.name)
		}
		return copyRaw(dst, header, src)
	}
	if hasMagic(header) {
		if err := decryptCurrent(src, totalSize, header, dst, p.password, p.name); err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		if log != nil {
			log.Info("remote file decrypted: %q", p.name)
		}
		return nil
	}
	if !p.allowLegacy {
		return ErrNotEncrypted
	}
	if n < legacyHeaderLen || (header[0] == 'P' && header[1] == 'K') {
		return copyRaw(dst, header, src)
	}
	if log != nil {
		log.Warn("remote file %q decrypted in legacy format (no integrity check); upload it again to convert", p.name)
	}
	rest := io.MultiReader(bytes.NewReader(header[legacyHeaderLen:]), src)
	if err := decryptLegacy(rest, dst, header[:saltLen], header[saltLen:legacyHeaderLen], p.password); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	return nil
}

// copyRaw writes the already read header followed by the rest of src to dst.
func copyRaw(dst io.Writer, header []byte, src io.Reader) error {
	if _, err := dst.Write(header); err != nil {
		return err
	}
	_, err := io.Copy(dst, src)
	return err
}
