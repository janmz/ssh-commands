package sshcommands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLen    = 16
	nonceLen   = 16
	aesKeyLen  = 32
	pbkdf2Iter = 100000
)

// EncryptionOverhead is the number of bytes added to an encrypted stream (salt + nonce).
const EncryptionOverhead = saltLen + nonceLen

func streamEncryptUpload(src io.Reader, dst io.Writer, password string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("rand salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rand nonce: %w", err)
	}
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iter, aesKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, nonce)
	if _, err := dst.Write(salt); err != nil {
		return err
	}
	if _, err := dst.Write(nonce); err != nil {
		return err
	}
	w := &cipher.StreamWriter{S: stream, W: dst}
	_, err = io.Copy(w, src)
	return err
}

func streamDecryptDownload(src io.Reader, dst io.Writer, salt, nonce []byte, password string) error {
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iter, aesKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	stream := cipher.NewCTR(block, nonce)
	w := &cipher.StreamWriter{S: stream, W: dst}
	_, err = io.Copy(w, src)
	return err
}
