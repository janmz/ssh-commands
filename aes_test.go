package sshcommands

import (
	"bytes"
	"testing"
)

func TestStreamEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	plain := []byte("hello encrypted ssh-commands payload")
	password := "test-password"

	var encrypted bytes.Buffer
	if err := streamEncryptUpload(bytes.NewReader(plain), &encrypted, password); err != nil {
		t.Fatalf("streamEncryptUpload: %v", err)
	}
	if encrypted.Len() != len(plain)+EncryptionOverhead {
		t.Fatalf("encrypted len=%d want %d", encrypted.Len(), len(plain)+EncryptionOverhead)
	}

	enc := encrypted.Bytes()
	salt := enc[0:saltLen]
	nonce := enc[saltLen : saltLen+nonceLen]
	ciphertext := enc[saltLen+nonceLen:]

	var decrypted bytes.Buffer
	if err := streamDecryptDownload(bytes.NewReader(ciphertext), &decrypted, salt, nonce, password); err != nil {
		t.Fatalf("streamDecryptDownload: %v", err)
	}
	if !bytes.Equal(plain, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q want %q", decrypted.Bytes(), plain)
	}
}

func TestStreamDecryptDownloadWrongPassword(t *testing.T) {
	t.Parallel()
	plain := []byte("secret data")
	password := "right"
	var encrypted bytes.Buffer
	if err := streamEncryptUpload(bytes.NewReader(plain), &encrypted, password); err != nil {
		t.Fatalf("streamEncryptUpload: %v", err)
	}
	enc := encrypted.Bytes()
	salt := enc[0:saltLen]
	nonce := enc[saltLen : saltLen+nonceLen]
	ciphertext := enc[saltLen+nonceLen:]

	var decrypted bytes.Buffer
	if err := streamDecryptDownload(bytes.NewReader(ciphertext), &decrypted, salt, nonce, "wrong"); err != nil {
		t.Fatalf("streamDecryptDownload: %v", err)
	}
	if bytes.Equal(plain, decrypted.Bytes()) {
		t.Fatal("expected different plaintext with wrong password")
	}
}
