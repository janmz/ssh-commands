package sshcommands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// encryptForTest encrypts plain with the current format, bound to name "f".
func encryptForTest(t *testing.T, plain []byte, password string) []byte {
	t.Helper()
	var enc bytes.Buffer
	if err := streamEncryptUpload(bytes.NewReader(plain), &enc, password, "f"); err != nil {
		t.Fatalf("streamEncryptUpload: %v", err)
	}
	return enc.Bytes()
}

// encryptLegacyForTest builds a legacy-format stream (salt | nonce | ciphertext).
func encryptLegacyForTest(t *testing.T, plain []byte, password string) []byte {
	t.Helper()
	salt := bytes.Repeat([]byte{0x11}, saltLen)
	nonce := bytes.Repeat([]byte{0x22}, nonceLen)
	key := pbkdf2.Key([]byte(password), salt, legacyPBKDF2Iter, aesKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(plain))
	cipher.NewCTR(block, nonce).XORKeyStream(ct, plain)
	return append(append(append([]byte{}, salt...), nonce...), ct...)
}

func decodeForTest(data []byte, p decodeParams) ([]byte, error) {
	var out bytes.Buffer
	if p.name == "" {
		p.name = "f"
	}
	err := decodeRemote(bytes.NewReader(data), int64(len(data)), &out, p, nil)
	return out.Bytes(), err
}

func TestEncryptDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	for _, plain := range [][]byte{nil, []byte("x"), []byte("hello encrypted ssh-commands payload"), bytes.Repeat([]byte("ab"), 70000)} {
		enc := encryptForTest(t, plain, "test-password")
		if len(enc) != len(plain)+EncryptionOverhead {
			t.Fatalf("encrypted len=%d want %d", len(enc), len(plain)+EncryptionOverhead)
		}
		if got := binary.BigEndian.Uint32(enc[magicLen+1:]); got != pbkdf2Iter {
			t.Fatalf("iterations in header=%d want %d", got, pbkdf2Iter)
		}
		got, err := decodeForTest(enc, decodeParams{password: "test-password"})
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round-trip mismatch for %d bytes", len(plain))
		}
	}
}

func TestDecodeIntegrityFailures(t *testing.T) {
	t.Parallel()
	enc := encryptForTest(t, []byte("secret data that is long enough"), "pw")
	tampered := append([]byte{}, enc...)
	tampered[headerLen+3] ^= 0x01
	cases := map[string]struct {
		data []byte
		p    decodeParams
	}{
		"wrong password": {enc, decodeParams{password: "wrong"}},
		"tampered":       {tampered, decodeParams{password: "pw"}},
		"renamed file":   {enc, decodeParams{password: "pw", name: "other"}},
	}
	for name, c := range cases {
		if _, err := decodeForTest(c.data, c.p); !errors.Is(err, ErrDecryptIntegrity) {
			t.Fatalf("%s: err=%v want ErrDecryptIntegrity", name, err)
		}
	}
	if _, err := decodeForTest(enc[:len(enc)-5], decodeParams{password: "pw"}); err == nil {
		t.Fatal("truncated stream must fail")
	}
}

func TestDecodeRejectsForgedHeader(t *testing.T) {
	t.Parallel()
	enc := encryptForTest(t, []byte("data"), "pw")
	for name, mutate := range map[string]func([]byte){
		"iterations too low":  func(b []byte) { binary.BigEndian.PutUint32(b[magicLen+1:], 1) },
		"iterations too high": func(b []byte) { binary.BigEndian.PutUint32(b[magicLen+1:], 1<<31) },
		"unknown version":     func(b []byte) { b[magicLen] = 9 },
	} {
		forged := append([]byte{}, enc...)
		mutate(forged)
		if _, err := decodeForTest(forged, decodeParams{password: "pw"}); err == nil || errors.Is(err, ErrDecryptIntegrity) {
			t.Fatalf("%s: err=%v want header error", name, err)
		}
	}
}

func TestDecodeLegacyRequiresOptIn(t *testing.T) {
	t.Parallel()
	plain := []byte("legacy encrypted content")
	legacy := encryptLegacyForTest(t, plain, "pw")
	if _, err := decodeForTest(legacy, decodeParams{password: "pw"}); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("legacy without opt-in err=%v want ErrNotEncrypted", err)
	}
	got, err := decodeForTest(legacy, decodeParams{password: "pw", allowLegacy: true})
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("legacy with opt-in: %q %v", got, err)
	}
}

func TestDecodeDowngradeAttackFails(t *testing.T) {
	t.Parallel()
	// Strip magic, version, iterations and MAC from a current file and present
	// the rest (salt | nonce | ciphertext) as legacy data.
	plain := []byte("amount=0100")
	enc := encryptForTest(t, plain, "pw")
	stripped := append([]byte{}, enc[magicLen+1+iterLen:len(enc)-macLen]...)
	if _, err := decodeForTest(stripped, decodeParams{password: "pw"}); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("downgrade without opt-in err=%v want ErrNotEncrypted", err)
	}
	// Even with opt-in the legacy key differs from the current one, so the
	// result is not the plaintext and targeted bit flips are impossible.
	got, err := decodeForTest(stripped, decodeParams{password: "pw", allowLegacy: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, plain) {
		t.Fatal("legacy key must differ from current key")
	}
}

func TestDecodePlainData(t *testing.T) {
	t.Parallel()
	text := []byte("plain content longer than thirty-two bytes ....")
	zip := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0}, 40)...)
	cases := []struct {
		name string
		p    decodeParams
		data []byte
	}{
		{"no password", decodeParams{}, text},
		{"encrypted without password", decodeParams{}, encryptForTest(t, []byte("abc"), "pw")},
		{"zip with legacy opt-in", decodeParams{password: "pw", allowLegacy: true}, zip},
		{"short with legacy opt-in", decodeParams{password: "pw", allowLegacy: true}, []byte("short")},
	}
	for _, c := range cases {
		got, err := decodeForTest(c.data, c.p)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !bytes.Equal(got, c.data) {
			t.Fatalf("%s: data changed", c.name)
		}
	}
	for _, data := range [][]byte{text, zip, nil} {
		if _, err := decodeForTest(data, decodeParams{password: "pw"}); !errors.Is(err, ErrNotEncrypted) {
			t.Fatalf("plain data with password: err=%v want ErrNotEncrypted", err)
		}
	}
}

func TestNormalizeAESPassword(t *testing.T) {
	t.Parallel()
	enc := encryptForTest(t, []byte("data"), normalizeAESPassword(" pw\n"))
	got, err := decodeForTest(enc, decodeParams{password: normalizeAESPassword("pw")})
	if err != nil || string(got) != "data" {
		t.Fatalf("normalized passwords must match: %q %v", got, err)
	}
}
