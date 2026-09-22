package crypto

import (
	"bytes"
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plain := []byte("secret personal data")
	ct, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Error("ciphertext equals plaintext")
	}
	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip failed: got %q, want %q", got, plain)
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	c, _ := New(key)
	ct, _ := c.Encrypt([]byte("data"))
	ct[len(ct)-1] ^= 0xff
	if _, err := c.Decrypt(ct); err == nil {
		t.Error("expected error on tampered ciphertext")
	}
}

func TestNewWrongKeySize(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestKeyFromEnv(t *testing.T) {
	t.Setenv("TEST_KEY_HEX", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	key, err := KeyFromEnv("TEST_KEY_HEX")
	if err != nil {
		t.Fatalf("KeyFromEnv hex: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("hex key length = %d, want 32", len(key))
	}

	t.Setenv("TEST_KEY_B64", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	key, err = KeyFromEnv("TEST_KEY_B64")
	if err != nil {
		t.Fatalf("KeyFromEnv base64: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("base64 key length = %d, want 32", len(key))
	}
}

func TestKeyFromEnvMissing(t *testing.T) {
	os.Unsetenv("TEST_KEY_MISSING")
	key, err := KeyFromEnv("TEST_KEY_MISSING")
	if err != nil {
		t.Fatalf("KeyFromEnv missing: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("generated key length = %d, want 32", len(key))
	}
}
