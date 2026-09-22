// Package crypto provides AES-256-GCM encryption for stored records.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
)

// ErrInvalidKey is returned when a key cannot be decoded.
var ErrInvalidKey = errors.New("crypto: invalid key")

// Cipher encrypts and decrypts data with AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a 32-byte key.
func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext with a random nonce. The returned value is
// nonce || ciphertext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens ciphertext produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.aead.NonceSize() {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce := ciphertext[:c.aead.NonceSize()]
	body := ciphertext[c.aead.NonceSize():]
	return c.aead.Open(nil, nonce, body, nil)
}

// KeyFromEnv reads a hex or base64 key from the environment variable name. If
// the variable is absent, a random key is generated and a warning is logged
// (without the key value).
func KeyFromEnv(name string) ([]byte, error) {
	raw := os.Getenv(name)
	if raw == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		log.Printf("crypto: env %s not set, generated a random key", name)
		return key, nil
	}
	if key, err := hex.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, fmt.Errorf("%w: env %s", ErrInvalidKey, name)
}
