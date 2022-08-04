// Package chacha20poly1305 wraps around golang.org/x/crypto/chacha20poly1305
// preventing repeated nonces.
package chacha20poly1305

import (
	"crypto/cipher"
	"github.com/oreparaz/go-nonce-sanitizer/internal/noncebag"
	upstream "golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// AEAD, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	NonceSize = 12

	// NonceSizeX is the size of the nonce used with the XChaCha20-Poly1305
	// variant of this AEAD, in bytes.
	NonceSizeX = 24

	// Overhead is the size of the Poly1305 authentication tag, and the
	// difference between a ciphertext length and its plaintext.
	Overhead = 16
)

type aeadWithNonceSanitizer struct {
	c cipher.AEAD
	nonceBag noncebag.NonceBag
	nonceCounter int
}

func (a *aeadWithNonceSanitizer) NonceSize() int {
	return a.c.NonceSize()
}

func (a *aeadWithNonceSanitizer) Overhead() int {
	return a.c.Overhead()
}

func (a *aeadWithNonceSanitizer) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	a.nonceBag.Add(nonce, plaintext)
	return a.c.Seal(dst, nonce, plaintext, additionalData)
}

func (a *aeadWithNonceSanitizer) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return a.c.Open(dst, nonce, ciphertext, additionalData)
}

// New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func New(key []byte) (cipher.AEAD, error) {
	aead, err := upstream.New(key)
	if err != nil {
		return nil, err
	}
	return &aeadWithNonceSanitizer{
		c: aead,
		nonceBag: noncebag.NewBag(),
	}, nil
}

// NewX returns a XChaCha20-Poly1305 AEAD that uses the given 256-bit key.
//
// XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
// suitable to be generated randomly without risk of collisions. It should be
// preferred when nonce uniqueness cannot be trivially ensured, or whenever
// nonces are randomly generated.
func NewX(key []byte) (cipher.AEAD, error) {
	aead, err := upstream.NewX(key)
	if err != nil {
		return nil, err
	}
	return &aeadWithNonceSanitizer{
		c: aead,
		nonceBag: noncebag.NewBag(),
	}, nil
}
