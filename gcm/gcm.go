// Package gcm wraps around crypto/cipher GCM preventing repeated nonces.
package gcm

import (
	"crypto/cipher"
	"github.com/oreparaz/go-nonce-sanitizer/internal/noncebag"
)

type aeadWithNonceSanitizer struct {
	c cipher.AEAD
	nonceBag noncebag.NonceBag
	nonceCounter int
}

func (a aeadWithNonceSanitizer) NonceSize() int {
	return a.c.NonceSize()
}

func (a aeadWithNonceSanitizer) Overhead() int {
	return a.c.Overhead()
}

func (a aeadWithNonceSanitizer) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	a.nonceBag.Add(nonce, plaintext)
	return a.c.Seal(dst, nonce, plaintext, additionalData)
}

func (a aeadWithNonceSanitizer) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return a.c.Open(dst, nonce, ciphertext, additionalData)
}

func NewGCM(key cipher.Block) (cipher.AEAD, error) {
	aead, err := cipher.NewGCM(key)
	if err != nil {
		return nil, err
	}
	return &aeadWithNonceSanitizer{
		c: aead,
		nonceBag: noncebag.NewBag(),
	}, nil
}
