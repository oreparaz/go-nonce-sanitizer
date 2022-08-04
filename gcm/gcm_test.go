package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOne(t *testing.T) {
	nonce := make([]byte, 12)
	plaintext := []byte("exampleplaintext")
	ad := make([]byte, 2)

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	aead, _ := NewGCM(block)
	aeadReference, _ := cipher.NewGCM(block)
	ct := aead.Seal(nil, nonce, plaintext, ad)
	ctReference := aeadReference.Seal(nil, nonce, plaintext, ad)
	assert.Equal(t, ct, ctReference, "ciphertext don't match.")
}

// TestRepeatedNonce checks that two invocations with same nonce cause a panic.
// Note that, in theory, calling two times with the same (key, nonce) *and* plaintext
// isn't bad, just weird since it'd compute the exact same result.
// This case isn't handled yet and will still cause a panic(),
// even when in theory we shouldn't.
func TestRepeatedNonce(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	aead, _ := NewGCM(block)
	plaintext := make([]byte, 42)
	ad := make([]byte, 2)
	nonce := make([]byte, 12)

	_ = aead.Seal(nil, nonce, plaintext, ad)
	_ = aead.Seal(nil, nonce, plaintext, ad)
}