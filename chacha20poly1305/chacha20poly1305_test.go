package chacha20poly1305

import (
	"crypto/cipher"
	"github.com/stretchr/testify/assert"
	upstream "golang.org/x/crypto/chacha20poly1305"
	"strconv"
	"testing"
)

func TestOne(t *testing.T) {
	nonce := make([]byte, NonceSize)
	plaintext := make([]byte, 42)
	ad := make([]byte, 2)
	var key [32]byte
	aead, _ := New(key[:])
	aeadReference, _ := upstream.New(key[:])
	ct := aead.Seal(nil, nonce, plaintext, ad)
	ctReference := aeadReference.Seal(nil, nonce, plaintext, ad)
	assert.Equal(t, ct, ctReference, "ciphertext don't match.")
}

func TestBunch(t *testing.T) {
	// todo: bunch of texts under the same key
}

// TestRepeatedNonce checks that two invocations with same nonce cause a panic.
// Note that, in theory, calling two times with the same (key, nonce) *and* plaintext
// isn't bad, just weird since it'd compute the exact same result.
// This case isn't handled yet and will cause a panic().
func TestRepeatedNonce(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	nonce := make([]byte, NonceSize)
	plaintext := make([]byte, 42)
	ad := make([]byte, 2)
	var key [32]byte
	aead, _ := New(key[:])
	_ = aead.Seal(nil, nonce, plaintext, ad)
	_ = aead.Seal(nil, nonce, plaintext, ad)
}

func TestTwoKeys(t *testing.T) {
	nonce := make([]byte, NonceSize)
	plaintext := make([]byte, 42)
	ad := make([]byte, 2)
	var key1 [32]byte
	var key2 [32]byte
	aead1, _ := New(key1[:])
	aead2, _ := New(key2[:])
	_ = aead1.Seal(nil, nonce, plaintext, ad)
	_ = aead2.Seal(nil, nonce, plaintext, ad)
}

// modified from https://cs.opensource.google/go/x/crypto/+/master:chacha20poly1305/chacha20poly1305_test.go
func benchmarkChaCha20Poly1305Seal(b *testing.B, buf []byte, nonceSize int, baseline bool) {
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce = make([]byte, nonceSize)
	var ad [13]byte
	var out []byte

	var aead cipher.AEAD

	switch len(nonce) {
	case NonceSize:
		if baseline {
			aead, _ = upstream.New(key[:])
		} else {
			aead, _ = New(key[:])
		}
	case NonceSizeX:
		if baseline {
			aead, _ = upstream.NewX(key[:])
		} else {
			aead, _ = NewX(key[:])
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce[:], buf[:], ad[:])
		nonce = incNonce(nonce)
	}
}

func Benchmark(b *testing.B) {
	for _, length := range []int{64, 1350, 8 * 1024} {

		b.Run("Seal-WithoutNonceSanitizer-"+strconv.Itoa(length), func(b *testing.B) {
			benchmarkChaCha20Poly1305Seal(b, make([]byte, length), NonceSize, true)
		})

		b.Run("Seal-WithNonceSanitizer-"+strconv.Itoa(length), func(b *testing.B) {
			benchmarkChaCha20Poly1305Seal(b, make([]byte, length), NonceSize, false)
		})
	}
}

// from age
func incNonce(nonce []byte) []byte {
	for i := len(nonce) - 2; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		} else if i == 0 {
			// The counter is 88 bits, this is unreachable.
			panic("stream: chunk counter wrapped around")
		}
	}
	return nonce
}