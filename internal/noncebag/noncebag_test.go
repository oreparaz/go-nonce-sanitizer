package noncebag

import (
	"testing"
)

func TestNonceBag_Add_Repeated(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	b := NewBag()
	nonce1 := []byte("nonce")
	nonce2 := []byte("nonce")
	plain := []byte("plain")

	b.Add(nonce1, plain)
	b.Add(nonce2, plain)
}

func TestNonceBag_Add_Different(t *testing.T) {
	b := NewBag()
	nonce1 := []byte("nonce1")
	nonce2 := []byte("nonce2")
	nonce3 := []byte("nonce3")
	plain := []byte("plain")

	b.Add(nonce1, plain)
	b.Add(nonce2, plain)
	b.Add(nonce3, plain)
}
