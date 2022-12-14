# go-nonce-sanitizer

This module wraps common AEAD modes to prevent the major screw-up everyone is scared to make: repeated
nonces under the same key.

In the happy path, when nonces don't repeat, this module wraps
transparently the AEAD. In the sad path (nonces repeat), this module will `panic()`.

See https://www.reparaz.net/oscar/misc/nonce-sanitizer.html for more details.

### How to use it

To use, `go get github.com/oreparaz/go-nonce-sanitizer` and then swap imports like this:
```
-       "golang.org/x/crypto/chacha20poly1305"
+       "github.com/oreparaz/go-nonce-sanitizer/chacha20poly1305"
```

and the rest should work. You can use it for tests or for the actual application if you can afford
the (small) overhead.


Currently supported modes:
* AES-GCM `crypto/cipher/#NewGCM`
* ChaCha20 + Poly1305 `golang.org/x/crypto/chacha20poly1305`