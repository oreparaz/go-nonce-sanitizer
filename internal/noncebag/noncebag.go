package noncebag

// keep things simple and just keep track of the last few nonces.
// this won't catch all nonce repetitions, but has the advantage of
// very small memory footprint
const maxBagSize    = 1000
const prunedBagSize = maxBagSize - (maxBagSize/2)

type NonceBag struct {
	bag          map[string]int
	nonceCounter int
}

func NewBag() NonceBag {
	return NonceBag {
		bag: make(map[string]int),
		nonceCounter: 0,
	}
}

func (m *NonceBag) Add(nonce []byte, plaintext []byte) {
	index := string(nonce)

	// we currently ignore the passed plaintext. in theory, we should
	// allow calling the AEAD with same nonce *and* same plaintext.
	// there's nothing wrong with that usage (even a bit weird).
	// for simplicity, ignore this case.
	_ = plaintext

	if _, ok := m.bag[index]; ok {
		panic("nonce/key pair already seen")
	}
	m.nonceCounter++
	m.bag[index] = m.nonceCounter
	m.cleanup()
}

func (m *NonceBag) cleanup() {
	if len(m.bag) < maxBagSize {
		return
	}
	for k, v := range m.bag {
		if v < (m.nonceCounter - prunedBagSize) {
			delete(m.bag, k)
		}
	}
}
