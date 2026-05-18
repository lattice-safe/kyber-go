package kyber

import (
	"bytes"
	"testing"
)

// FuzzRoundtrip fuzzes the deterministic generation using raw entropy.
func FuzzRoundtrip(f *testing.F) {
	f.Add(make([]byte, 64), make([]byte, 32))

	f.Fuzz(func(t *testing.T, coinsKeyGen []byte, coinsEncaps []byte) {
		if len(coinsKeyGen) != 64 || len(coinsEncaps) != 32 {
			return
		}

		kp, err := GenerateKeyPairDerand(Kyber768, coinsKeyGen)
		if err != nil {
			t.Fatal(err)
		}

		ct, ssEncaps, err := EncapsulateDerand(Kyber768, kp.PublicKey(), coinsEncaps)
		if err != nil {
			t.Fatal(err)
		}

		ssDecaps, err := kp.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(ssEncaps, ssDecaps) {
			t.Errorf("Decapsulated shared secret does not match encapsulated shared secret")
		}
	})
}

// FuzzDecapsulate ensures that malformed ciphertexts are handled safely
// (constant-time implicit rejection without panics).
func FuzzDecapsulate(f *testing.F) {
	kp, _ := GenerateKeyPair(Kyber768)
	ct, _, _ := Encapsulate(Kyber768, kp.PublicKey())
	f.Add(ct)

	f.Fuzz(func(t *testing.T, corruptedCt []byte) {
		if len(corruptedCt) != Kyber768.CiphertextBytes() {
			return
		}
		// This should not panic and should return an implicitly rejected shared secret
		ss, err := kp.Decapsulate(corruptedCt)
		if err != nil {
			t.Fatal(err)
		}
		_ = ss
	})
}
