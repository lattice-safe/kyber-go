package kyber

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

// stdEncapsulationKey abstracts over mlkem.EncapsulationKey768 and
// mlkem.EncapsulationKey1024.
type stdEncapsulationKey interface {
	Bytes() []byte
	Encapsulate() (sharedKey, ciphertext []byte)
}

// stdDecapsulationKey abstracts over mlkem.DecapsulationKey768 and
// mlkem.DecapsulationKey1024. EK is the corresponding encapsulation key
// type, since EncapsulationKey() returns a concrete, size-specific type
// in the standard library.
type stdDecapsulationKey[EK stdEncapsulationKey] interface {
	Decapsulate(ciphertext []byte) ([]byte, error)
	EncapsulationKey() EK
}

// TestInteropStdlibMLKEM verifies that this package is byte-for-byte
// interoperable with the Go standard library's crypto/mlkem implementation
// of FIPS 203 ML-KEM, for the two parameter sets crypto/mlkem supports
// (ML-KEM-768 and ML-KEM-1024). This guards against the SHAKE-128 index
// swap bug in genMatrix that previously made this package's keys and
// ciphertexts non-interoperable with any conformant FIPS 203 implementation.
func TestInteropStdlibMLKEM(t *testing.T) {
	t.Run("ML-KEM-768", func(t *testing.T) {
		runInterop(t, "ML-KEM-768", Kyber768, mlkem.NewDecapsulationKey768)
	})
	t.Run("ML-KEM-1024", func(t *testing.T) {
		runInterop(t, "ML-KEM-1024", Kyber1024, mlkem.NewDecapsulationKey1024)
	})
}

func runInterop[EK stdEncapsulationKey, DK stdDecapsulationKey[EK]](
	t *testing.T,
	name string,
	mode *Mode,
	newDecapsulationKey func(seed []byte) (DK, error),
) {
	for iter := 0; iter < 10; iter++ {
		seed := make([]byte, 64)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("%s: iter %d: failed to generate random seed: %v", name, iter, err)
		}

		dk, err := newDecapsulationKey(seed)
		if err != nil {
			t.Fatalf("%s: iter %d: stdlib NewDecapsulationKey failed: %v", name, iter, err)
		}

		kp, err := GenerateKeyPairDerand(mode, seed)
		if err != nil {
			t.Fatalf("%s: iter %d: GenerateKeyPairDerand failed: %v", name, iter, err)
		}

		stdEK := dk.EncapsulationKey()
		stdPub := stdEK.Bytes()
		ourPub := kp.PublicKey()
		if !bytes.Equal(stdPub, ourPub) {
			t.Fatalf("%s: iter %d: public keys differ between stdlib and this package", name, iter)
		}

		// stdlib encapsulates, this package decapsulates.
		stdSS, stdCT := stdEK.Encapsulate()
		ourSS, err := kp.Decapsulate(stdCT)
		if err != nil {
			t.Fatalf("%s: iter %d: Decapsulate (of stdlib ciphertext) failed: %v", name, iter, err)
		}
		if !bytes.Equal(stdSS, ourSS) {
			t.Fatalf("%s: iter %d: shared secrets differ: stdlib encapsulated, this package decapsulated", name, iter)
		}

		// this package encapsulates, stdlib decapsulates.
		ourCT, ourSS2, err := Encapsulate(mode, ourPub)
		if err != nil {
			t.Fatalf("%s: iter %d: Encapsulate failed: %v", name, iter, err)
		}
		stdSS2, err := dk.Decapsulate(ourCT)
		if err != nil {
			t.Fatalf("%s: iter %d: stdlib Decapsulate (of this package's ciphertext) failed: %v", name, iter, err)
		}
		if !bytes.Equal(ourSS2, stdSS2) {
			t.Fatalf("%s: iter %d: shared secrets differ: this package encapsulated, stdlib decapsulated", name, iter)
		}

		// Flip one bit of the stdlib ciphertext and confirm both
		// implementations agree on the implicit-rejection secret.
		badCT := make([]byte, len(stdCT))
		copy(badCT, stdCT)
		badCT[0] ^= 0x01

		stdRejectSS, err := dk.Decapsulate(badCT)
		if err != nil {
			t.Fatalf("%s: iter %d: stdlib Decapsulate (of corrupted ciphertext) failed: %v", name, iter, err)
		}
		ourRejectSS, err := kp.Decapsulate(badCT)
		if err != nil {
			t.Fatalf("%s: iter %d: Decapsulate (of corrupted ciphertext) failed: %v", name, iter, err)
		}
		if !bytes.Equal(stdRejectSS, ourRejectSS) {
			t.Fatalf("%s: iter %d: implicit-rejection shared secrets differ between stdlib and this package", name, iter)
		}
	}
}
