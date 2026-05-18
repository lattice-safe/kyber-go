package kyber

import (
	"testing"
)

func TestCoverage(t *testing.T) {
	// 1. api.go invalid inputs
	mode := Kyber768
	_, err := GenerateKeyPairDerand(mode, make([]byte, 63))
	if err != ErrInvalidCoinsLength {
		t.Fatalf("expected ErrInvalidCoinsLength, got %v", err)
	}

	kp, _ := GenerateKeyPair(mode)
	if kp.Mode() != mode {
		t.Fatalf("expected Mode to be %v, got %v", mode, kp.Mode())
	}
	if len(kp.SecretKey()) != mode.SecretKeyBytes() {
		t.Fatalf("invalid secret key length")
	}

	_, err = kp.Decapsulate(make([]byte, 10))
	if err != ErrInvalidCiphertextLength {
		t.Fatalf("expected ErrInvalidCiphertextLength, got %v", err)
	}

	_, _, err = EncapsulateDerand(mode, make([]byte, 10), make([]byte, 32))
	if err != ErrInvalidPublicKeyLength {
		t.Fatalf("expected ErrInvalidPublicKeyLength, got %v", err)
	}

	_, _, err = EncapsulateDerand(mode, kp.PublicKey(), make([]byte, 31))
	if err != ErrInvalidCoinsLength {
		t.Fatalf("expected ErrInvalidCoinsLength, got %v", err)
	}

	// 2. api.go Zeroize on KeyPair
	kp.Zeroize()
	for _, b := range kp.PublicKey() {
		if b != 0 {
			t.Fatalf("public key not zeroized")
		}
	}

	// 4. poly.go / polyvec.go Compress / Decompress panics
	badModePoly := &Mode{PolyCompressedBytes: 999}
	p := NewPoly()
	assertPanic(t, func() { p.Compress(make([]byte, 1000), badModePoly) })
	assertPanic(t, func() { DecompressToPoly(make([]byte, 1000), badModePoly) })

	badModePolyVec := &Mode{K: 2, PolyvecCompressedBytes: 999}
	pv := NewPolyVec(2)
	assertPanic(t, func() { pv.Compress(make([]byte, 1000), badModePolyVec) })
	assertPanic(t, func() { DecompressToPolyVec(make([]byte, 1000), badModePolyVec) })

	// 5. symmetric.go shake256
	out := make([]byte, 32)
	in := make([]byte, 32)
	shake256(out, in)

	out2 := make([]byte, 32)
	shake256(out2, in)
	for i := range out {
		if out[i] != out2[i] {
			t.Fatalf("shake256 is not deterministic")
		}
	}

	// 6. polyCbd panic
	var r [256]int16
	assertPanic(t, func() { polyCbd(&r, nil, 999) })
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f()
}
