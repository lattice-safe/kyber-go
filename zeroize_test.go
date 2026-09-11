package kyber

import "testing"

// TestZeroizeDecapsulateAfterZeroize verifies that Decapsulate refuses to
// operate on a KeyPair once it has been zeroized.
func TestZeroizeDecapsulateAfterZeroize(t *testing.T) {
	mode := Kyber768
	kp, err := GenerateKeyPair(mode)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ct, _, err := Encapsulate(mode, kp.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	kp.Zeroize()

	if _, err := kp.Decapsulate(ct); err != ErrKeyZeroized {
		t.Fatalf("expected ErrKeyZeroized, got %v", err)
	}
}

// TestZeroizePublicSecretKeyNilAfterZeroize verifies that PublicKey and
// SecretKey stop handing out material once the key pair is zeroized.
func TestZeroizePublicSecretKeyNilAfterZeroize(t *testing.T) {
	mode := Kyber768
	kp, err := GenerateKeyPair(mode)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp.Zeroize()

	if pk := kp.PublicKey(); pk != nil {
		t.Fatalf("expected PublicKey() to be nil after Zeroize, got %d bytes", len(pk))
	}
	if sk := kp.SecretKey(); sk != nil {
		t.Fatalf("expected SecretKey() to be nil after Zeroize, got %d bytes", len(sk))
	}
}

// TestZeroizeSecretKeyCopyIsIndependent verifies that PublicKey/SecretKey
// return fresh copies, so mutating the returned slice cannot affect the
// KeyPair's internal state (and therefore cannot affect later operations
// such as Decapsulate).
func TestZeroizeSecretKeyCopyIsIndependent(t *testing.T) {
	mode := Kyber768
	kp, err := GenerateKeyPair(mode)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ct, ssWant, err := Encapsulate(mode, kp.PublicKey())
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Mutate the returned copies; the KeyPair's internal state must be
	// unaffected.
	sk := kp.SecretKey()
	for i := range sk {
		sk[i] ^= 0xFF
	}
	pk := kp.PublicKey()
	for i := range pk {
		pk[i] ^= 0xFF
	}

	ssGot, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate failed after mutating returned copies: %v", err)
	}
	if string(ssGot) != string(ssWant) {
		t.Fatalf("mutating the slice returned by SecretKey()/PublicKey() affected a subsequent Decapsulate")
	}
}

// TestZeroizeByteSlice verifies the package-level Zeroize helper on a small
// slice.
func TestZeroizeByteSlice(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroized: got %d", i, v)
		}
	}
}

// TestZeroizeKeyPairTwiceIsSafe verifies that calling Zeroize more than once
// on the same KeyPair does not panic and leaves it in the zeroized state.
func TestZeroizeKeyPairTwiceIsSafe(t *testing.T) {
	mode := Kyber768
	kp, err := GenerateKeyPair(mode)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp.Zeroize()
	kp.Zeroize()

	if kp.PublicKey() != nil {
		t.Fatalf("expected PublicKey() to remain nil after double Zeroize")
	}
	if kp.SecretKey() != nil {
		t.Fatalf("expected SecretKey() to remain nil after double Zeroize")
	}
	if _, err := kp.Decapsulate(make([]byte, mode.CiphertextBytes())); err != ErrKeyZeroized {
		t.Fatalf("expected ErrKeyZeroized after double Zeroize, got %v", err)
	}
}
