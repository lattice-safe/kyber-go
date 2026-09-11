package kyber

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"testing"
)

// setCoeff0 rewrites the first 12-bit coefficient (bytes 0,1 of the encoded
// polynomial) of pk to val (0..4095), leaving every other coefficient
// (including the top nibble of byte 1, which belongs to coefficient 1)
// untouched.
func setCoeff0(pk []byte, val uint16) {
	pk[0] = byte(val)
	pk[1] = (pk[1] &^ 0x0F) | byte((val>>8)&0x0F)
}

func allModes() []struct {
	name string
	mode *Mode
} {
	return []struct {
		name string
		mode *Mode
	}{
		{"ML-KEM-512", Kyber512},
		{"ML-KEM-768", Kyber768},
		{"ML-KEM-1024", Kyber1024},
	}
}

func TestValidatePublicKeyAccepted(t *testing.T) {
	for _, tc := range allModes() {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tc.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}
			if err := validatePublicKey(tc.mode, kp.PublicKey()); err != nil {
				t.Fatalf("expected valid public key to pass validation, got %v", err)
			}
			if _, _, err := Encapsulate(tc.mode, kp.PublicKey()); err != nil {
				t.Fatalf("Encapsulate failed on valid public key: %v", err)
			}
		})
	}
}

func TestValidatePublicKeyRejectsNonCanonicalCoefficient(t *testing.T) {
	for _, tc := range allModes() {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tc.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			badPk := make([]byte, len(kp.PublicKey()))
			copy(badPk, kp.PublicKey())
			// Force the first coefficient to the maximum 12-bit value (4095),
			// which is >= Q and therefore non-canonical.
			badPk[0] = 0xFF
			badPk[1] |= 0x0F

			if err := validatePublicKey(tc.mode, badPk); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("expected ErrInvalidPublicKey, got %v", err)
			}

			var coins [32]byte
			if _, _, err := EncapsulateDerand(tc.mode, badPk, coins[:]); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("EncapsulateDerand: expected ErrInvalidPublicKey, got %v", err)
			}
			if _, _, err := Encapsulate(tc.mode, badPk); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("Encapsulate: expected ErrInvalidPublicKey, got %v", err)
			}
		})
	}
}

func TestValidatePublicKeyBoundaryValues(t *testing.T) {
	for _, tc := range allModes() {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tc.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			// Exactly Q (3329, 0xD01) must be rejected: it is not < Q.
			atQ := make([]byte, len(kp.PublicKey()))
			copy(atQ, kp.PublicKey())
			setCoeff0(atQ, 3329)
			if err := validatePublicKey(tc.mode, atQ); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("coefficient == Q: expected ErrInvalidPublicKey, got %v", err)
			}

			// Q-1 (3328, 0xD00) is the largest canonical value and must be
			// accepted.
			belowQ := make([]byte, len(kp.PublicKey()))
			copy(belowQ, kp.PublicKey())
			setCoeff0(belowQ, 3328)
			if err := validatePublicKey(tc.mode, belowQ); err != nil {
				t.Fatalf("coefficient == Q-1: expected acceptance, got %v", err)
			}
		})
	}
}

func TestNewKeyPairFromSecretKeyRoundtrip(t *testing.T) {
	for _, tc := range allModes() {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tc.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			ct, ss, err := Encapsulate(tc.mode, kp.PublicKey())
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			kp2, err := NewKeyPairFromSecretKey(tc.mode, kp.SecretKey())
			if err != nil {
				t.Fatalf("NewKeyPairFromSecretKey failed: %v", err)
			}

			if !bytes.Equal(kp2.PublicKey(), kp.PublicKey()) {
				t.Fatalf("reconstructed public key does not match original")
			}

			ss2, err := kp2.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate on reconstructed key pair failed: %v", err)
			}

			if !bytes.Equal(ss, ss2) {
				t.Fatalf("shared secrets do not match after reconstructing key pair from secret key")
			}
		})
	}
}

func TestNewKeyPairFromSecretKeyWrongLength(t *testing.T) {
	for _, tc := range allModes() {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tc.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			short := kp.SecretKey()[:len(kp.SecretKey())-1]
			if _, err := NewKeyPairFromSecretKey(tc.mode, short); !errors.Is(err, ErrInvalidSecretKey) {
				t.Fatalf("expected ErrInvalidSecretKey for short key, got %v", err)
			}

			long := append(append([]byte{}, kp.SecretKey()...), 0x00)
			if _, err := NewKeyPairFromSecretKey(tc.mode, long); !errors.Is(err, ErrInvalidSecretKey) {
				t.Fatalf("expected ErrInvalidSecretKey for long key, got %v", err)
			}
		})
	}
}

func TestSecretKeyHashCheckDetectsCorruption(t *testing.T) {
	for _, tc := range allModes() {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tc.mode)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			ct, _, err := Encapsulate(tc.mode, kp.PublicKey())
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			cpaLen := tc.mode.indcpaSecretkeyBytes()
			pkLen := tc.mode.PublicKeyBytes()
			hashOffset := cpaLen + pkLen // start of the stored 32-byte H(ek)

			corrupted := make([]byte, len(kp.SecretKey()))
			copy(corrupted, kp.SecretKey())
			corrupted[hashOffset] ^= 0x01

			if _, err := NewKeyPairFromSecretKey(tc.mode, corrupted); !errors.Is(err, ErrInvalidSecretKey) {
				t.Fatalf("NewKeyPairFromSecretKey: expected ErrInvalidSecretKey, got %v", err)
			}

			// A KeyPair built directly (bypassing the constructor) with a
			// corrupted stored hash must also be rejected by Decapsulate.
			badKp := &KeyPair{mode: tc.mode, pubkey: kp.PublicKey(), seckey: corrupted}
			if _, err := badKp.Decapsulate(ct); !errors.Is(err, ErrInvalidSecretKey) {
				t.Fatalf("Decapsulate: expected ErrInvalidSecretKey, got %v", err)
			}
		})
	}
}

// TestInteropInvalidPublicKeyRejectedByStdlib cross-checks that a public key
// this package rejects for having a non-canonical coefficient is also
// rejected by the Go standard library's crypto/mlkem, confirming both
// implementations agree on the FIPS 203 §7.2 modulus check.
func TestInteropInvalidPublicKeyRejectedByStdlib(t *testing.T) {
	kp, err := GenerateKeyPair(Kyber768)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	badPk := make([]byte, len(kp.PublicKey()))
	copy(badPk, kp.PublicKey())
	badPk[0] = 0xFF
	badPk[1] |= 0x0F

	if err := validatePublicKey(Kyber768, badPk); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("expected this package to reject the malformed key, got %v", err)
	}

	if _, err := mlkem.NewEncapsulationKey768(badPk); err == nil {
		t.Fatalf("expected crypto/mlkem to also reject the malformed key")
	}
}
