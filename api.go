package kyber

import (
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	ErrInvalidPublicKeyLength  = errors.New("invalid public key length")
	ErrInvalidSecretKeyLength  = errors.New("invalid secret key length")
	ErrInvalidCiphertextLength = errors.New("invalid ciphertext length")
	ErrInvalidCoinsLength      = errors.New("invalid coins length")
	ErrInvalidPublicKey        = errors.New("invalid public key: non-canonical polynomial encoding")
	ErrInvalidSecretKey        = errors.New("invalid secret key")
	ErrKeyZeroized             = errors.New("key pair has been zeroized")
	// ErrInvalidMode is returned when mode is nil or is not one of the
	// package-provided parameter sets (Kyber512, Kyber768, Kyber1024, or
	// their MLKEM* aliases).
	ErrInvalidMode = errors.New("invalid mode: must be Kyber512, Kyber768, or Kyber1024 (or their MLKEM* aliases)")
)

// Zeroize securely clears a byte slice.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// KeyPair represents an ML-KEM key pair.
type KeyPair struct {
	mode     *Mode
	pubkey   []byte
	seckey   []byte
	zeroized bool
}

// GenerateKeyPairDerand generates an ML-KEM key pair deterministically from
// 64 bytes of caller-supplied coins.
func GenerateKeyPairDerand(mode *Mode, coins []byte) (*KeyPair, error) {
	if !mode.valid() {
		return nil, ErrInvalidMode
	}
	if len(coins) != 64 {
		return nil, ErrInvalidCoinsLength
	}
	pk, sk := keypairDerand(mode, coins)
	return &KeyPair{
		mode:   mode,
		pubkey: pk,
		seckey: sk,
	}, nil
}

// GenerateKeyPair generates a random ML-KEM key pair.
func GenerateKeyPair(mode *Mode) (*KeyPair, error) {
	if !mode.valid() {
		return nil, ErrInvalidMode
	}
	var coins [64]byte
	if _, err := rand.Read(coins[:]); err != nil {
		return nil, fmt.Errorf("kyber: entropy source failed: %w", err)
	}
	kp, err := GenerateKeyPairDerand(mode, coins[:])
	Zeroize(coins[:])
	return kp, err
}

// Mode returns the parameter set this key pair was generated with.
func (kp *KeyPair) Mode() *Mode {
	return kp.mode
}

// PublicKey returns a fresh copy of the encapsulation (public) key so that
// callers cannot mutate the key pair's internal state through the returned
// slice. It returns nil once the key pair has been zeroized.
func (kp *KeyPair) PublicKey() []byte {
	if kp.zeroized {
		return nil
	}
	return append([]byte(nil), kp.pubkey...)
}

// SecretKey returns a fresh copy of the decapsulation (secret) key so that
// callers cannot mutate the key pair's internal state through the returned
// slice. It returns nil once the key pair has been zeroized. Callers should
// call Zeroize on the returned copy once it is no longer needed.
func (kp *KeyPair) SecretKey() []byte {
	if kp.zeroized {
		return nil
	}
	return append([]byte(nil), kp.seckey...)
}

// Zeroize clears the sensitive material in the key pair. It is safe to call
// more than once.
func (kp *KeyPair) Zeroize() {
	Zeroize(kp.pubkey)
	Zeroize(kp.seckey)
	kp.zeroized = true
}

// Decapsulate recovers the shared secret from a ciphertext using this key
// pair's decapsulation (secret) key.
func (kp *KeyPair) Decapsulate(ct []byte) ([]byte, error) {
	if !kp.mode.valid() {
		return nil, ErrInvalidMode
	}
	if kp.zeroized {
		return nil, ErrKeyZeroized
	}
	if len(ct) != kp.mode.CiphertextBytes() {
		return nil, ErrInvalidCiphertextLength
	}
	if err := validateSecretKey(kp.mode, kp.seckey); err != nil {
		return nil, ErrInvalidSecretKey
	}
	ss := decaps(kp.mode, ct, kp.seckey)
	return ss, nil
}

// EncapsulateDerand encapsulates deterministically against a public key,
// using 32 bytes of caller-supplied coins.
func EncapsulateDerand(mode *Mode, pk []byte, coins []byte) ([]byte, []byte, error) {
	if !mode.valid() {
		return nil, nil, ErrInvalidMode
	}
	if len(pk) != mode.PublicKeyBytes() {
		return nil, nil, ErrInvalidPublicKeyLength
	}
	if err := validatePublicKey(mode, pk); err != nil {
		return nil, nil, err
	}
	if len(coins) != 32 {
		return nil, nil, ErrInvalidCoinsLength
	}
	ct, ss := encapsDerand(mode, pk, coins)
	return ct, ss, nil
}

// Encapsulate encapsulates a random shared secret against a public key.
func Encapsulate(mode *Mode, pk []byte) ([]byte, []byte, error) {
	if !mode.valid() {
		return nil, nil, ErrInvalidMode
	}
	var coins [32]byte
	if _, err := rand.Read(coins[:]); err != nil {
		return nil, nil, fmt.Errorf("kyber: entropy source failed: %w", err)
	}
	ct, ss, err := EncapsulateDerand(mode, pk, coins[:])
	Zeroize(coins[:])
	return ct, ss, err
}
