package kyber

import (
	"crypto/rand"
	"errors"
)

var (
	ErrInvalidPublicKeyLength  = errors.New("invalid public key length")
	ErrInvalidSecretKeyLength  = errors.New("invalid secret key length")
	ErrInvalidCiphertextLength = errors.New("invalid ciphertext length")
	ErrInvalidCoinsLength      = errors.New("invalid coins length")
)

// Zeroize securely clears a byte slice.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// KeyPair represents an ML-KEM key pair.
type KeyPair struct {
	mode   *Mode
	pubkey []byte
	seckey []byte
}

func GenerateKeyPairDerand(mode *Mode, coins []byte) (*KeyPair, error) {
	if len(coins) != 64 {
		return nil, ErrInvalidCoinsLength
	}
	pk, sk := KeypairDerand(mode, coins)
	return &KeyPair{
		mode:   mode,
		pubkey: pk,
		seckey: sk,
	}, nil
}

func GenerateKeyPair(mode *Mode) (*KeyPair, error) {
	var coins [64]byte
	rand.Read(coins[:])
	kp, err := GenerateKeyPairDerand(mode, coins[:])
	Zeroize(coins[:])
	return kp, err
}

func (kp *KeyPair) Mode() *Mode {
	return kp.mode
}

func (kp *KeyPair) PublicKey() []byte {
	return kp.pubkey
}

func (kp *KeyPair) SecretKey() []byte {
	return kp.seckey
}

// Zeroize clears the sensitive material in the key pair.
func (kp *KeyPair) Zeroize() {
	Zeroize(kp.pubkey)
	Zeroize(kp.seckey)
}

func (kp *KeyPair) Decapsulate(ct []byte) ([]byte, error) {
	if len(ct) != kp.mode.CiphertextBytes() {
		return nil, ErrInvalidCiphertextLength
	}
	ss := Decaps(kp.mode, ct, kp.seckey)
	return ss, nil
}

func EncapsulateDerand(mode *Mode, pk []byte, coins []byte) ([]byte, []byte, error) {
	if len(pk) != mode.PublicKeyBytes() {
		return nil, nil, ErrInvalidPublicKeyLength
	}
	if len(coins) != 32 {
		return nil, nil, ErrInvalidCoinsLength
	}
	ct, ss := EncapsDerand(mode, pk, coins)
	return ct, ss, nil
}

func Encapsulate(mode *Mode, pk []byte) ([]byte, []byte, error) {
	var coins [32]byte
	rand.Read(coins[:])
	ct, ss, err := EncapsulateDerand(mode, pk, coins[:])
	Zeroize(coins[:])
	return ct, ss, err
}
