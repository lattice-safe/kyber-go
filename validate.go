package kyber

import "crypto/subtle"

// validatePublicKey implements the FIPS 203 §7.2 "Modulus check" for
// encapsulation keys: every 12-bit coefficient of the encoded polynomial
// vector that makes up the encapsulation key must be a canonical value,
// i.e. strictly less than Q (3329). Coefficients are decoded exactly like
// frombytesToPoly does, and a single "bad" flag is OR-accumulated across
// every coefficient of every polynomial (no early return), so the check
// runs in time independent of which coefficient (if any) is out of range.
func validatePublicKey(mode *Mode, pk []byte) error {
	pvb := mode.polyvecBytes()
	a := pk[:pvb]

	var bad uint32
	for i := 0; i < pvb/3; i++ {
		c0 := (uint16(a[3*i]) | (uint16(a[3*i+1]) << 8)) & 0xFFF
		c1 := (uint16(a[3*i+1]) >> 4) | (uint16(a[3*i+2]) << 4)

		// diff is negative (bit 31 set) exactly when the coefficient is a
		// canonical value (< 3329); branchlessly turn that into a 0/1
		// "invalid" flag and OR it into the accumulator so every
		// coefficient is inspected regardless of earlier results.
		diff0 := int32(c0) - int32(q)
		diff1 := int32(c1) - int32(q)
		bad |= 1 ^ (uint32(diff0) >> 31)
		bad |= 1 ^ (uint32(diff1) >> 31)
	}

	if bad != 0 {
		return ErrInvalidPublicKey
	}
	return nil
}

// validateSecretKey implements the FIPS 203 §7.3 "Hash check" for
// decapsulation keys: the length must match the expected size for the
// mode, and the stored hash of the embedded encapsulation key must match
// SHA3-256 recomputed over that embedded key.
func validateSecretKey(mode *Mode, sk []byte) error {
	if len(sk) != mode.SecretKeyBytes() {
		return ErrInvalidSecretKey
	}

	cpaLen := mode.indcpaSecretkeyBytes()
	pkLen := mode.PublicKeyBytes()

	ek := sk[cpaLen : cpaLen+pkLen]
	storedHash := sk[cpaLen+pkLen : cpaLen+pkLen+32]

	var h [32]byte
	hashH(h[:], ek)

	if subtle.ConstantTimeCompare(h[:], storedHash) != 1 {
		return ErrInvalidSecretKey
	}
	return nil
}

// NewKeyPairFromSecretKey reconstructs a KeyPair from a serialized ML-KEM
// decapsulation key, performing the FIPS 203 §7.3 hash check.
func NewKeyPairFromSecretKey(mode *Mode, sk []byte) (*KeyPair, error) {
	if !mode.valid() {
		return nil, ErrInvalidMode
	}
	if err := validateSecretKey(mode, sk); err != nil {
		return nil, err
	}

	cpaLen := mode.indcpaSecretkeyBytes()
	pkLen := mode.PublicKeyBytes()

	seckey := make([]byte, len(sk))
	copy(seckey, sk)

	pubkey := make([]byte, pkLen)
	copy(pubkey, sk[cpaLen:cpaLen+pkLen])

	return &KeyPair{
		mode:   mode,
		pubkey: pubkey,
		seckey: seckey,
	}, nil
}
