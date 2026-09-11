package kyber

// Polynomial ring degree.
const n = 256

// Modulus.
const q int16 = 3329

// Q as i32 for arithmetic.
const q32 int32 = 3329

// Montgomery constant: Q^{-1} mod 2^16.
const qInv int32 = -3327

// Symbol bytes (hash/seed length).
const symBytes = 32

// SharedSecretSize is the length, in bytes, of the shared secret produced by
// Encapsulate/EncapsulateDerand and recovered by (*KeyPair).Decapsulate.
const SharedSecretSize = 32

// SSBYTES is a compatibility alias for SharedSecretSize.
const SSBYTES = SharedSecretSize

// Packed polynomial bytes (12 bits per coefficient).
const polyBytes = 384

// Mode defines the security level parameters for ML-KEM.
type Mode struct {
	k                      int
	eta1                   int
	eta2                   int
	polyCompressedBytes    int
	polyvecCompressedBytes int
}

var (
	// ML-KEM-512 (NIST Level 1)
	Kyber512 = &Mode{k: 2, eta1: 3, eta2: 2, polyCompressedBytes: 128, polyvecCompressedBytes: 2 * 320}
	// ML-KEM-768 (NIST Level 3)
	Kyber768 = &Mode{k: 3, eta1: 2, eta2: 2, polyCompressedBytes: 128, polyvecCompressedBytes: 3 * 320}
	// ML-KEM-1024 (NIST Level 5)
	Kyber1024 = &Mode{k: 4, eta1: 2, eta2: 2, polyCompressedBytes: 160, polyvecCompressedBytes: 4 * 352}

	// MLKEM512 is an alias for Kyber512, named after the FIPS 203
	// parameter set it implements.
	MLKEM512 = Kyber512
	// MLKEM768 is an alias for Kyber768, named after the FIPS 203
	// parameter set it implements.
	MLKEM768 = Kyber768
	// MLKEM1024 is an alias for Kyber1024, named after the FIPS 203
	// parameter set it implements.
	MLKEM1024 = Kyber1024
)

// valid reports whether m is one of the package-provided parameter sets
// (Kyber512, Kyber768, Kyber1024, and their MLKEM* aliases, which point to
// the same values). It rejects nil and any other *Mode, including a
// zero-value &Mode{}, since such a Mode was never validated against FIPS
// 203 and its size accessors would return nonsensical values.
func (m *Mode) valid() bool {
	return m == Kyber512 || m == Kyber768 || m == Kyber1024
}

// Name returns the FIPS 203 name of the parameter set, e.g. "ML-KEM-768".
// It returns "unknown" for nil or any *Mode that is not one of the
// package-provided parameter sets (which cannot happen for a *Mode obtained
// from this package), rather than panicking.
func (m *Mode) Name() string {
	switch m {
	case Kyber512:
		return "ML-KEM-512"
	case Kyber768:
		return "ML-KEM-768"
	case Kyber1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}

func (m *Mode) polyvecBytes() int {
	return m.k * polyBytes
}

func (m *Mode) indcpaPublickeyBytes() int {
	return m.polyvecBytes() + symBytes
}

func (m *Mode) indcpaSecretkeyBytes() int {
	return m.polyvecBytes()
}

func (m *Mode) indcpaBytes() int {
	return m.polyvecCompressedBytes + m.polyCompressedBytes
}

// PublicKeyBytes returns the encoded length, in bytes, of an encapsulation
// (public) key for this parameter set. It returns 0 for nil or any *Mode
// that is not one of the package-provided parameter sets, rather than
// panicking.
func (m *Mode) PublicKeyBytes() int {
	if !m.valid() {
		return 0
	}
	return m.indcpaPublickeyBytes()
}

// SecretKeyBytes returns the encoded length, in bytes, of a decapsulation
// (secret) key for this parameter set. It returns 0 for nil or any *Mode
// that is not one of the package-provided parameter sets, rather than
// panicking.
func (m *Mode) SecretKeyBytes() int {
	if !m.valid() {
		return 0
	}
	return m.indcpaSecretkeyBytes() + m.indcpaPublickeyBytes() + 2*symBytes
}

// CiphertextBytes returns the encoded length, in bytes, of a ciphertext for
// this parameter set. It returns 0 for nil or any *Mode that is not one of
// the package-provided parameter sets, rather than panicking.
func (m *Mode) CiphertextBytes() int {
	if !m.valid() {
		return 0
	}
	return m.indcpaBytes()
}
