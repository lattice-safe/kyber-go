package kyber

// Polynomial ring degree.
const N = 256

// Modulus.
const Q int16 = 3329

// Q as i32 for arithmetic.
const Q32 int32 = 3329

// Montgomery constant: Q^{-1} mod 2^16.
const QINV int32 = -3327

// Symbol bytes (hash/seed length).
const SYMBYTES = 32

// Shared secret bytes.
const SSBYTES = 32

// Packed polynomial bytes (12 bits per coefficient).
const POLYBYTES = 384

// Mode defines the security level parameters for ML-KEM.
type Mode struct {
	K                      int
	Eta1                   int
	Eta2                   int
	PolyCompressedBytes    int
	PolyvecCompressedBytes int
}

var (
	// ML-KEM-512 (NIST Level 1)
	Kyber512 = &Mode{K: 2, Eta1: 3, Eta2: 2, PolyCompressedBytes: 128, PolyvecCompressedBytes: 2 * 320}
	// ML-KEM-768 (NIST Level 3)
	Kyber768 = &Mode{K: 3, Eta1: 2, Eta2: 2, PolyCompressedBytes: 128, PolyvecCompressedBytes: 3 * 320}
	// ML-KEM-1024 (NIST Level 5)
	Kyber1024 = &Mode{K: 4, Eta1: 2, Eta2: 2, PolyCompressedBytes: 160, PolyvecCompressedBytes: 4 * 352}
)

func (m *Mode) PolyvecBytes() int {
	return m.K * POLYBYTES
}

func (m *Mode) IndcpaPublickeyBytes() int {
	return m.PolyvecBytes() + SYMBYTES
}

func (m *Mode) IndcpaSecretkeyBytes() int {
	return m.PolyvecBytes()
}

func (m *Mode) IndcpaBytes() int {
	return m.PolyvecCompressedBytes + m.PolyCompressedBytes
}

func (m *Mode) PublicKeyBytes() int {
	return m.IndcpaPublickeyBytes()
}

func (m *Mode) SecretKeyBytes() int {
	return m.IndcpaSecretkeyBytes() + m.IndcpaPublickeyBytes() + 2*SYMBYTES
}

func (m *Mode) CiphertextBytes() int {
	return m.IndcpaBytes()
}
