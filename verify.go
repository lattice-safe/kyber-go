package kyber

import "crypto/subtle"

// verify compares two byte slices in constant time.
// Returns 0 if equal, 1 otherwise.
func verify(a, b []byte) byte {
	// subtle.ConstantTimeCompare returns 1 if equal, 0 if not.
	return 1 - byte(subtle.ConstantTimeCompare(a, b))
}

// cmov conditionally moves x into r if b == 1, no-op if b == 0.
// Constant time.
func cmov(r, x []byte, b byte) {
	mask := byte(-int8(b)) // 0x00 if b==0, 0xFF if b==1
	for i := 0; i < len(r); i++ {
		r[i] ^= mask & (r[i] ^ x[i])
	}
}
