package kyber

import (
	"golang.org/x/crypto/sha3"
)

// hashH computes SHA3-256 hash.
func hashH(out []byte, input []byte) {
	h := sha3.New256()
	h.Write(input)
	h.Sum(out[:0])
}

// hashG computes SHA3-512 hash.
func hashG(out []byte, input []byte) {
	h := sha3.New512()
	h.Write(input)
	h.Sum(out[:0])
}

// shake256 absorbs input and squeezes output using SHAKE-256.
func shake256(out []byte, input []byte) {
	h := sha3.NewShake256()
	h.Write(input)
	h.Read(out)
}

// prf computes SHAKE-256(key || nonce).
func prf(out []byte, key []byte, nonce byte) {
	h := sha3.NewShake256()
	h.Write(key)
	h.Write([]byte{nonce})
	h.Read(out)
}

// rkprf computes SHAKE-256(key || ct) for implicit rejection.
func rkprf(out []byte, key []byte, ct []byte) {
	h := sha3.NewShake256()
	h.Write(key)
	h.Write(ct)
	h.Read(out)
}

// XofState represents the state for matrix generation.
type XofState struct {
	h sha3.ShakeHash
}

// absorbXof absorbs seed || i || j for matrix generation.
func absorbXof(seed []byte, i, j byte) *XofState {
	h := sha3.NewShake128()
	h.Write(seed)
	h.Write([]byte{i, j})
	return &XofState{
		h: h,
	}
}

// squeeze squeezes bytes from the XOF state.
func (x *XofState) squeeze(out []byte) {
	x.h.Read(out)
}
