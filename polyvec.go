package kyber

type polyVec struct {
	vec []*poly
}

func newPolyVec(k int) *polyVec {
	vec := make([]*poly, k)
	for i := range vec {
		vec[i] = newPoly()
	}
	return &polyVec{vec: vec}
}

// zero overwrites every coefficient of every polynomial in the vector with
// 0. Used to wipe secret intermediates from memory once they are no longer
// needed.
func (pv *polyVec) zero() {
	for _, p := range pv.vec {
		p.zero()
	}
}

func (pv *polyVec) ntt() {
	for _, p := range pv.vec {
		p.ntt()
	}
}

func (pv *polyVec) invnttTomont() {
	for _, p := range pv.vec {
		p.invnttTomont()
	}
}

func (pv *polyVec) reduce() {
	for _, p := range pv.vec {
		p.reduce()
	}
}

func (pv *polyVec) add(a, b *polyVec) {
	for i := range pv.vec {
		pv.vec[i].add(a.vec[i], b.vec[i])
	}
}

func basemulAccMontgomery(r *poly, a, b *polyVec) {
	t := newPoly()
	r.basemulMontgomery(a.vec[0], b.vec[0])
	for i := 1; i < len(a.vec); i++ {
		t.basemulMontgomery(a.vec[i], b.vec[i])
		for j := 0; j < n; j++ {
			r.coeffs[j] += t.coeffs[j]
		}
	}
	r.reduce()
}

func (pv *polyVec) tobytes(r []byte) {
	for i := range pv.vec {
		pv.vec[i].tobytes(r[i*polyBytes : (i+1)*polyBytes])
	}
}

func frombytesToPolyVec(a []byte, k int) *polyVec {
	pv := newPolyVec(k)
	for i := 0; i < k; i++ {
		pv.vec[i] = frombytesToPoly(a[i*polyBytes : (i+1)*polyBytes])
	}
	return pv
}

// compress10 maps a coefficient u already normalized to [0, q) to a 10-bit
// value, computed without dividing by q (KyberSlash hardening).
func compress10(u uint16) uint16 {
	t := uint64(u) << 10
	t += 1665
	t = (t * 1290167) >> 32
	t &= 0x3FF
	return uint16(t)
}

// compress11 maps a coefficient u already normalized to [0, q) to an 11-bit
// value, computed without dividing by q (KyberSlash hardening).
func compress11(u uint16) uint16 {
	t := uint64(u) << 11
	t += 1664
	t = (t * 645084) >> 31
	t &= 0x7FF
	return uint16(t)
}

func (pv *polyVec) compress(r []byte, mode *Mode) {
	k := mode.k
	// Switch on mode.polyvecCompressedBytes directly (not
	// polyvecCompressedBytes/k): avoids any DIV instruction on this path,
	// while still panicking on a malformed Mode the same way the old
	// polyvecCompressedBytes/k switch did.
	switch mode.polyvecCompressedBytes {
	case 1408: // k=4, 352 bytes/poly
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < n/8; j++ {
				var t [8]uint16
				for m := 0; m < 8; m++ {
					u := pv.vec[i].coeffs[8*j+m]
					u += (u >> 15) & q
					// Division-free (KyberSlash hardening): no `/ q` may appear on secret data.
					t[m] = compress11(uint16(u))
				}
				r[idx] = byte(t[0])
				r[idx+1] = byte((t[0] >> 8) | (t[1] << 3))
				r[idx+2] = byte((t[1] >> 5) | (t[2] << 6))
				r[idx+3] = byte(t[2] >> 2)
				r[idx+4] = byte((t[2] >> 10) | (t[3] << 1))
				r[idx+5] = byte((t[3] >> 7) | (t[4] << 4))
				r[idx+6] = byte((t[4] >> 4) | (t[5] << 7))
				r[idx+7] = byte(t[5] >> 1)
				r[idx+8] = byte((t[5] >> 9) | (t[6] << 2))
				r[idx+9] = byte((t[6] >> 6) | (t[7] << 5))
				r[idx+10] = byte(t[7] >> 3)
				idx += 11
			}
		}
	case 640, 960: // k=2 or k=3, 320 bytes/poly
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < n/4; j++ {
				var t [4]uint16
				for m := 0; m < 4; m++ {
					u := pv.vec[i].coeffs[4*j+m]
					u += (u >> 15) & q
					// Division-free (KyberSlash hardening): no `/ q` may appear on secret data.
					t[m] = compress10(uint16(u))
				}
				r[idx] = byte(t[0])
				r[idx+1] = byte((t[0] >> 8) | (t[1] << 2))
				r[idx+2] = byte((t[1] >> 6) | (t[2] << 4))
				r[idx+3] = byte((t[2] >> 4) | (t[3] << 6))
				r[idx+4] = byte(t[3] >> 2)
				idx += 5
			}
		}
	default:
		panic("unreachable")
	}
}

func decompressToPolyVec(a []byte, mode *Mode) *polyVec {
	k := mode.k
	pv := newPolyVec(k)
	// See the matching comment in compress for why this switches on
	// polyvecCompressedBytes directly rather than polyvecCompressedBytes/k.
	switch mode.polyvecCompressedBytes {
	case 1408: // k=4, 352 bytes/poly
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < n/8; j++ {
				var t [8]uint16
				t[0] = (uint16(a[idx]) | (uint16(a[idx+1]) << 8)) & 0x7FF
				t[1] = ((uint16(a[idx+1]) >> 3) | (uint16(a[idx+2]) << 5)) & 0x7FF
				t[2] = ((uint16(a[idx+2]) >> 6) | (uint16(a[idx+3]) << 2) | (uint16(a[idx+4]) << 10)) & 0x7FF
				t[3] = ((uint16(a[idx+4]) >> 1) | (uint16(a[idx+5]) << 7)) & 0x7FF
				t[4] = ((uint16(a[idx+5]) >> 4) | (uint16(a[idx+6]) << 4)) & 0x7FF
				t[5] = ((uint16(a[idx+6]) >> 7) | (uint16(a[idx+7]) << 1) | (uint16(a[idx+8]) << 9)) & 0x7FF
				t[6] = ((uint16(a[idx+8]) >> 2) | (uint16(a[idx+9]) << 6)) & 0x7FF
				t[7] = ((uint16(a[idx+9]) >> 5) | (uint16(a[idx+10]) << 3)) & 0x7FF
				idx += 11
				for m, tm := range t {
					pv.vec[i].coeffs[8*j+m] = int16((uint32(tm)*uint32(q) + 1024) >> 11)
				}
			}
		}
	case 640, 960: // k=2 or k=3, 320 bytes/poly
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < n/4; j++ {
				var t [4]uint16
				t[0] = (uint16(a[idx]) | (uint16(a[idx+1]) << 8)) & 0x3FF
				t[1] = ((uint16(a[idx+1]) >> 2) | (uint16(a[idx+2]) << 6)) & 0x3FF
				t[2] = ((uint16(a[idx+2]) >> 4) | (uint16(a[idx+3]) << 4)) & 0x3FF
				t[3] = ((uint16(a[idx+3]) >> 6) | (uint16(a[idx+4]) << 2)) & 0x3FF
				idx += 5
				for m, tm := range t {
					pv.vec[i].coeffs[4*j+m] = int16((uint32(tm)*uint32(q) + 512) >> 10)
				}
			}
		}
	default:
		panic("unreachable")
	}
	return pv
}
