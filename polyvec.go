package kyber

type PolyVec struct {
	vec []*Poly
}

func NewPolyVec(k int) *PolyVec {
	vec := make([]*Poly, k)
	for i := range vec {
		vec[i] = NewPoly()
	}
	return &PolyVec{vec: vec}
}

func (pv *PolyVec) Ntt() {
	for _, p := range pv.vec {
		p.Ntt()
	}
}

func (pv *PolyVec) InvnttTomont() {
	for _, p := range pv.vec {
		p.InvnttTomont()
	}
}

func (pv *PolyVec) Reduce() {
	for _, p := range pv.vec {
		p.Reduce()
	}
}

func (pv *PolyVec) Add(a, b *PolyVec) {
	for i := range pv.vec {
		pv.vec[i].Add(a.vec[i], b.vec[i])
	}
}

func BasemulAccMontgomery(r *Poly, a, b *PolyVec) {
	t := NewPoly()
	r.BasemulMontgomery(a.vec[0], b.vec[0])
	for i := 1; i < len(a.vec); i++ {
		t.BasemulMontgomery(a.vec[i], b.vec[i])
		for j := 0; j < N; j++ {
			r.coeffs[j] += t.coeffs[j]
		}
	}
	r.Reduce()
}

func (pv *PolyVec) Tobytes(r []byte) {
	for i := range pv.vec {
		pv.vec[i].Tobytes(r[i*POLYBYTES : (i+1)*POLYBYTES])
	}
}

func FrombytesToPolyVec(a []byte, k int) *PolyVec {
	pv := NewPolyVec(k)
	for i := 0; i < k; i++ {
		pv.vec[i] = FrombytesToPoly(a[i*POLYBYTES : (i+1)*POLYBYTES])
	}
	return pv
}

func (pv *PolyVec) Compress(r []byte, mode *Mode) {
	k := mode.K
	switch mode.PolyvecCompressedBytes / k {
	case 352:
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < N/8; j++ {
				var t [8]uint16
				for m := 0; m < 8; m++ {
					u := pv.vec[i].coeffs[8*j+m]
					u += (u >> 15) & Q
					t[m] = uint16((((uint32(u) << 11) + uint32(Q)/2) / uint32(Q)) & 0x7FF)
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
	case 320:
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < N/4; j++ {
				var t [4]uint16
				for m := 0; m < 4; m++ {
					u := pv.vec[i].coeffs[4*j+m]
					u += (u >> 15) & Q
					t[m] = uint16((((uint32(u) << 10) + uint32(Q)/2) / uint32(Q)) & 0x3FF)
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

func DecompressToPolyVec(a []byte, mode *Mode) *PolyVec {
	k := mode.K
	pv := NewPolyVec(k)
	switch mode.PolyvecCompressedBytes / k {
	case 352:
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < N/8; j++ {
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
					pv.vec[i].coeffs[8*j+m] = int16((uint32(tm)*uint32(Q) + 1024) >> 11)
				}
			}
		}
	case 320:
		idx := 0
		for i := 0; i < k; i++ {
			for j := 0; j < N/4; j++ {
				var t [4]uint16
				t[0] = (uint16(a[idx]) | (uint16(a[idx+1]) << 8)) & 0x3FF
				t[1] = ((uint16(a[idx+1]) >> 2) | (uint16(a[idx+2]) << 6)) & 0x3FF
				t[2] = ((uint16(a[idx+2]) >> 4) | (uint16(a[idx+3]) << 4)) & 0x3FF
				t[3] = ((uint16(a[idx+3]) >> 6) | (uint16(a[idx+4]) << 2)) & 0x3FF
				idx += 5
				for m, tm := range t {
					pv.vec[i].coeffs[4*j+m] = int16((uint32(tm)*uint32(Q) + 512) >> 10)
				}
			}
		}
	default:
		panic("unreachable")
	}
	return pv
}
