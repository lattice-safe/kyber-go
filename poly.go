package kyber

type Poly struct {
	coeffs [N]int16
}

func NewPoly() *Poly {
	return &Poly{}
}

func (p *Poly) Ntt() {
	ntt(&p.coeffs)
	p.Reduce()
}

func (p *Poly) InvnttTomont() {
	invntt(&p.coeffs)
}

func (p *Poly) Reduce() {
	for i := range p.coeffs {
		p.coeffs[i] = barrettReduce(p.coeffs[i])
	}
}

func (p *Poly) Add(a, b *Poly) {
	for i := 0; i < N; i++ {
		p.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

func (p *Poly) Sub(a, b *Poly) {
	for i := 0; i < N; i++ {
		p.coeffs[i] = a.coeffs[i] - b.coeffs[i]
	}
}

func (p *Poly) Tomont() {
	f := int64(1<<32) % int64(Q32)
	for i := range p.coeffs {
		p.coeffs[i] = montgomeryReduce(int32(p.coeffs[i]) * int32(f))
	}
}

func (p *Poly) BasemulMontgomery(a, b *Poly) {
	for i := 0; i < N/4; i++ {
		basemul(p.coeffs[4*i:4*i+2], a.coeffs[4*i:4*i+2], b.coeffs[4*i:4*i+2], ZETAS[64+i])
		basemul(p.coeffs[4*i+2:4*i+4], a.coeffs[4*i+2:4*i+4], b.coeffs[4*i+2:4*i+4], -ZETAS[64+i])
	}
}

func GetNoise(seed []byte, nonce byte, eta int) *Poly {
	bufLen := eta * N / 4
	buf := make([]byte, bufLen)
	prf(buf, seed, nonce)
	p := NewPoly()
	polyCbd(&p.coeffs, buf, eta)
	return p
}

func (p *Poly) Tobytes(r []byte) {
	for i := 0; i < N/2; i++ {
		t0 := uint16(p.coeffs[2*i])
		t1 := uint16(p.coeffs[2*i+1])
		if int16(t0) < 0 {
			t0 = uint16(int16(t0) + Q)
		}
		if int16(t1) < 0 {
			t1 = uint16(int16(t1) + Q)
		}
		r[3*i] = byte(t0)
		r[3*i+1] = byte((t0 >> 8) | (t1 << 4))
		r[3*i+2] = byte(t1 >> 4)
	}
}

func FrombytesToPoly(a []byte) *Poly {
	p := NewPoly()
	for i := 0; i < N/2; i++ {
		p.coeffs[2*i] = int16(uint16(a[3*i])|(uint16(a[3*i+1])<<8)) & 0xFFF
		p.coeffs[2*i+1] = int16((uint16(a[3*i+1]) >> 4) | (uint16(a[3*i+2]) << 4))
	}
	return p
}

func Frommsg(msg []byte) *Poly {
	p := NewPoly()
	for i, b := range msg {
		for j := 0; j < 8; j++ {
			mask := -int16((b >> j) & 1)
			p.coeffs[8*i+j] = mask & ((Q + 1) / 2)
		}
	}
	return p
}

func (p *Poly) Tomsg(msg []byte) {
	for i := range msg {
		msg[i] = 0
		for j := 0; j < 8; j++ {
			t := p.coeffs[8*i+j]
			t += (t >> 15) & Q
			val := ((((uint16(t) << 1) + uint16(Q)/2) / uint16(Q)) & 1)
			msg[i] |= byte(val) << j
		}
	}
}

func (p *Poly) Compress(r []byte, mode *Mode) {
	var t [8]byte
	switch mode.PolyCompressedBytes {
	case 128:
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				u := p.coeffs[8*i+j]
				u += (u >> 15) & Q
				t[j] = byte((((uint32(u) << 4) + uint32(Q)/2) / uint32(Q)) & 15)
			}
			r[4*i] = t[0] | (t[1] << 4)
			r[4*i+1] = t[2] | (t[3] << 4)
			r[4*i+2] = t[4] | (t[5] << 4)
			r[4*i+3] = t[6] | (t[7] << 4)
		}
	case 160:
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				u := p.coeffs[8*i+j]
				u += (u >> 15) & Q
				t[j] = byte((((uint32(u) << 5) + uint32(Q)/2) / uint32(Q)) & 31)
			}
			r[5*i] = t[0] | (t[1] << 5)
			r[5*i+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
			r[5*i+2] = (t[3] >> 1) | (t[4] << 4)
			r[5*i+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
			r[5*i+4] = (t[6] >> 2) | (t[7] << 3)
		}
	default:
		panic("unreachable")
	}
}

func DecompressToPoly(a []byte, mode *Mode) *Poly {
	p := NewPoly()
	switch mode.PolyCompressedBytes {
	case 128:
		for i := 0; i < N/2; i++ {
			p.coeffs[2*i] = int16((uint32(a[i]&15)*uint32(Q) + 8) >> 4)
			p.coeffs[2*i+1] = int16((uint32(a[i]>>4)*uint32(Q) + 8) >> 4)
		}
	case 160:
		var t [8]byte
		for i := 0; i < N/8; i++ {
			t[0] = a[5*i] & 0x1F
			t[1] = (a[5*i] >> 5) | ((a[5*i+1] << 3) & 0x1F)
			t[2] = (a[5*i+1] >> 2) & 0x1F
			t[3] = (a[5*i+1] >> 7) | ((a[5*i+2] << 1) & 0x1F)
			t[4] = (a[5*i+2] >> 4) | ((a[5*i+3] << 4) & 0x1F)
			t[5] = (a[5*i+3] >> 1) & 0x1F
			t[6] = (a[5*i+3] >> 6) | ((a[5*i+4] << 2) & 0x1F)
			t[7] = a[5*i+4] >> 3
			for j, tj := range t {
				p.coeffs[8*i+j] = int16((uint32(tj)*uint32(Q) + 16) >> 5)
			}
		}
	default:
		panic("unreachable")
	}
	return p
}
