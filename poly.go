package kyber

type poly struct {
	coeffs [n]int16
}

func newPoly() *poly {
	return &poly{}
}

// zero overwrites every coefficient with 0. Used to wipe secret
// intermediates from memory once they are no longer needed.
func (p *poly) zero() {
	for i := range p.coeffs {
		p.coeffs[i] = 0
	}
}

func (p *poly) ntt() {
	ntt(&p.coeffs)
	p.reduce()
}

func (p *poly) invnttTomont() {
	invntt(&p.coeffs)
}

func (p *poly) reduce() {
	for i := range p.coeffs {
		p.coeffs[i] = barrettReduce(p.coeffs[i])
	}
}

func (p *poly) add(a, b *poly) {
	for i := 0; i < n; i++ {
		p.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

func (p *poly) sub(a, b *poly) {
	for i := 0; i < n; i++ {
		p.coeffs[i] = a.coeffs[i] - b.coeffs[i]
	}
}

func (p *poly) tomont() {
	f := int64(1<<32) % int64(q32)
	for i := range p.coeffs {
		p.coeffs[i] = montgomeryReduce(int32(p.coeffs[i]) * int32(f))
	}
}

func (p *poly) basemulMontgomery(a, b *poly) {
	for i := 0; i < n/4; i++ {
		basemul(p.coeffs[4*i:4*i+2], a.coeffs[4*i:4*i+2], b.coeffs[4*i:4*i+2], zetas[64+i])
		basemul(p.coeffs[4*i+2:4*i+4], a.coeffs[4*i+2:4*i+4], b.coeffs[4*i+2:4*i+4], -zetas[64+i])
	}
}

func getNoise(seed []byte, nonce byte, eta int) *poly {
	bufLen := eta * n / 4
	buf := make([]byte, bufLen)
	prf(buf, seed, nonce)
	p := newPoly()
	polyCbd(&p.coeffs, buf, eta)
	return p
}

func (p *poly) tobytes(r []byte) {
	for i := 0; i < n/2; i++ {
		// Branchless: coefficients are secret; never branch on their sign.
		c0 := p.coeffs[2*i]
		c0 += (c0 >> 15) & q
		t0 := uint16(c0)
		c1 := p.coeffs[2*i+1]
		c1 += (c1 >> 15) & q
		t1 := uint16(c1)
		r[3*i] = byte(t0)
		r[3*i+1] = byte((t0 >> 8) | (t1 << 4))
		r[3*i+2] = byte(t1 >> 4)
	}
}

func frombytesToPoly(a []byte) *poly {
	p := newPoly()
	for i := 0; i < n/2; i++ {
		p.coeffs[2*i] = int16(uint16(a[3*i])|(uint16(a[3*i+1])<<8)) & 0xFFF
		p.coeffs[2*i+1] = int16((uint16(a[3*i+1]) >> 4) | (uint16(a[3*i+2]) << 4))
	}
	return p
}

func frommsg(msg []byte) *poly {
	p := newPoly()
	for i, b := range msg {
		for j := 0; j < 8; j++ {
			mask := -int16((b >> j) & 1)
			p.coeffs[8*i+j] = mask & ((q + 1) / 2)
		}
	}
	return p
}

// compress1 maps a coefficient u already normalized to [0, q) to a single
// bit, computed without dividing by q (KyberSlash hardening).
func compress1(u uint16) byte {
	t := uint32(u)
	t = (t << 1) + 1665
	t = (t * 80635) >> 28
	t &= 1
	return byte(t)
}

// compress4 maps a coefficient u already normalized to [0, q) to a 4-bit
// value, computed without dividing by q (KyberSlash hardening).
func compress4(u uint16) byte {
	t := uint32(u) << 4
	t += 1665
	t = (t * 80635) >> 28
	t &= 15
	return byte(t)
}

// compress5 maps a coefficient u already normalized to [0, q) to a 5-bit
// value, computed without dividing by q (KyberSlash hardening).
func compress5(u uint16) byte {
	t := uint32(u) << 5
	t += 1664
	t = (t * 40318) >> 27
	t &= 31
	return byte(t)
}

func (p *poly) tomsg(msg []byte) {
	for i := range msg {
		msg[i] = 0
		for j := 0; j < 8; j++ {
			t := p.coeffs[8*i+j]
			t += (t >> 15) & q
			// Division-free (KyberSlash hardening): no `/ q` may appear on secret data.
			val := compress1(uint16(t))
			msg[i] |= val << j
		}
	}
}

func (p *poly) compress(r []byte, mode *Mode) {
	var t [8]byte
	switch mode.polyCompressedBytes {
	case 128:
		for i := 0; i < n/8; i++ {
			for j := 0; j < 8; j++ {
				u := p.coeffs[8*i+j]
				u += (u >> 15) & q
				// Division-free (KyberSlash hardening): no `/ q` may appear on secret data.
				t[j] = compress4(uint16(u))
			}
			r[4*i] = t[0] | (t[1] << 4)
			r[4*i+1] = t[2] | (t[3] << 4)
			r[4*i+2] = t[4] | (t[5] << 4)
			r[4*i+3] = t[6] | (t[7] << 4)
		}
	case 160:
		for i := 0; i < n/8; i++ {
			for j := 0; j < 8; j++ {
				u := p.coeffs[8*i+j]
				u += (u >> 15) & q
				// Division-free (KyberSlash hardening): no `/ q` may appear on secret data.
				t[j] = compress5(uint16(u))
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

func decompressToPoly(a []byte, mode *Mode) *poly {
	p := newPoly()
	switch mode.polyCompressedBytes {
	case 128:
		for i := 0; i < n/2; i++ {
			p.coeffs[2*i] = int16((uint32(a[i]&15)*uint32(q) + 8) >> 4)
			p.coeffs[2*i+1] = int16((uint32(a[i]>>4)*uint32(q) + 8) >> 4)
		}
	case 160:
		var t [8]byte
		for i := 0; i < n/8; i++ {
			t[0] = a[5*i] & 0x1F
			t[1] = (a[5*i] >> 5) | ((a[5*i+1] << 3) & 0x1F)
			t[2] = (a[5*i+1] >> 2) & 0x1F
			t[3] = (a[5*i+1] >> 7) | ((a[5*i+2] << 1) & 0x1F)
			t[4] = (a[5*i+2] >> 4) | ((a[5*i+3] << 4) & 0x1F)
			t[5] = (a[5*i+3] >> 1) & 0x1F
			t[6] = (a[5*i+3] >> 6) | ((a[5*i+4] << 2) & 0x1F)
			t[7] = a[5*i+4] >> 3
			for j, tj := range t {
				p.coeffs[8*i+j] = int16((uint32(tj)*uint32(q) + 16) >> 5)
			}
		}
	default:
		panic("unreachable")
	}
	return p
}
