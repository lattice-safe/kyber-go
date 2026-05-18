package kyber

import "encoding/binary"

func load32Le(x []byte) uint32 {
	return binary.LittleEndian.Uint32(x)
}

func load24Le(x []byte) uint32 {
	return uint32(x[0]) | (uint32(x[1]) << 8) | (uint32(x[2]) << 16)
}

func cbd2(r *[N]int16, buf []byte) {
	for i := 0; i < N/8; i++ {
		t := load32Le(buf[4*i:])
		d := (t & 0x55555555) + ((t >> 1) & 0x55555555)
		for j := 0; j < 8; j++ {
			a := int16((d >> (4 * j)) & 0x3)
			b := int16((d >> (4*j + 2)) & 0x3)
			r[8*i+j] = a - b
		}
	}
}

func cbd3(r *[N]int16, buf []byte) {
	for i := 0; i < N/4; i++ {
		t := load24Le(buf[3*i:])
		d := (t & 0x00249249) + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249)
		for j := 0; j < 4; j++ {
			a := int16((d >> (6 * j)) & 0x7)
			b := int16((d >> (6*j + 3)) & 0x7)
			r[4*i+j] = a - b
		}
	}
}

func polyCbd(r *[N]int16, buf []byte, eta int) {
	if eta == 2 {
		cbd2(r, buf)
	} else if eta == 3 {
		cbd3(r, buf)
	} else {
		panic("unsupported eta")
	}
}
