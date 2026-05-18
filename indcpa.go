package kyber

func rejUniform(r []int16, buf []byte) int {
	ctr := 0
	pos := 0
	len_ := len(r)
	buflen := len(buf)
	for ctr < len_ && pos+3 <= buflen {
		val0 := (uint16(buf[pos]) | (uint16(buf[pos+1]) << 8)) & 0xFFF
		val1 := ((uint16(buf[pos+1]) >> 4) | (uint16(buf[pos+2]) << 4)) & 0xFFF
		pos += 3
		if val0 < 3329 {
			r[ctr] = int16(val0)
			ctr++
		}
		if ctr < len_ && val1 < 3329 {
			r[ctr] = int16(val1)
			ctr++
		}
	}
	return ctr
}

const XOF_BLOCKBYTES = 168

func genMatrix(mode *Mode, seed []byte, transposed bool) []*PolyVec {
	k := mode.K
	genNblocks := ((12 * N / 8 * (1 << 12) / 3329) + XOF_BLOCKBYTES) / XOF_BLOCKBYTES

	a := make([]*PolyVec, k)
	for i := 0; i < k; i++ {
		a[i] = NewPolyVec(k)
	}

	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			si, sj := i, j
			if transposed {
				si, sj = j, i
			}
			state := absorbXof(seed, byte(si), byte(sj))
			buf := make([]byte, genNblocks*XOF_BLOCKBYTES)
			state.squeeze(buf)
			ctr := rejUniform(a[i].vec[j].coeffs[:], buf)
			for ctr < N {
				extra := make([]byte, XOF_BLOCKBYTES)
				state.squeeze(extra)
				ctr += rejUniform(a[i].vec[j].coeffs[ctr:], extra)
			}
		}
	}
	return a
}

func indcpaKeypairDerand(mode *Mode, coins []byte) ([]byte, []byte) {
	k := mode.K

	var buf [64]byte
	var seedInput [33]byte
	copy(seedInput[:32], coins)
	seedInput[32] = byte(k)
	hashG(buf[:], seedInput[:])

	publicseed := buf[:32]
	noiseseed := buf[32:64]

	a := genMatrix(mode, publicseed, false)

	var nonce byte = 0
	skpv := NewPolyVec(k)
	e := NewPolyVec(k)

	for i := 0; i < k; i++ {
		skpv.vec[i] = GetNoise(noiseseed, nonce, mode.Eta1)
		nonce++
	}
	for i := 0; i < k; i++ {
		e.vec[i] = GetNoise(noiseseed, nonce, mode.Eta1)
		nonce++
	}

	skpv.Ntt()
	e.Ntt()

	pkpv := NewPolyVec(k)
	for i := 0; i < k; i++ {
		BasemulAccMontgomery(pkpv.vec[i], a[i], skpv)
		pkpv.vec[i].Tomont()
	}
	pkpv.Add(pkpv, e)
	pkpv.Reduce()

	pkBytes := mode.IndcpaPublickeyBytes()
	skBytes := mode.IndcpaSecretkeyBytes()
	pk := make([]byte, pkBytes)
	sk := make([]byte, skBytes)

	skpv.Tobytes(sk)
	pkpv.Tobytes(pk[:mode.PolyvecBytes()])
	copy(pk[mode.PolyvecBytes():], publicseed)

	return pk, sk
}

func indcpaEnc(mode *Mode, ct []byte, msg []byte, pk []byte, coins []byte) {
	k := mode.K
	pvb := mode.PolyvecBytes()

	pkpv := FrombytesToPolyVec(pk[:pvb], k)
	var seed [32]byte
	copy(seed[:], pk[pvb:pvb+32])

	at := genMatrix(mode, seed[:], true)

	var nonce byte = 0
	sp := NewPolyVec(k)
	ep := NewPolyVec(k)

	for i := 0; i < k; i++ {
		sp.vec[i] = GetNoise(coins, nonce, mode.Eta1)
		nonce++
	}
	for i := 0; i < k; i++ {
		ep.vec[i] = GetNoise(coins, nonce, mode.Eta2)
		nonce++
	}
	epp := GetNoise(coins, nonce, mode.Eta2)

	sp.Ntt()

	b := NewPolyVec(k)
	for i := 0; i < k; i++ {
		BasemulAccMontgomery(b.vec[i], at[i], sp)
	}

	v := NewPoly()
	BasemulAccMontgomery(v, pkpv, sp)

	b.InvnttTomont()
	v.InvnttTomont()

	b.Add(b, ep)
	kPoly := Frommsg(msg)
	v2 := NewPoly()
	v2.Add(v, epp)
	v3 := NewPoly()
	v3.Add(v2, kPoly)
	v = v3

	b.Reduce()
	v.Reduce()

	pvcb := mode.PolyvecCompressedBytes
	b.Compress(ct[:pvcb], mode)
	v.Compress(ct[pvcb:], mode)
}

func indcpaDec(mode *Mode, msg []byte, ct []byte, sk []byte) {
	k := mode.K
	pvcb := mode.PolyvecCompressedBytes

	b := DecompressToPolyVec(ct[:pvcb], mode)
	v := DecompressToPoly(ct[pvcb:], mode)

	skpv := FrombytesToPolyVec(sk, k)

	b.Ntt()
	mp := NewPoly()
	BasemulAccMontgomery(mp, skpv, b)
	mp.InvnttTomont()

	result := NewPoly()
	result.Sub(v, mp)
	result.Reduce()

	result.Tomsg(msg)
}
