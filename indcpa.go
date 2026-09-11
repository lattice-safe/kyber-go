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

const xofBlockBytes = 168

func genMatrix(mode *Mode, seed []byte, transposed bool) []*polyVec {
	k := mode.k
	genNblocks := ((12 * n / 8 * (1 << 12) / 3329) + xofBlockBytes) / xofBlockBytes

	a := make([]*polyVec, k)
	for i := 0; i < k; i++ {
		a[i] = newPolyVec(k)
	}

	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			si, sj := j, i
			if transposed {
				si, sj = i, j
			}
			state := absorbXof(seed, byte(si), byte(sj))
			buf := make([]byte, genNblocks*xofBlockBytes)
			state.squeeze(buf)
			ctr := rejUniform(a[i].vec[j].coeffs[:], buf)
			for ctr < n {
				extra := make([]byte, xofBlockBytes)
				state.squeeze(extra)
				ctr += rejUniform(a[i].vec[j].coeffs[ctr:], extra)
			}
		}
	}
	return a
}

func indcpaKeypairDerand(mode *Mode, coins []byte) ([]byte, []byte) {
	k := mode.k

	var buf [64]byte
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()
	var seedInput [33]byte
	defer func() {
		for i := range seedInput {
			seedInput[i] = 0
		}
	}()
	copy(seedInput[:32], coins)
	seedInput[32] = byte(k)
	hashG(buf[:], seedInput[:])

	// publicseed is embedded in the public key and is not secret.
	publicseed := buf[:32]
	noiseseed := buf[32:64]

	a := genMatrix(mode, publicseed, false)

	var nonce byte = 0
	skpv := newPolyVec(k)
	defer skpv.zero()
	e := newPolyVec(k)
	defer e.zero()

	for i := 0; i < k; i++ {
		skpv.vec[i] = getNoise(noiseseed, nonce, mode.eta1)
		nonce++
	}
	for i := 0; i < k; i++ {
		e.vec[i] = getNoise(noiseseed, nonce, mode.eta1)
		nonce++
	}

	skpv.ntt()
	e.ntt()

	pkpv := newPolyVec(k)
	for i := 0; i < k; i++ {
		basemulAccMontgomery(pkpv.vec[i], a[i], skpv)
		pkpv.vec[i].tomont()
	}
	pkpv.add(pkpv, e)
	pkpv.reduce()

	pkBytes := mode.indcpaPublickeyBytes()
	skBytes := mode.indcpaSecretkeyBytes()
	pk := make([]byte, pkBytes)
	sk := make([]byte, skBytes)

	skpv.tobytes(sk)
	pkpv.tobytes(pk[:mode.polyvecBytes()])
	copy(pk[mode.polyvecBytes():], publicseed)

	return pk, sk
}

func indcpaEnc(mode *Mode, ct []byte, msg []byte, pk []byte, coins []byte) {
	k := mode.k
	pvb := mode.polyvecBytes()

	pkpv := frombytesToPolyVec(pk[:pvb], k)
	var seed [32]byte
	copy(seed[:], pk[pvb:pvb+32])

	at := genMatrix(mode, seed[:], true)

	var nonce byte = 0
	sp := newPolyVec(k)
	defer sp.zero()
	ep := newPolyVec(k)
	defer ep.zero()

	for i := 0; i < k; i++ {
		sp.vec[i] = getNoise(coins, nonce, mode.eta1)
		nonce++
	}
	for i := 0; i < k; i++ {
		ep.vec[i] = getNoise(coins, nonce, mode.eta2)
		nonce++
	}
	epp := getNoise(coins, nonce, mode.eta2)
	defer epp.zero()

	sp.ntt()

	b := newPolyVec(k)
	defer b.zero()
	for i := 0; i < k; i++ {
		basemulAccMontgomery(b.vec[i], at[i], sp)
	}

	v := newPoly()
	defer v.zero()
	basemulAccMontgomery(v, pkpv, sp)

	b.invnttTomont()
	v.invnttTomont()

	b.add(b, ep)
	kPoly := frommsg(msg)
	defer kPoly.zero()
	v2 := newPoly()
	defer v2.zero()
	v2.add(v, epp)
	v3 := newPoly()
	defer v3.zero()
	v3.add(v2, kPoly)
	v = v3

	b.reduce()
	v.reduce()

	pvcb := mode.polyvecCompressedBytes
	b.compress(ct[:pvcb], mode)
	v.compress(ct[pvcb:], mode)
}

func indcpaDec(mode *Mode, msg []byte, ct []byte, sk []byte) {
	k := mode.k
	pvcb := mode.polyvecCompressedBytes

	b := decompressToPolyVec(ct[:pvcb], mode)
	defer b.zero()
	v := decompressToPoly(ct[pvcb:], mode)
	defer v.zero()

	skpv := frombytesToPolyVec(sk, k)
	defer skpv.zero()

	b.ntt()
	mp := newPoly()
	defer mp.zero()
	basemulAccMontgomery(mp, skpv, b)
	mp.invnttTomont()

	result := newPoly()
	defer result.zero()
	result.sub(v, mp)
	result.reduce()

	result.tomsg(msg)
}
