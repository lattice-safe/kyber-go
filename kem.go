package kyber

// keypairDerand generates ML-KEM key pair deterministically from 64 bytes of coins.
func keypairDerand(mode *Mode, coins []byte) ([]byte, []byte) {
	pk, skCpa := indcpaKeypairDerand(mode, coins[:32])
	defer func() {
		for i := range skCpa {
			skCpa[i] = 0
		}
	}()

	sk := make([]byte, mode.SecretKeyBytes())
	cpaLen := mode.indcpaSecretkeyBytes()
	pkLen := mode.PublicKeyBytes()

	copy(sk[:cpaLen], skCpa)
	copy(sk[cpaLen:cpaLen+pkLen], pk)

	var hPk [32]byte
	hashH(hPk[:], pk)
	copy(sk[cpaLen+pkLen:cpaLen+pkLen+32], hPk[:])

	copy(sk[cpaLen+pkLen+32:], coins[32:64])

	return pk, sk
}

// encapsDerand encapsulates deterministically, generating shared secret and ciphertext.
func encapsDerand(mode *Mode, pk []byte, coins []byte) ([]byte, []byte) {
	var buf [64]byte
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()
	copy(buf[:32], coins)

	var hPk [32]byte
	hashH(hPk[:], pk)
	copy(buf[32:64], hPk[:])

	var kr [64]byte
	defer func() {
		for i := range kr {
			kr[i] = 0
		}
	}()
	hashG(kr[:], buf[:])

	ct := make([]byte, mode.CiphertextBytes())
	indcpaEnc(mode, ct, coins, pk, kr[32:64])

	ss := make([]byte, SSBYTES)
	copy(ss, kr[:32])
	return ct, ss
}

// decaps recovers shared secret from ciphertext.
func decaps(mode *Mode, ct []byte, sk []byte) []byte {
	cpaLen := mode.indcpaSecretkeyBytes()
	pkLen := mode.PublicKeyBytes()

	pk := sk[cpaLen : cpaLen+pkLen]

	var buf [64]byte
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()
	var m [32]byte
	defer func() {
		for i := range m {
			m[i] = 0
		}
	}()
	indcpaDec(mode, m[:], ct, sk[:cpaLen])
	copy(buf[:32], m[:])

	copy(buf[32:64], sk[cpaLen+pkLen:cpaLen+pkLen+32])

	var kr [64]byte
	defer func() {
		for i := range kr {
			kr[i] = 0
		}
	}()
	hashG(kr[:], buf[:])

	cmp := make([]byte, mode.CiphertextBytes())
	defer func() {
		for i := range cmp {
			cmp[i] = 0
		}
	}()
	indcpaEnc(mode, cmp, buf[:32], pk, kr[32:64])

	fail := verify(ct, cmp)

	z := sk[mode.SecretKeyBytes()-symBytes:]
	var ssReject [32]byte
	defer func() {
		for i := range ssReject {
			ssReject[i] = 0
		}
	}()
	rkprf(ssReject[:], z, ct)

	ss := make([]byte, SSBYTES)
	copy(ss, kr[:32])

	cmov(ss, ssReject[:], fail)
	return ss
}
