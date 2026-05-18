package kyber

// KeypairDerand generates ML-KEM key pair deterministically from 64 bytes of coins.
func KeypairDerand(mode *Mode, coins []byte) ([]byte, []byte) {
	pk, skCpa := indcpaKeypairDerand(mode, coins[:32])

	sk := make([]byte, mode.SecretKeyBytes())
	cpaLen := mode.IndcpaSecretkeyBytes()
	pkLen := mode.PublicKeyBytes()

	copy(sk[:cpaLen], skCpa)
	copy(sk[cpaLen:cpaLen+pkLen], pk)

	var hPk [32]byte
	hashH(hPk[:], pk)
	copy(sk[cpaLen+pkLen:cpaLen+pkLen+32], hPk[:])

	copy(sk[cpaLen+pkLen+32:], coins[32:64])

	return pk, sk
}

// EncapsDerand encapsulates deterministically, generating shared secret and ciphertext.
func EncapsDerand(mode *Mode, pk []byte, coins []byte) ([]byte, []byte) {
	var buf [64]byte
	copy(buf[:32], coins)

	var hPk [32]byte
	hashH(hPk[:], pk)
	copy(buf[32:64], hPk[:])

	var kr [64]byte
	hashG(kr[:], buf[:])

	ct := make([]byte, mode.CiphertextBytes())
	indcpaEnc(mode, ct, coins, pk, kr[32:64])

	ss := make([]byte, SSBYTES)
	copy(ss, kr[:32])
	return ct, ss
}

// Decaps recovers shared secret from ciphertext.
func Decaps(mode *Mode, ct []byte, sk []byte) []byte {
	cpaLen := mode.IndcpaSecretkeyBytes()
	pkLen := mode.PublicKeyBytes()

	pk := sk[cpaLen : cpaLen+pkLen]

	var buf [64]byte
	var m [32]byte
	indcpaDec(mode, m[:], ct, sk[:cpaLen])
	copy(buf[:32], m[:])

	copy(buf[32:64], sk[cpaLen+pkLen:cpaLen+pkLen+32])

	var kr [64]byte
	hashG(kr[:], buf[:])

	cmp := make([]byte, mode.CiphertextBytes())
	indcpaEnc(mode, cmp, buf[:32], pk, kr[32:64])

	fail := verify(ct, cmp)

	z := sk[mode.SecretKeyBytes()-SYMBYTES:]
	var ssReject [32]byte
	rkprf(ssReject[:], z, ct)

	ss := make([]byte, SSBYTES)
	copy(ss, kr[:32])

	cmov(ss, ssReject[:], fail)
	return ss
}
