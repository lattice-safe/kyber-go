package kyber

import (
	"bytes"
	"testing"
)

func testRoundtrip(t *testing.T, mode *Mode, modeName string) {
	// 1. Generate key pair
	kp, err := GenerateKeyPair(mode)
	if err != nil {
		t.Fatalf("[%s] Failed to generate keypair: %v", modeName, err)
	}

	// 2. Encapsulate
	ct, ss, err := Encapsulate(mode, kp.PublicKey())
	if err != nil {
		t.Fatalf("[%s] Failed to encapsulate: %v", modeName, err)
	}

	// 3. Decapsulate
	ssDec, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatalf("[%s] Failed to decapsulate: %v", modeName, err)
	}

	if !bytes.Equal(ss, ssDec) {
		t.Errorf("[%s] Shared secrets do not match!", modeName)
	}
}

func TestKyberRoundtrips(t *testing.T) {
	testRoundtrip(t, Kyber512, "ML-KEM-512")
	testRoundtrip(t, Kyber768, "ML-KEM-768")
	testRoundtrip(t, Kyber1024, "ML-KEM-1024")
}

func TestDeterministic(t *testing.T) {
	var coins1 [64]byte
	for i := range coins1 {
		coins1[i] = byte(i)
	}

	kp1, _ := GenerateKeyPairDerand(Kyber768, coins1[:])
	kp2, _ := GenerateKeyPairDerand(Kyber768, coins1[:])

	if !bytes.Equal(kp1.PublicKey(), kp2.PublicKey()) {
		t.Fatal("Deterministic keygen failed")
	}

	var coinsEnc [32]byte
	for i := range coinsEnc {
		coinsEnc[i] = byte(i + 100)
	}

	ct1, ss1, _ := EncapsulateDerand(Kyber768, kp1.PublicKey(), coinsEnc[:])
	ct2, ss2, _ := EncapsulateDerand(Kyber768, kp2.PublicKey(), coinsEnc[:])

	if !bytes.Equal(ct1, ct2) || !bytes.Equal(ss1, ss2) {
		t.Fatal("Deterministic encaps failed")
	}
}
