package kyber

import (
	"bytes"
	"testing"
)

func TestKATMLKEM512(t *testing.T) {
	mode := Kyber512

	var coinsKeyGen [64]byte
	for i := range coinsKeyGen {
		coinsKeyGen[i] = byte(i + 1)
	}

	kp, err := GenerateKeyPairDerand(mode, coinsKeyGen[:])
	if err != nil {
		t.Fatalf("GenerateKeyPairDerand failed: %v", err)
	}

	if len(kp.PublicKey()) != mode.PublicKeyBytes() {
		t.Fatalf("expected pk length %d, got %d", mode.PublicKeyBytes(), len(kp.PublicKey()))
	}
	if len(kp.SecretKey()) != mode.SecretKeyBytes() {
		t.Fatalf("expected sk length %d, got %d", mode.SecretKeyBytes(), len(kp.SecretKey()))
	}

	var coinsEncaps [32]byte
	for i := range coinsEncaps {
		coinsEncaps[i] = byte(i + 65)
	}

	ct, ssEncaps, err := EncapsulateDerand(mode, kp.PublicKey(), coinsEncaps[:])
	if err != nil {
		t.Fatalf("EncapsulateDerand failed: %v", err)
	}

	if len(ct) != mode.CiphertextBytes() {
		t.Fatalf("expected ct length %d, got %d", mode.CiphertextBytes(), len(ct))
	}
	if len(ssEncaps) != SSBYTES {
		t.Fatalf("expected ss length %d, got %d", SSBYTES, len(ssEncaps))
	}

	ssDecaps, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ssEncaps, ssDecaps) {
		t.Fatalf("ML-KEM-512 KAT failed: shared secrets do not match")
	}

	// Implicit Rejection test
	ctCorrupted := make([]byte, len(ct))
	copy(ctCorrupted, ct)
	ctCorrupted[0] ^= 0xFF

	ssRejected, err := kp.Decapsulate(ctCorrupted)
	if err != nil {
		t.Fatalf("Decapsulate on corrupted ct failed: %v", err)
	}
	if bytes.Equal(ssEncaps, ssRejected) {
		t.Fatalf("Implicit rejection failed: corrupted ct yielded valid shared secret")
	}
}

func TestKATMLKEM768(t *testing.T) {
	mode := Kyber768

	var coinsKeyGen [64]byte
	for i := range coinsKeyGen {
		coinsKeyGen[i] = byte(i + 10)
	}

	kp, err := GenerateKeyPairDerand(mode, coinsKeyGen[:])
	if err != nil {
		t.Fatalf("GenerateKeyPairDerand failed: %v", err)
	}

	if len(kp.PublicKey()) != mode.PublicKeyBytes() {
		t.Fatalf("expected pk length %d, got %d", mode.PublicKeyBytes(), len(kp.PublicKey()))
	}
	if len(kp.SecretKey()) != mode.SecretKeyBytes() {
		t.Fatalf("expected sk length %d, got %d", mode.SecretKeyBytes(), len(kp.SecretKey()))
	}

	var coinsEncaps [32]byte
	for i := range coinsEncaps {
		coinsEncaps[i] = byte(i + 80)
	}

	ct, ssEncaps, err := EncapsulateDerand(mode, kp.PublicKey(), coinsEncaps[:])
	if err != nil {
		t.Fatalf("EncapsulateDerand failed: %v", err)
	}

	ssDecaps, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ssEncaps, ssDecaps) {
		t.Fatalf("ML-KEM-768 KAT failed: shared secrets do not match")
	}

	// Implicit Rejection test
	ctCorrupted := make([]byte, len(ct))
	copy(ctCorrupted, ct)
	ctCorrupted[len(ctCorrupted)-1] ^= 0x01

	ssRejected, err := kp.Decapsulate(ctCorrupted)
	if err != nil {
		t.Fatalf("Decapsulate on corrupted ct failed: %v", err)
	}
	if bytes.Equal(ssEncaps, ssRejected) {
		t.Fatalf("Implicit rejection failed: corrupted ct yielded valid shared secret")
	}
}

func TestKATMLKEM1024(t *testing.T) {
	mode := Kyber1024

	var coinsKeyGen [64]byte
	for i := range coinsKeyGen {
		coinsKeyGen[i] = byte(i + 20)
	}

	kp, err := GenerateKeyPairDerand(mode, coinsKeyGen[:])
	if err != nil {
		t.Fatalf("GenerateKeyPairDerand failed: %v", err)
	}

	if len(kp.PublicKey()) != mode.PublicKeyBytes() {
		t.Fatalf("expected pk length %d, got %d", mode.PublicKeyBytes(), len(kp.PublicKey()))
	}
	if len(kp.SecretKey()) != mode.SecretKeyBytes() {
		t.Fatalf("expected sk length %d, got %d", mode.SecretKeyBytes(), len(kp.SecretKey()))
	}

	var coinsEncaps [32]byte
	for i := range coinsEncaps {
		coinsEncaps[i] = byte(i + 100)
	}

	ct, ssEncaps, err := EncapsulateDerand(mode, kp.PublicKey(), coinsEncaps[:])
	if err != nil {
		t.Fatalf("EncapsulateDerand failed: %v", err)
	}

	ssDecaps, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ssEncaps, ssDecaps) {
		t.Fatalf("ML-KEM-1024 KAT failed: shared secrets do not match")
	}

	// Implicit Rejection test
	ctCorrupted := make([]byte, len(ct))
	copy(ctCorrupted, ct)
	ctCorrupted[len(ctCorrupted)/2] ^= 0xAA

	ssRejected, err := kp.Decapsulate(ctCorrupted)
	if err != nil {
		t.Fatalf("Decapsulate on corrupted ct failed: %v", err)
	}
	if bytes.Equal(ssEncaps, ssRejected) {
		t.Fatalf("Implicit rejection failed: corrupted ct yielded valid shared secret")
	}
}
