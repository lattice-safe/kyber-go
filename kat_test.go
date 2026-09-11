package kyber

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"testing"
)

// TestRoundtripFixedSeed512 exercises GenerateKeyPairDerand,
// EncapsulateDerand and Decapsulate end-to-end using a fixed (non-random)
// 64-byte coin string for key generation and a fixed 32-byte coin string
// for encapsulation.
//
// NOTE: despite the historical "KAT" name this file used to carry, this is
// NOT a Known-Answer Test: it never compares any intermediate or final
// value against an externally produced fixed answer. It only checks
// internal self-consistency (decapsulation recovers what encapsulation
// produced, and implicit rejection kicks in for a corrupted ciphertext)
// using a deterministic, but otherwise arbitrary, seed. Real fixed-vector
// KATs live in TestKAT (checked against Go's standard library
// crypto/mlkem) and TestKAT512CrossImplementationHash /
// TestKAT768CrossImplementationHash / TestKAT1024CrossImplementationHash
// (checked against lattice-safe/kyber-rs) below.
func TestRoundtripFixedSeed512(t *testing.T) {
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
		t.Fatalf("ML-KEM-512 roundtrip failed: shared secrets do not match")
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

// TestRoundtripFixedSeed768 is the ML-KEM-768 analogue of
// TestRoundtripFixedSeed512; see its comment for what this test does (and
// does not) verify.
func TestRoundtripFixedSeed768(t *testing.T) {
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
		t.Fatalf("ML-KEM-768 roundtrip failed: shared secrets do not match")
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

// TestRoundtripFixedSeed1024 is the ML-KEM-1024 analogue of
// TestRoundtripFixedSeed512; see its comment for what this test does (and
// does not) verify.
func TestRoundtripFixedSeed1024(t *testing.T) {
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
		t.Fatalf("ML-KEM-1024 roundtrip failed: shared secrets do not match")
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

// katVector holds one fixed Known-Answer-Test vector produced by an
// independent FIPS 203 implementation (Go's standard library
// crypto/mlkem). See kat_vectors_test.go for the hex constants and exactly
// how they were generated.
type katVector struct {
	name string
	mode *Mode
	seed string // 64-byte hex: d (32 bytes) || z (32 bytes)
	ek   string // full encapsulation key hex
	ct   string // ciphertext hex
	ss   string // shared secret hex
}

// TestKAT checks this package against fixed vectors produced by Go's
// standard library crypto/mlkem, an independent FIPS 203 implementation,
// for the two parameter sets it supports (ML-KEM-768 and ML-KEM-1024).
// crypto/mlkem does not implement ML-KEM-512; that parameter set is
// instead covered by TestKAT512CrossImplementationHash below.
//
// For each vector this test checks:
//   - GenerateKeyPairDerand(mode, seed) yields a public key byte-equal to
//     the vector's ek.
//   - The secret key's embedded encapsulation key equals ek.
//   - The last 32 bytes of the secret key (z) equal seed[32:64].
//   - kp.Decapsulate(ct) equals ss.
//   - NewKeyPairFromSecretKey(mode, kp.SecretKey()) followed by
//     Decapsulate(ct) also equals ss (round-tripping the secret key
//     through its serialized form).
func TestKAT(t *testing.T) {
	vectors := []katVector{
		{"ML-KEM-768/0", Kyber768, kat768Seed0, kat768EK0, kat768CT0, kat768SS0},
		{"ML-KEM-768/1", Kyber768, kat768Seed1, kat768EK1, kat768CT1, kat768SS1},
		{"ML-KEM-1024/0", Kyber1024, kat1024Seed0, kat1024EK0, kat1024CT0, kat1024SS0},
		{"ML-KEM-1024/1", Kyber1024, kat1024Seed1, kat1024EK1, kat1024CT1, kat1024SS1},
	}

	for _, v := range vectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			seed, err := hex.DecodeString(v.seed)
			if err != nil {
				t.Fatalf("decode seed: %v", err)
			}
			wantEK, err := hex.DecodeString(v.ek)
			if err != nil {
				t.Fatalf("decode ek: %v", err)
			}
			wantCT, err := hex.DecodeString(v.ct)
			if err != nil {
				t.Fatalf("decode ct: %v", err)
			}
			wantSS, err := hex.DecodeString(v.ss)
			if err != nil {
				t.Fatalf("decode ss: %v", err)
			}
			if len(seed) != 64 {
				t.Fatalf("seed must be 64 bytes, got %d", len(seed))
			}

			kp, err := GenerateKeyPairDerand(v.mode, seed)
			if err != nil {
				t.Fatalf("GenerateKeyPairDerand failed: %v", err)
			}

			if !bytes.Equal(kp.PublicKey(), wantEK) {
				t.Fatalf("public key mismatch:\n got:  %x\n want: %x", kp.PublicKey(), wantEK)
			}

			sk := kp.SecretKey()
			cpaLen := v.mode.indcpaSecretkeyBytes()
			pkLen := v.mode.PublicKeyBytes()
			embeddedEK := sk[cpaLen : cpaLen+pkLen]
			if !bytes.Equal(embeddedEK, wantEK) {
				t.Fatalf("secret key's embedded encapsulation key mismatch:\n got:  %x\n want: %x", embeddedEK, wantEK)
			}

			z := sk[len(sk)-symBytes:]
			if !bytes.Equal(z, seed[32:]) {
				t.Fatalf("secret key's z mismatch:\n got:  %x\n want: %x", z, seed[32:])
			}

			ss, err := kp.Decapsulate(wantCT)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}
			if !bytes.Equal(ss, wantSS) {
				t.Fatalf("shared secret mismatch:\n got:  %x\n want: %x", ss, wantSS)
			}

			// Round-trip the secret key through its serialized form and
			// confirm decapsulation still recovers the same shared secret.
			kp2, err := NewKeyPairFromSecretKey(v.mode, kp.SecretKey())
			if err != nil {
				t.Fatalf("NewKeyPairFromSecretKey failed: %v", err)
			}
			ss2, err := kp2.Decapsulate(wantCT)
			if err != nil {
				t.Fatalf("Decapsulate (after NewKeyPairFromSecretKey) failed: %v", err)
			}
			if !bytes.Equal(ss2, wantSS) {
				t.Fatalf("shared secret mismatch after NewKeyPairFromSecretKey:\n got:  %x\n want: %x", ss2, wantSS)
			}
		})
	}
}

// crossImplKATHash reproduces, byte-for-byte, the deterministic hash-chain
// procedure implemented by lattice-safe/kyber-rs in
// tests/kat_vectors.rs::run_kat: a SHA3-256 seed chain drives 100
// iterations of keypair/encaps/decaps, and every produced value (public
// key, secret key, ciphertext, encapsulated shared secret, decapsulated
// shared secret) is fed into a single running SHA3-256 hash. The final
// digest is deterministic and implementation-agnostic *only* if both
// implementations compute identical bytes at every step, which makes it a
// strong cross-implementation consistency check.
//
// This is NOT a NIST KAT: the golden digests it is compared against
// (KAT512Hash / KAT768Hash / KAT1024Hash in the tests calling this
// function) were themselves computed by lattice-safe/kyber-rs, not by
// NIST. It exists specifically to cover ML-KEM-512, which Go's standard
// library crypto/mlkem does not implement and which therefore cannot be
// checked by TestKAT above.
func crossImplKATHash(t *testing.T, mode *Mode) string {
	t.Helper()

	deriveSeed := func(state *[32]byte, extra byte) {
		h := sha3.New256()
		h.Write(state[:])
		h.Write([]byte{extra})
		h.Sum(state[:0])
	}

	hasher := sha3.New256()
	var seed [32]byte

	for i := 0; i < 100; i++ {
		ib := byte(i)

		var coins [64]byte
		deriveSeed(&seed, ib)
		copy(coins[:32], seed[:])
		deriveSeed(&seed, ib+100)
		copy(coins[32:], seed[:])

		pk, sk := keypairDerand(mode, coins[:])
		hasher.Write(pk)
		hasher.Write(sk)

		deriveSeed(&seed, ib+200)
		var encCoins [32]byte
		copy(encCoins[:], seed[:])

		ct, ssEnc := encapsDerand(mode, pk, encCoins[:])
		hasher.Write(ct)
		hasher.Write(ssEnc)

		ssDec := decaps(mode, ct, sk)
		hasher.Write(ssDec)

		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatalf("cross-impl KAT: KEM roundtrip failed at iteration %d", i)
		}
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// Golden hashes computed and locked in by lattice-safe/kyber-rs's
// tests/kat_vectors.rs. A mismatch here means this package's byte-level
// output for the corresponding ML-KEM parameter set has diverged from
// lattice-safe/kyber-rs.
const (
	kyberRSGoldenHash512  = "47a87680881e19bd4c4dd3a19aebcc8e2751ba3e05571f967c1f95f8739b33bd"
	kyberRSGoldenHash768  = "48f926a974fd391c0b06d52b34cd7e4d2afa952d518c81527e726a1fca889eef"
	kyberRSGoldenHash1024 = "88e19af98ded164e69b35582a82d56b6c56ddac7e078bcb0fe5a1328fa72533d"
)

// TestKAT512CrossImplementationHash locks ML-KEM-512's output against the
// golden hash computed by lattice-safe/kyber-rs. Go's standard library
// crypto/mlkem does not implement ML-KEM-512, so this cross-implementation
// hash chain is the only fixed-vector-style check available for it.
func TestKAT512CrossImplementationHash(t *testing.T) {
	got := crossImplKATHash(t, Kyber512)
	if got != kyberRSGoldenHash512 {
		t.Fatalf("ML-KEM-512 cross-implementation hash mismatch against lattice-safe/kyber-rs:\n  got:  %s\n  want: %s", got, kyberRSGoldenHash512)
	}
}

// TestKAT768CrossImplementationHash locks ML-KEM-768's output against the
// golden hash computed by lattice-safe/kyber-rs, as an additional check
// alongside the stdlib-derived vectors in TestKAT.
func TestKAT768CrossImplementationHash(t *testing.T) {
	got := crossImplKATHash(t, Kyber768)
	if got != kyberRSGoldenHash768 {
		t.Fatalf("ML-KEM-768 cross-implementation hash mismatch against lattice-safe/kyber-rs:\n  got:  %s\n  want: %s", got, kyberRSGoldenHash768)
	}
}

// TestKAT1024CrossImplementationHash locks ML-KEM-1024's output against
// the golden hash computed by lattice-safe/kyber-rs, as an additional
// check alongside the stdlib-derived vectors in TestKAT.
func TestKAT1024CrossImplementationHash(t *testing.T) {
	got := crossImplKATHash(t, Kyber1024)
	if got != kyberRSGoldenHash1024 {
		t.Fatalf("ML-KEM-1024 cross-implementation hash mismatch against lattice-safe/kyber-rs:\n  got:  %s\n  want: %s", got, kyberRSGoldenHash1024)
	}
}
