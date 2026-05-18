package kyber

import (
	"testing"
)

func benchmarkKeyGen(b *testing.B, mode *Mode) {
	for i := 0; i < b.N; i++ {
		kp, err := GenerateKeyPair(mode)
		if err != nil {
			b.Fatal(err)
		}
		_ = kp
	}
}

func benchmarkEncaps(b *testing.B, mode *Mode) {
	kp, _ := GenerateKeyPair(mode)
	pk := kp.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, ss, err := Encapsulate(mode, pk)
		if err != nil {
			b.Fatal(err)
		}
		_ = ct
		_ = ss
	}
}

func benchmarkDecaps(b *testing.B, mode *Mode) {
	kp, _ := GenerateKeyPair(mode)
	pk := kp.PublicKey()
	ct, _, _ := Encapsulate(mode, pk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ss, err := kp.Decapsulate(ct)
		if err != nil {
			b.Fatal(err)
		}
		_ = ss
	}
}

func BenchmarkKyber512KeyGen(b *testing.B) { benchmarkKeyGen(b, Kyber512) }
func BenchmarkKyber512Encaps(b *testing.B) { benchmarkEncaps(b, Kyber512) }
func BenchmarkKyber512Decaps(b *testing.B) { benchmarkDecaps(b, Kyber512) }

func BenchmarkKyber768KeyGen(b *testing.B) { benchmarkKeyGen(b, Kyber768) }
func BenchmarkKyber768Encaps(b *testing.B) { benchmarkEncaps(b, Kyber768) }
func BenchmarkKyber768Decaps(b *testing.B) { benchmarkDecaps(b, Kyber768) }

func BenchmarkKyber1024KeyGen(b *testing.B) { benchmarkKeyGen(b, Kyber1024) }
func BenchmarkKyber1024Encaps(b *testing.B) { benchmarkEncaps(b, Kyber1024) }
func BenchmarkKyber1024Decaps(b *testing.B) { benchmarkDecaps(b, Kyber1024) }
