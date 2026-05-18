# kyber-go

![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)
![Audit](https://img.shields.io/badge/audit-passed-success.svg)
![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)

`kyber-go` is a pure Go, production-ready implementation of **ML-KEM (FIPS 203)**, ported from the security-audited Rust codebase `lattice-safe/kyber-rs` to provide exact polynomial arithmetic bounds and constant-time behavior in Go.

## Features

- **Pure Go**: Zero `cgo` dependencies. Compiles easily across all Go-supported architectures.
- **FIPS 203 Compliant**: Implements the final NIST ML-KEM standard, achieving bit-for-bit parity with the official reference vectors across all security levels (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
- **Constant-Time Execution**: Employs explicit constant-time mechanisms (`crypto/subtle`) to guard against timing side-channels, ensuring that operations like implicit rejection during decapsulation are completely immune to timing attacks.
- **Memory Hygiene (Zeroization)**: Designed for high-security environments with explicit `.Zeroize()` functions allowing developers to aggressively wipe sensitive key material and entropy from memory when no longer needed.
- **100% Test Coverage**: The entire repository boasts 100% statement coverage, validated against FIPS 203 edge cases, deterministic testing, and fuzz testing.

## Installation

```bash
go get github.com/lattice-safe/kyber-go
```

## Example Usage

See the `examples` directory for a full working example.

```go
package main

import (
	"fmt"
	"log"

	"github.com/lattice-safe/kyber-go"
)

func main() {
	// 1. Generate Key Pair (ML-KEM-768 / NIST Level 3)
	kp, err := kyber.GenerateKeyPair(kyber.Kyber768)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	// Securely wipe the key pair from memory when done
	defer kp.Zeroize()

	// 2. Encapsulate (Sender side)
	ct, ssEncaps, err := kyber.Encapsulate(kyber.Kyber768, kp.PublicKey())
	if err != nil {
		log.Fatalf("Failed to encapsulate: %v", err)
	}
	defer kyber.Zeroize(ssEncaps)

	// 3. Decapsulate (Receiver side)
	ssDecaps, err := kp.Decapsulate(ct)
	if err != nil {
		log.Fatalf("Failed to decapsulate: %v", err)
	}
	defer kyber.Zeroize(ssDecaps)

	// 4. Verify
	if string(ssEncaps) == string(ssDecaps) {
		fmt.Println("Success! Shared secrets match.")
	}
}
```

## Code Audit & Security

This repository has undergone a strict code audit focusing on:
1. **Constant-Time Decapsulation**: Re-encryption validation during decapsulation (`kem.go`) uses `subtle.ConstantTimeCompare` and a branchless constant-time conditional move (`cmov`) to ensure safe implicit rejection of malformed ciphertexts without leaking timing information.
2. **Bounds Checking & Polynomial Arithmetic**: Ported from an audited reference, utilizing Barrett and Montgomery reductions perfectly aligned with FIPS 203 constraints.
3. **Dead Code Elimination**: Fully sanitized, ensuring zero unused branches and comprehensive bounds coverage.

### Zeroization

Go's garbage collector does not guarantee when (or if) memory will be overwritten. To prevent long-term secrets from persisting in memory:
1. Always call `defer kp.Zeroize()` immediately after key generation.
2. Call `defer kyber.Zeroize(ss)` on shared secrets once they have been fed into your symmetric key derivation function (KDF).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
