# kyber-go

![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)
![FIPS 203](https://img.shields.io/badge/FIPS_203-compliant-blue.svg)
![kyber-rs](https://img.shields.io/badge/kyber--rs-100%25_compatible-success.svg)
![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)

`kyber-go` is a pure Go, production-ready implementation of **ML-KEM (FIPS 203)**, completely compatible with [`lattice-safe/kyber-rs`](https://github.com/lattice-safe/kyber-rs). It provides exact polynomial arithmetic bounds, constant-time decapsulation, and 100% test coverage across all NIST security categories.

## Features

- **Pure Go**: Zero `cgo` dependencies. Compiles easily across all Go-supported architectures (`GOOS`/`GOARCH`).
- **FIPS 203 Compliant**: Full bit-for-bit parity with the final NIST FIPS 203 specification and [`lattice-safe/kyber-rs`](https://github.com/lattice-safe/kyber-rs) across all parameter sets (**ML-KEM-512**, **ML-KEM-768**, **ML-KEM-1024**).
- **Constant-Time Execution**: Employs explicit constant-time mechanisms (`crypto/subtle` and branchless conditional move `cmov`) to prevent timing side-channels during decapsulation and implicit rejection.
- **Memory Hygiene (Zeroization)**: Memory sanitization functions (`.Zeroize()`) allow wiping sensitive key material and entropy slices when no longer needed.
- **100% Test Coverage & KAT Validation**: 100% statement coverage backed by deterministic Known Answer Tests (KAT), implicit rejection fuzz testing, and edge-case error path validation.

## Installation

```bash
go get github.com/lattice-safe/kyber-go
```

## Parameter Sets

| Parameter Set | Security Level | Public Key | Secret Key | Ciphertext | Shared Secret |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | NIST Level 1 | 800 bytes | 1632 bytes | 768 bytes | 32 bytes |
| **ML-KEM-768** | NIST Level 3 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes |
| **ML-KEM-1024** | NIST Level 5 | 1568 bytes | 3168 bytes | 1184 bytes | 32 bytes |

## Example Usage

See the [`examples`](file:///Users/suleymankardas/Desktop/lattice-safe/kyber-go/examples) directory for a full working example.

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

## Testing & Coverage

Run the full test suite and verify 100% statement coverage:

```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

Run fuzzing tests:

```bash
go test -fuzz=FuzzRoundtrip -fuzztime=10s .
go test -fuzz=FuzzDecapsulate -fuzztime=10s .
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

