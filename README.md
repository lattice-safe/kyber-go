# kyber-go

`kyber-go` is a pure Go, production-ready implementation of **ML-KEM (FIPS 203)**, originally based on the `lattice-safe/kyber-rs` implementation of CRYSTALS-Kyber.

## Features

- **Pure Go**: No cgo dependencies.
- **FIPS 203 Compliant**: Implements the final ML-KEM standard, achieving bit-for-bit parity with reference vectors across all security levels (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
- **Constant-Time**: Explicit constant-time mechanisms (`crypto/subtle`) to guard against timing side-channels, including constant-time implicit rejection during decapsulation.
- **Zeroization**: Designed for high security with explicit `.Zeroize()` functions to wipe sensitive key material and entropy from memory when no longer needed.
- **Tested**: Verified with round-trip, determinism, and fuzz testing.

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

## Security

This library was ported from a security-audited Rust codebase (`lattice-safe/kyber-rs`), ensuring exact polynomial arithmetic bounds and constant-time behavior are maintained.

### Zeroization

Go's garbage collector does not guarantee when (or if) memory will be overwritten. To prevent long-term secrets from persisting in memory:
1. Always call `defer kp.Zeroize()` immediately after key generation.
2. Call `defer kyber.Zeroize(ss)` on shared secrets once they have been fed into your symmetric key derivation function (KDF).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
