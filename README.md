# kyber-go

![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)
![FIPS 203](https://img.shields.io/badge/FIPS_203-compliant-blue.svg)
![kyber-rs](https://img.shields.io/badge/kyber--rs-hash_tests_match-success.svg)
![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)

`kyber-go` is a pure Go implementation of **ML-KEM (FIPS 203)** with zero external dependencies (it uses only the Go standard library, including `crypto/sha3`, added in Go 1.24). Interoperability with FIPS 203 is verified in CI against Go's standard-library `crypto/mlkem` (ML-KEM-768/1024) and by fixed test vectors derived from it; ML-KEM-512, which `crypto/mlkem` does not implement, is cross-checked against [`lattice-safe/kyber-rs`](https://github.com/lattice-safe/kyber-rs) via matching hash tests. See [Security notes / limitations](#security-notes--limitations) below before using this in production.

## Features

- **Pure Go, zero dependencies**: No `cgo`, and — as of the `crypto/sha3` migration — no third-party Go modules either. Compiles easily across all Go-supported architectures (`GOOS`/`GOARCH`).
- **FIPS 203 compliant**: Matches the final NIST FIPS 203 specification across all parameter sets (**ML-KEM-512**, **ML-KEM-768**, **ML-KEM-1024**), verified against Go's standard-library `crypto/mlkem` (768/1024) and, via cross-implementation hash tests, against [`lattice-safe/kyber-rs`](https://github.com/lattice-safe/kyber-rs) (all three parameter sets).
- **Constant-time execution**: Employs explicit constant-time mechanisms (`crypto/subtle` and a branchless conditional move `cmov`) to avoid timing side-channels during decapsulation and implicit rejection. See the limitations section for how this has (and has not) been checked.
- **Memory hygiene (zeroization)**: Memory sanitization functions (`.Zeroize()`) allow wiping sensitive key material and entropy slices when no longer needed, on a best-effort basis (see limitations).
- **100% test coverage & multi-tier validation**: 100% statement coverage backed by three independent test tiers — fixed Known Answer Test (KAT) vectors generated from Go's standard library `crypto/mlkem` (ML-KEM-768/1024), a cross-implementation SHA3-256 hash lock against [`lattice-safe/kyber-rs`](https://github.com/lattice-safe/kyber-rs) (all three parameter sets, including ML-KEM-512, which `crypto/mlkem` does not implement), and a live interop test against `crypto/mlkem` — plus implicit rejection fuzz testing and edge-case error path validation.

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

## API

This package deliberately exports a minimal surface: everything needed to
generate keys, encapsulate, and decapsulate, and nothing of the internal
polynomial/NTT/encoding machinery that implements it. The full public API
lives in `api.go`, `validate.go`, and `params.go`, and is enforced
mechanically by `TestExportedAPISurface` in `api_surface_test.go`, which
parses the package's own source and fails if anything else becomes
exported.

- `GenerateKeyPair(mode *Mode) (*KeyPair, error)` / `GenerateKeyPairDerand(mode *Mode, coins []byte) (*KeyPair, error)` — generate a key pair, randomly or from 64 bytes of caller-supplied coins.
- `Encapsulate(mode *Mode, pk []byte) (ct, ss []byte, err error)` / `EncapsulateDerand(mode *Mode, pk []byte, coins []byte) (ct, ss []byte, err error)` — encapsulate against a public key, randomly or from 32 bytes of caller-supplied coins.
- `(*KeyPair).Decapsulate(ct []byte) ([]byte, error)` — recover the shared secret from a ciphertext.
- `NewKeyPairFromSecretKey(mode *Mode, sk []byte) (*KeyPair, error)` — reconstruct a `*KeyPair` from a previously-serialized decapsulation key, after validating it (see below).
- `(*KeyPair).Mode() *Mode` / `(*KeyPair).PublicKey()` / `(*KeyPair).SecretKey()` — `PublicKey`/`SecretKey` each return a **fresh copy** of the respective key material, so callers cannot mutate the `KeyPair`'s internal state through the returned slice; both return `nil` once `(*KeyPair).Zeroize()` has been called.
- `(*KeyPair).Zeroize()` / the package-level `Zeroize(b []byte)` — wipe key material or any byte slice. `KeyPair.Zeroize` is safe to call more than once.
- `Kyber512`, `Kyber768`, `Kyber1024` — the three `*Mode` parameter sets, with size accessors `(*Mode).PublicKeyBytes()`, `(*Mode).SecretKeyBytes()`, `(*Mode).CiphertextBytes()`, and `(*Mode).Name() string` (e.g. `"ML-KEM-768"`). `MLKEM512`, `MLKEM768`, and `MLKEM1024` are aliases for `Kyber512`, `Kyber768`, and `Kyber1024` respectively — the same `*Mode` values under the FIPS 203 name, not copies. `Mode`'s fields are unexported, so the only valid `*Mode` values are these six package-level variables (three parameter sets under two names each); a caller-constructed `&Mode{}` is deliberately not a usable parameter set.
- `SharedSecretSize` (and its alias `SSBYTES`) — the fixed 32-byte length of every shared secret this package produces.
- Sentinel errors: `ErrInvalidPublicKeyLength`, `ErrInvalidSecretKeyLength`, `ErrInvalidCiphertextLength`, `ErrInvalidCoinsLength`, `ErrInvalidPublicKey` (non-canonical polynomial encoding, FIPS 203 §7.2 modulus check), `ErrInvalidSecretKey` (FIPS 203 §7.3 hash check failure), `ErrKeyZeroized` (returned by `Decapsulate` once the key pair has been zeroized), and `ErrInvalidMode` (returned by every function above that takes a `*Mode` when it is `nil` or not one of `Kyber512`/`Kyber768`/`Kyber1024`/their `MLKEM*` aliases). Every exported function validates its inputs and returns one of these errors instead of panicking.

## Testing & Coverage

This package is validated by three independent test tiers, in addition to
ordinary unit tests:

1. **Fixed KAT vectors from an independent implementation** (`TestKAT` in
   `kat_test.go`, vectors in `kat_vectors_test.go`): for ML-KEM-768 and
   ML-KEM-1024, fixed 64-byte seeds are fed through
   `GenerateKeyPairDerand`, and the resulting encapsulation key, the
   secret key's embedded encapsulation key, and the shared secret
   recovered from a fixed ciphertext are all checked byte-for-byte
   against values recorded from Go's standard library `crypto/mlkem` — an
   independent FIPS 203 implementation. These are not official NIST ACVP
   vectors, but unlike a roundtrip test they catch bugs that are
   self-consistent within this package alone.
2. **Cross-implementation hash lock against `lattice-safe/kyber-rs`**
   (`TestKAT512CrossImplementationHash`,
   `TestKAT768CrossImplementationHash`,
   `TestKAT1024CrossImplementationHash` in `kat_test.go`): a deterministic
   SHA3-256 seed chain drives 100 iterations of keygen/encaps/decaps for
   each parameter set, and every produced value is folded into a running
   SHA3-256 hash whose final digest is compared against golden hashes
   locked into `lattice-safe/kyber-rs`'s own test suite. This is the only
   fixed-vector-style check available for ML-KEM-512, which
   `crypto/mlkem` does not implement.
3. **Live interop test against `crypto/mlkem`** (`TestInteropStdlibMLKEM`
   in `interop_test.go`): randomized round trips in both directions
   (this package encapsulates / `crypto/mlkem` decapsulates, and vice
   versa), including agreement on implicit-rejection behavior for
   corrupted ciphertexts, for ML-KEM-768 and ML-KEM-1024.

The purely internal roundtrip regression tests (`TestRoundtripFixedSeed512`
/ `768` / `1024` in `kat_test.go`) are also still run, but — despite their
historical name — they are not KATs: they only check that decapsulation
recovers what encapsulation produced, using a deterministic but arbitrary
seed, with no externally produced fixed value to compare against.

Run the full test suite and verify 100% statement coverage:

```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

Run fuzzing tests (fuzz targets live in the root package, so target `.`
rather than `./...`):

```bash
go test -run=^$ -fuzz=FuzzRoundtrip -fuzztime=10s .
go test -run=^$ -fuzz=FuzzDecapsulate -fuzztime=10s .
```

## Design notes

1. **Constant-time re-encryption check**: Re-encryption validation during decapsulation (`kem.go`) uses `subtle.ConstantTimeCompare` and a branchless constant-time conditional move (`cmov`) so that implicit rejection of malformed ciphertexts does not branch on secret-derived data.
2. **Bounds checking & polynomial arithmetic**: Ported from a reference implementation, using Barrett and Montgomery reductions aligned with FIPS 203's constraints.
3. **Input validation (FIPS 203 §7.2 / §7.3)**: `Encapsulate`/`EncapsulateDerand` perform the §7.2 "Modulus check" on the supplied encapsulation key, rejecting keys whose encoded polynomial coefficients are not canonical (i.e. not strictly less than `q = 3329`). `Decapsulate` and `NewKeyPairFromSecretKey` perform the §7.3 "Hash check" on the decapsulation key, rejecting keys whose stored `H(ek)` does not match a freshly computed SHA3-256 hash of the embedded encapsulation key.

## Security notes / limitations

- **No independent audit**: This code has not been reviewed by a third-party security firm or cryptography auditor. "100% test coverage" refers to statement coverage in Go's `go test -cover`, not to a security review, and does not by itself demonstrate correctness or side-channel resistance.
- **Constant-time claims are inspection-only**: The constant-time properties described above have been checked by inspecting compiler-generated assembly for `amd64`, `arm64`, `arm`, and `386` to confirm the absence of division instructions and secret-dependent branches in the compression, decompression, and serialization code paths. This has *not* been verified with formal constant-time tooling (e.g. `ctgrind`, `ct-verif`, ELISA, or dudect-style statistical timing analysis), and Go's compiler and runtime (garbage collector, goroutine scheduler) offer no constant-time guarantees of their own.
- **Zeroization is best-effort**: `Zeroize()` overwrites the backing array of a slice, but Go's garbage collector can copy or move memory (e.g. during stack growth) before `Zeroize()` is called, and the compiler is free to keep additional copies of values in registers or on the stack. There is no guarantee that all copies of key material are erased.
- **Randomness**: Key generation and encapsulation read entropy from `crypto/rand`; if the OS entropy source fails, these functions now return an error instead of silently proceeding with short or zero-filled coins.
- **Reporting vulnerabilities**: Please report suspected security issues via [GitHub Security Advisories](https://github.com/lattice-safe/kyber-go/security/advisories/new) for this repository (or open a private report to the maintainer) rather than filing a public issue.

### Zeroization usage

Go's garbage collector does not guarantee when (or if) memory will be overwritten, so treat `Zeroize()` as a mitigation, not a guarantee. To reduce the window that secrets stay resident:
1. Call `defer kp.Zeroize()` immediately after key generation.
2. Call `defer kyber.Zeroize(ss)` on shared secrets once they have been fed into your symmetric key derivation function (KDF).

## Compatibility Note

Versions prior to this fix generated the SHAKE-128-derived public matrix `A` in `indcpa.go`'s `genMatrix` with the byte-absorption indices `(i, j)` swapped relative to FIPS 203 Algorithms 13/14, which specify `A[i][j] = SampleNTT(rho || j || i)` (and `rho || i || j` for the transposed matrix `A^T` used during encryption). As a result:

- Public keys, secret keys, and ciphertexts produced by affected versions are **not interoperable** with any conformant FIPS 203 implementation (including Go's standard library `crypto/mlkem`) or with other ML-KEM implementations.
- Key pairs and ciphertexts produced by affected versions are also **not interoperable** with key pairs and ciphertexts produced by this package after the fix, even though internal encapsulation/decapsulation round-trips still succeeded (the bug was self-consistent, so it did not surface as a functional failure within the package itself).

If you generated or exchanged any keys or ciphertexts using a version of this package predating the fix, you must regenerate your keys using the fixed version. This package's interoperability with `crypto/mlkem` is now verified by `TestInteropStdlibMLKEM` in `interop_test.go`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

