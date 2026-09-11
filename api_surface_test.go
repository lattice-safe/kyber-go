package kyber

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// allowedTopLevel is the exact set of exported top-level identifiers
// (consts, vars, types, and functions without a receiver) that this
// package is allowed to export. Anything else appearing at package scope
// with an exported name is a leak of the internal implementation surface.
var allowedTopLevel = map[string]bool{
	// constants
	"SharedSecretSize": true,
	"SSBYTES":          true,
	// sentinel errors (package-level vars)
	"ErrInvalidPublicKeyLength":  true,
	"ErrInvalidSecretKeyLength":  true,
	"ErrInvalidCiphertextLength": true,
	"ErrInvalidCoinsLength":      true,
	"ErrInvalidPublicKey":        true,
	"ErrInvalidSecretKey":        true,
	"ErrKeyZeroized":             true,
	"ErrInvalidMode":             true,
	// parameter sets (package-level vars)
	"Kyber512":  true,
	"Kyber768":  true,
	"Kyber1024": true,
	"MLKEM512":  true,
	"MLKEM768":  true,
	"MLKEM1024": true,
	// types
	"Mode":    true,
	"KeyPair": true,
	// functions (no receiver)
	"GenerateKeyPairDerand":   true,
	"GenerateKeyPair":         true,
	"NewKeyPairFromSecretKey": true,
	"EncapsulateDerand":       true,
	"Encapsulate":             true,
	"Zeroize":                 true,
}

// allowedMethods is the exact set of exported methods allowed on each
// exported type, keyed by "TypeName.MethodName".
var allowedMethods = map[string]bool{
	"Mode.PublicKeyBytes":  true,
	"Mode.SecretKeyBytes":  true,
	"Mode.CiphertextBytes": true,
	"Mode.Name":            true,

	"KeyPair.Mode":        true,
	"KeyPair.PublicKey":   true,
	"KeyPair.SecretKey":   true,
	"KeyPair.Zeroize":     true,
	"KeyPair.Decapsulate": true,
}

// parsePackageNonTestFiles parses every non-test .go file in the package
// directory (the current directory, since this test file lives in package
// kyber) and returns the parsed files.
func parsePackageNonTestFiles(t *testing.T) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("ParseFile(%s) failed: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test .go files found in package directory")
	}
	return files
}

// receiverTypeName extracts the (possibly pointer) receiver's base type
// name from a method's field list, e.g. "*Mode" -> "Mode".
func receiverTypeName(fl *ast.FieldList) string {
	if fl == nil || len(fl.List) == 0 {
		return ""
	}
	expr := fl.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// TestExportedAPISurface parses every non-test .go file in the package and
// asserts that the exact set of exported top-level identifiers (consts,
// vars, types, and receiver-less funcs) plus exported methods on exported
// types matches the intended public API. Anything else exported is a leak
// of internal implementation details and fails this test with a diff.
func TestExportedAPISurface(t *testing.T) {
	files := parsePackageNonTestFiles(t)

	gotTopLevel := map[string]bool{}
	gotMethods := map[string]bool{}

	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec: // const or var
						for _, name := range s.Names {
							if name.IsExported() {
								gotTopLevel[name.Name] = true
							}
						}
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							gotTopLevel[s.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv == nil {
					gotTopLevel[d.Name.Name] = true
					continue
				}
				recvType := receiverTypeName(d.Recv)
				gotMethods[recvType+"."+d.Name.Name] = true
			}
		}
	}

	if diff := setDiff(gotTopLevel, allowedTopLevel); diff != "" {
		t.Errorf("exported top-level identifiers do not match the allowed public API:\n%s", diff)
	}
	if diff := setDiff(gotMethods, allowedMethods); diff != "" {
		t.Errorf("exported methods do not match the allowed public API:\n%s", diff)
	}
}

// setDiff returns a human-readable diff between got and want (both treated
// as sets), or "" if they are identical.
func setDiff(got, want map[string]bool) string {
	var extra, missing []string
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(extra)
	sort.Strings(missing)

	if len(extra) == 0 && len(missing) == 0 {
		return ""
	}
	var b bytes.Buffer
	if len(extra) > 0 {
		b.WriteString("unexpectedly exported (should be unexported or removed):\n")
		for _, k := range extra {
			b.WriteString("  + " + k + "\n")
		}
	}
	if len(missing) > 0 {
		b.WriteString("expected to be exported but is missing:\n")
		for _, k := range missing {
			b.WriteString("  - " + k + "\n")
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------
// Panic-safety of the exported API.
// ---------------------------------------------------------------------

// recoverToError runs f and converts any panic into a non-nil error,
// returning the error f itself produced (nil on no error) alongside a
// panic flag.
func callNoPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()
	f()
}

// TestExportedFunctionsNeverPanic drives every exported function that
// takes a *Mode and/or a byte slice with a table of hostile inputs (nil
// mode, a zero-value &Mode{} that a caller cannot otherwise construct
// since Mode's fields are unexported, and nil/short/long byte slices) and
// asserts that none of them ever panics -- they must return an error
// (ErrInvalidMode or one of the ErrInvalid*Length/ErrInvalid* sentinels)
// instead.
func TestExportedFunctionsNeverPanic(t *testing.T) {
	invalidModes := []*Mode{nil, {}}

	validKP, err := GenerateKeyPair(Kyber768)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Kyber768) failed: %v", err)
	}
	validPK := validKP.PublicKey()
	validSK := validKP.SecretKey()
	validCT, _, err := Encapsulate(Kyber768, validPK)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	badLengthByteSlices := func(valid []byte) [][]byte {
		return [][]byte{
			nil,
			{},
			valid[:len(valid)/2], // short
			append(append([]byte{}, valid...), 0x00, 0x01, 0x02), // long
		}
	}

	// 1. Invalid *Mode passed to every function that takes one.
	for _, m := range invalidModes {
		callNoPanic(t, "GenerateKeyPairDerand(invalid mode)", func() {
			if _, err := GenerateKeyPairDerand(m, make([]byte, 64)); err == nil {
				t.Error("GenerateKeyPairDerand(invalid mode): expected error, got nil")
			}
		})
		callNoPanic(t, "GenerateKeyPair(invalid mode)", func() {
			if _, err := GenerateKeyPair(m); err == nil {
				t.Error("GenerateKeyPair(invalid mode): expected error, got nil")
			}
		})
		callNoPanic(t, "NewKeyPairFromSecretKey(invalid mode)", func() {
			if _, err := NewKeyPairFromSecretKey(m, validSK); err == nil {
				t.Error("NewKeyPairFromSecretKey(invalid mode): expected error, got nil")
			}
		})
		callNoPanic(t, "Encapsulate(invalid mode)", func() {
			if _, _, err := Encapsulate(m, validPK); err == nil {
				t.Error("Encapsulate(invalid mode): expected error, got nil")
			}
		})
		callNoPanic(t, "EncapsulateDerand(invalid mode)", func() {
			if _, _, err := EncapsulateDerand(m, validPK, make([]byte, 32)); err == nil {
				t.Error("EncapsulateDerand(invalid mode): expected error, got nil")
			}
		})
		callNoPanic(t, "Mode.PublicKeyBytes(invalid mode)", func() {
			_ = m.PublicKeyBytes()
		})
		callNoPanic(t, "Mode.SecretKeyBytes(invalid mode)", func() {
			_ = m.SecretKeyBytes()
		})
		callNoPanic(t, "Mode.CiphertextBytes(invalid mode)", func() {
			_ = m.CiphertextBytes()
		})
		callNoPanic(t, "Mode.Name(invalid mode)", func() {
			_ = m.Name()
		})
	}

	// 2. Nil/short/long coins for GenerateKeyPairDerand.
	for _, coins := range badLengthByteSlices(make([]byte, 64)) {
		coins := coins
		callNoPanic(t, "GenerateKeyPairDerand(bad coins)", func() {
			if _, err := GenerateKeyPairDerand(Kyber768, coins); err == nil {
				t.Errorf("GenerateKeyPairDerand(coins len=%d): expected error, got nil", len(coins))
			}
		})
	}

	// 3. Nil/short/long public key for EncapsulateDerand/Encapsulate.
	for _, pk := range badLengthByteSlices(validPK) {
		pk := pk
		callNoPanic(t, "EncapsulateDerand(bad pk)", func() {
			if _, _, err := EncapsulateDerand(Kyber768, pk, make([]byte, 32)); err == nil {
				t.Errorf("EncapsulateDerand(pk len=%d): expected error, got nil", len(pk))
			}
		})
		callNoPanic(t, "Encapsulate(bad pk)", func() {
			if _, _, err := Encapsulate(Kyber768, pk); err == nil {
				t.Errorf("Encapsulate(pk len=%d): expected error, got nil", len(pk))
			}
		})
	}

	// 4. Nil/short/long coins for EncapsulateDerand.
	for _, coins := range badLengthByteSlices(make([]byte, 32)) {
		coins := coins
		callNoPanic(t, "EncapsulateDerand(bad coins)", func() {
			if _, _, err := EncapsulateDerand(Kyber768, validPK, coins); err == nil {
				t.Errorf("EncapsulateDerand(coins len=%d): expected error, got nil", len(coins))
			}
		})
	}

	// 5. Nil/short/long secret key for NewKeyPairFromSecretKey.
	for _, sk := range badLengthByteSlices(validSK) {
		sk := sk
		callNoPanic(t, "NewKeyPairFromSecretKey(bad sk)", func() {
			if _, err := NewKeyPairFromSecretKey(Kyber768, sk); err == nil {
				t.Errorf("NewKeyPairFromSecretKey(sk len=%d): expected error, got nil", len(sk))
			}
		})
	}

	// 6. Nil/short/long ciphertext for (*KeyPair).Decapsulate.
	for _, ct := range badLengthByteSlices(validCT) {
		ct := ct
		callNoPanic(t, "KeyPair.Decapsulate(bad ct)", func() {
			if _, err := validKP.Decapsulate(ct); err == nil {
				t.Errorf("Decapsulate(ct len=%d): expected error, got nil", len(ct))
			}
		})
	}

	// 7. Package-level Zeroize and (*KeyPair).Zeroize must never panic on
	// nil/empty input, and must be safe to call repeatedly.
	callNoPanic(t, "Zeroize(nil)", func() { Zeroize(nil) })
	callNoPanic(t, "Zeroize(empty)", func() { Zeroize([]byte{}) })
	callNoPanic(t, "KeyPair.Zeroize (repeated)", func() {
		kp, err := GenerateKeyPair(Kyber512)
		if err != nil {
			t.Fatalf("GenerateKeyPair(Kyber512) failed: %v", err)
		}
		kp.Zeroize()
		kp.Zeroize()
	})
}

// ---------------------------------------------------------------------
// Coverage of the invalid-mode/entropy-failure branches added above.
// ---------------------------------------------------------------------

// TestModeNameAndAliases exercises every branch of (*Mode).Name and
// confirms the MLKEM* aliases point at the same values as their Kyber*
// counterparts.
func TestModeNameAndAliases(t *testing.T) {
	cases := []struct {
		mode *Mode
		want string
	}{
		{Kyber512, "ML-KEM-512"},
		{Kyber768, "ML-KEM-768"},
		{Kyber1024, "ML-KEM-1024"},
	}
	for _, tc := range cases {
		if got := tc.mode.Name(); got != tc.want {
			t.Errorf("Name() = %q, want %q", got, tc.want)
		}
	}

	if MLKEM512 != Kyber512 {
		t.Error("MLKEM512 must be the same *Mode value as Kyber512")
	}
	if MLKEM768 != Kyber768 {
		t.Error("MLKEM768 must be the same *Mode value as Kyber768")
	}
	if MLKEM1024 != Kyber1024 {
		t.Error("MLKEM1024 must be the same *Mode value as Kyber1024")
	}
}

// TestDecapsulateInvalidMode confirms that (*KeyPair).Decapsulate rejects a
// KeyPair whose mode is nil or an invalid &Mode{} (which cannot happen via
// the exported constructors, but is reachable from inside the package,
// exercising the defensive check).
func TestDecapsulateInvalidMode(t *testing.T) {
	for _, mode := range []*Mode{nil, {}} {
		kp := &KeyPair{mode: mode, pubkey: []byte{}, seckey: []byte{}}
		if _, err := kp.Decapsulate(make([]byte, 10)); !errors.Is(err, ErrInvalidMode) {
			t.Errorf("Decapsulate with invalid mode %v: expected ErrInvalidMode, got %v", mode, err)
		}
	}
}

// Note: GenerateKeyPair's and Encapsulate's "entropy source failed" error
// paths (crypto/rand.Read returning a non-nil error) are intentionally not
// exercised here. As of Go 1.24, crypto/rand.Read no longer returns an
// error on failure of the operating system's random number generator; it
// crashes the process instead (see the Go 1.24 release notes), so this
// branch cannot be triggered from a test without terminating the test
// binary. The error-returning code path is kept as defensive
// belt-and-suspenders for non-standard io.Reader implementations reachable
// only via internal refactoring, not for coverage purposes.
