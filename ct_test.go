package kyber

import "testing"

// oldCompress reproduces the previous divide-by-q formula
// ((u<<d) + q/2) / q, masked to d bits, using arbitrary-precision-safe
// uint64 arithmetic so it never overflows regardless of d. It exists only
// as a correctness oracle for the new, division-free helpers below and must
// never be reintroduced into production code paths that touch secret data.
func oldCompress(u uint16, d uint, mask uint32) uint32 {
	t := (uint64(u) << d) + uint64(q)/2
	t /= uint64(q)
	return uint32(t) & mask
}

// TestCompressDivisionFreeEquivalence proves, for every representable
// coefficient value u in [0, q-1] (and one boundary value at q, since the
// callers first normalize into [0, q) via `u += (u >> 15) & Q`, the caller
// never actually passes q itself, but we also sweep [0, 3328] exactly as
// specified), that the new division-free helpers compute exactly the same
// result as the reference divide-based formula they replace.
func TestCompressDivisionFreeEquivalence(t *testing.T) {
	for u := 0; u <= 3328; u++ {
		uu := uint16(u)

		if got, want := uint32(compress1(uu)), oldCompress(uu, 1, 1); got != want {
			t.Fatalf("compress1(%d) = %d, want %d", u, got, want)
		}
		if got, want := uint32(compress4(uu)), oldCompress(uu, 4, 15); got != want {
			t.Fatalf("compress4(%d) = %d, want %d", u, got, want)
		}
		if got, want := uint32(compress5(uu)), oldCompress(uu, 5, 31); got != want {
			t.Fatalf("compress5(%d) = %d, want %d", u, got, want)
		}
		if got, want := uint32(compress10(uu)), oldCompress(uu, 10, 0x3FF); got != want {
			t.Fatalf("compress10(%d) = %d, want %d", u, got, want)
		}
		if got, want := uint32(compress11(uu)), oldCompress(uu, 11, 0x7FF); got != want {
			t.Fatalf("compress11(%d) = %d, want %d", u, got, want)
		}
	}
}

// TestTobytesFrombytesRoundtripFullRange exercises (*poly).tobytes followed
// by frombytesToPoly across every coefficient value in both the centered
// representative range [-(q-1)/2, (q-1)/2] and the non-negative range
// [0, q-1], confirming the branchless normalization in tobytes is exactly
// equivalent to the old sign-branching version for every possible input.
func TestTobytesFrombytesRoundtripFullRange(t *testing.T) {
	const half = (int(q) - 1) / 2 // 1664

	var values []int16
	for c := -half; c <= half; c++ {
		values = append(values, int16(c))
	}
	for c := 0; c < int(q); c++ {
		values = append(values, int16(c))
	}

	buf := make([]byte, polyBytes)
	for start := 0; start < len(values); start += n {
		end := start + n
		if end > len(values) {
			end = len(values)
		}

		p := newPoly()
		for i := start; i < end; i++ {
			p.coeffs[i-start] = values[i]
		}
		// Pad any remaining coefficients with 0 so tobytes/frombytes see a
		// full-width polynomial.
		for i := end - start; i < n; i++ {
			p.coeffs[i] = 0
		}

		p.tobytes(buf)
		p2 := frombytesToPoly(buf)

		for i := start; i < end; i++ {
			c := values[i]
			want := c + ((c >> 15) & q) // branchless normalization into [0, q)
			got := p2.coeffs[i-start]
			if got != want {
				t.Fatalf("roundtrip mismatch for coeff %d: got %d, want %d", c, got, want)
			}
		}
	}
}
