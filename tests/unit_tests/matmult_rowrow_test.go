package unittests

import (
	"math"
	"testing"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/hcholab/sfgwas/gwas"
	"github.com/ldsec/lattigo/v2/ckks"
)

// rowTimesRowImpl is one of the interchangeable row-times-row matmul variants.
type rowTimesRowImpl struct {
	name string
	fn   func(*crypto.CryptoParams, crypto.CipherMatrix, crypto.CipherMatrix, int) crypto.CipherMatrix
}

// rowTimesRowImpls are the variants under test. They must agree up to CKKS noise.
var rowTimesRowImpls = []rowTimesRowImpl{
	{"V1", gwas.CMultMatRowTimesRowV1},
	{"V2", gwas.CMultMatRowTimesRowV2},
	{"V3", gwas.CMultMatRowTimesRowV3},
}

// newTestCryptoParams builds a single-party CKKS context with enough levels for
// two consecutive multiplications, plus the power-of-two rotation keys needed for
// slot replication. Small parameters: fast to key-generate, precise enough that
// the tolerance below is dominated by the algorithm rather than by noise.
func newTestCryptoParams(t *testing.T) *crypto.CryptoParams {
	t.Helper()

	params, err := ckks.NewParametersFromLogModuli(12, &ckks.LogModuli{
		LogQi: []int{55, 45, 45, 45, 45},
		LogPi: []int{55},
	})
	if err != nil {
		t.Fatal(err)
	}
	params.SetScale(1 << 45)
	params.SetLogSlots(11)

	cps := crypto.NewCryptoParamsForNetwork(params, 1, 30)[0]
	cps.SetRotKeys(crypto.GenerateRotKeys(cps.GetSlots(), 0, false))
	return cps
}

// refMatMul is the plaintext reference implementation.
func refMatMul(a, b [][]float64) [][]float64 {
	out := make([][]float64, len(a))
	for i := range out {
		out[i] = make([]float64, len(b[0]))
		for j := range out[i] {
			for k := range b {
				out[i][j] += a[i][k] * b[k][j]
			}
		}
	}
	return out
}

// maxAbsErr decrypts each row of got and returns the largest deviation from want.
func maxAbsErr(t *testing.T, cps *crypto.CryptoParams, got crypto.CipherMatrix, want [][]float64, ncols int) float64 {
	t.Helper()

	worst := 0.0
	for i := range want {
		dec := crypto.DecryptFloatVector(cps, got[i], ncols)
		for j := 0; j < ncols; j++ {
			if e := math.Abs(dec[j] - want[i][j]); e > worst {
				worst = e
			}
		}
	}
	return worst
}

func TestCMultMatRowTimesRow(t *testing.T) {
	cps := newTestCryptoParams(t)
	slots := cps.GetSlots()
	t.Logf("slots=%d", slots)

	// n x k times k x m, with m spanning several ciphertexts.
	n, k, m := 3, 5, slots+7

	A := make([][]float64, n)
	for i := range A {
		A[i] = make([]float64, k)
		for j := range A[i] {
			A[i][j] = 0.1*float64(i+1) + 0.01*float64(j+1)
		}
	}
	B := make([][]float64, k)
	for i := range B {
		B[i] = make([]float64, m)
		for j := range B[i] {
			B[i][j] = math.Sin(float64(i+1)) * float64(j%13) / 7.0
		}
	}

	Aenc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, A)
	Benc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, B)
	want := refMatMul(A, B)

	for _, impl := range rowTimesRowImpls {
		t.Run(impl.name, func(t *testing.T) {
			got := impl.fn(cps, Aenc, Benc, 4)

			if len(got) != n {
				t.Fatalf("result has %d rows, want %d", len(got), n)
			}
			if len(got[0]) != len(Benc[0]) {
				t.Fatalf("result row has %d ciphertexts, want %d", len(got[0]), len(Benc[0]))
			}

			err := maxAbsErr(t, cps, got, want, m)
			t.Logf("max abs error = %g", err)
			if err > 1e-4 {
				t.Fatalf("result mismatch, max abs error %g", err)
			}

			// Padding slots of the last ciphertext must stay zero.
			tail := crypto.DecryptFloatVector(cps, crypto.CipherVector{got[0][len(got[0])-1]}, slots)
			for j := m % slots; j < slots; j++ {
				if math.Abs(tail[j]) > 1e-4 {
					t.Fatalf("padding slot %d of last ciphertext is %g, want 0", j, tail[j])
				}
			}
		})
	}
}

// TestCMultMatRowTimesRowMultiCtx exercises the ctid > 0 path, where the shared
// dimension spans multiple ciphertexts of N.
func TestCMultMatRowTimesRowMultiCtx(t *testing.T) {
	cps := newTestCryptoParams(t)
	slots := cps.GetSlots()

	n, k, m := 2, slots+3, 9

	A := make([][]float64, n)
	for i := range A {
		A[i] = make([]float64, k)
		for j := range A[i] {
			A[i][j] = float64((i*k+j)%17) / 100.0
		}
	}
	B := make([][]float64, k)
	for i := range B {
		B[i] = make([]float64, m)
		for j := range B[i] {
			B[i][j] = float64((i+j)%5) / 50.0
		}
	}

	Aenc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, A)
	Benc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, B)
	if len(Aenc[0]) < 2 {
		t.Fatalf("expected N rows to span >1 ciphertext, got %d", len(Aenc[0]))
	}
	want := refMatMul(A, B)

	for _, impl := range rowTimesRowImpls {
		t.Run(impl.name, func(t *testing.T) {
			got := impl.fn(cps, Aenc, Benc, 4)

			err := maxAbsErr(t, cps, got, want, m)
			t.Logf("max abs error = %g", err)
			if err > 1e-4 {
				t.Fatalf("result mismatch, max abs error %g", err)
			}
		})
	}
}

// TestCMultMatRowTimesRowShapes covers the shapes the association test actually
// uses, including the single-row operand that made the original implementation's
// output shape ambiguous.
func TestCMultMatRowTimesRowShapes(t *testing.T) {
	cps := newTestCryptoParams(t)

	shapes := []struct{ n, k, m int }{
		{1, 4, 20}, // {OnetQ} x B
		{4, 4, 20}, // Vt x ZtXscaled
		{2, 4, 20}, // YtQ x B
		{5, 3, 1},  // single output column
		{1, 1, 1},  // degenerate
	}

	for _, s := range shapes {
		A := make([][]float64, s.n)
		for i := range A {
			A[i] = make([]float64, s.k)
			for j := range A[i] {
				A[i][j] = float64((i+2)*(j+3)) / 37.0
			}
		}
		B := make([][]float64, s.k)
		for i := range B {
			B[i] = make([]float64, s.m)
			for j := range B[i] {
				B[i][j] = float64((i+5)*(j+7)) / 53.0
			}
		}

		Aenc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, A)
		Benc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, B)
		want := refMatMul(A, B)

		for _, impl := range rowTimesRowImpls {
			t.Run(impl.name, func(t *testing.T) {
				got := impl.fn(cps, Aenc, Benc, 4)

				if len(got) != s.n {
					t.Fatalf("%dx%d * %dx%d: result has %d rows, want %d",
						s.n, s.k, s.k, s.m, len(got), s.n)
				}
				if err := maxAbsErr(t, cps, got, want, s.m); err > 1e-4 {
					t.Fatalf("%dx%d * %dx%d: max abs error %g",
						s.n, s.k, s.k, s.m, err)
				}
			})
		}
	}
}
