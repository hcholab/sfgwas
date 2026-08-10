package unittests

import (
	"path/filepath"
	"testing"

	"github.com/hcholab/sfgwas/gwas"
)

// The plaintext assoc-test cache writes with SaveFloatMatrixToFileRowMajor and reads
// with LoadMatrixFromFileFloat, so the pair must round-trip exactly: a cached run has
// to reproduce an uncached one bit for bit.
func TestSaveFloatMatrixRowMajorRoundTrip(t *testing.T) {
	in := [][]float64{
		{1, 2, 3, 4, 5},
		{-1.5, 0, 1e-12, 1e12, 0.1},
		{3.141592653589793, 2.718281828459045, -0.0, 1234567.891011, -9.87654321e-5},
	}

	path := filepath.Join(t.TempDir(), "mult.txt")
	gwas.SaveFloatMatrixToFileRowMajor(path, in)
	out := gwas.LoadMatrixFromFileFloat(path, ',')

	if len(out) != len(in) {
		t.Fatalf("row count: got %d, want %d", len(out), len(in))
	}
	for i := range in {
		if len(out[i]) != len(in[i]) {
			t.Fatalf("row %d length: got %d, want %d", i, len(out[i]), len(in[i]))
		}
		for j := range in[i] {
			if out[i][j] != in[i][j] {
				t.Errorf("[%d][%d]: got %v, want %v", i, j, out[i][j], in[i][j])
			}
		}
	}
}
