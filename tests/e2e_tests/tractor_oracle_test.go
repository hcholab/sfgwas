package e2etests

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hcholab/sfgwas/gwas"
	"gonum.org/v1/gonum/mat"
)

// TestTractorOracle recomputes Tractor association statistics entirely in plaintext
// (gwas.TractorStatsPlain, the same function tests/unit_tests/tractor_projection_test.go
// validates against an independent full-regression reference) from the raw fixture files
// under tractor_fixture/, and compares against out/party1_tractor/tractor_<k>.txt -- the
// values GetTractorStatsPlainMult (gwas/tractor_mpc.go) actually revealed from the live
// encrypted/MPC protocol.
//
// The test skips unless a run has already produced output.
//
//	go run ./scripts/gen_tractor_fixture -out tractor_fixture
//	for i in 0 1 2; do PID=$i PROTOCOL=tractor RUN_STAGE=all go run sfgwas.go & done; wait
//	go test ./tests/e2e_tests/ -run TestTractorOracle -v
func TestTractorOracle(t *testing.T) {
	const (
		fixtureDir  = "../../tractor_fixture"
		outDir      = "../../out/party1_tractor"
		countThresh = 5
		detTol      = 1e-9
		npheno      = 2
		tol         = 5e-2 // fixed-point MPC precision, not float64 -- looser than the Phase A unit test's 1e-9
	)

	if _, err := os.Stat(outDir + "/tractor_0.txt"); err != nil {
		t.Skipf("no Tractor run output found at %s -- run the fixture generator and a live 3-process run first (see doc comment)", outDir)
	}

	Z, Y, A, Xamr, Xeur := loadFixture(t, fixtureDir, npheno)

	want := gwas.TractorStatsPlain(Z, Y, A, Xamr, Xeur, countThresh, detTol)

	for k := 0; k < npheno; k++ {
		got := loadRevealed(t, outDir, k)

		m, _ := want.BetaA.Dims()
		if len(got) != m {
			t.Fatalf("phenotype %d: revealed file has %d SNPs, oracle has %d", k, len(got), m)
		}

		nCompared := 0
		for j := 0; j < m; j++ {
			if !want.Valid[j] || !got[j].valid {
				if want.Valid[j] != got[j].valid {
					t.Errorf("SNP %d pheno %d: validity mismatch: oracle=%v revealed=%v", j, k, want.Valid[j], got[j].valid)
				}
				continue
			}
			nCompared++
			checkClose(t, j, k, "beta_A", got[j].betaA, want.BetaA.At(j, k), tol)
			checkClose(t, j, k, "beta_AMR", got[j].betaM, want.BetaAMR.At(j, k), tol)
			checkClose(t, j, k, "beta_EUR", got[j].betaE, want.BetaEUR.At(j, k), tol)
			checkClose(t, j, k, "se_A", got[j].seA, want.SEA.At(j, k), tol)
			checkClose(t, j, k, "se_AMR", got[j].seM, want.SEAMR.At(j, k), tol)
			checkClose(t, j, k, "se_EUR", got[j].seE, want.SEEUR.At(j, k), tol)
		}
		if nCompared == 0 {
			t.Fatalf("phenotype %d: no SNPs were valid in both oracle and revealed output; comparison is vacuous", k)
		}
	}
}

func checkClose(t *testing.T, j, k int, name string, got, want, tol float64) {
	t.Helper()
	if math.IsNaN(want) || math.IsNaN(got) {
		t.Errorf("SNP %d pheno %d %s: NaN (got=%v want=%v)", j, k, name, got, want)
		return
	}
	denom := math.Max(1, math.Abs(want))
	if math.Abs(got-want)/denom > tol {
		t.Errorf("SNP %d pheno %d %s mismatch: got=%v want=%v relDiff=%g", j, k, name, got, want, math.Abs(got-want)/denom)
	}
}

type revealedRow struct {
	betaA, seA, pA float64
	betaM, seM, pM float64
	betaE, seE, pE float64
	valid          bool
}

func loadRevealed(t *testing.T, dir string, pheno int) []revealedRow {
	t.Helper()
	f, err := os.Open(dir + "/tractor_" + strconv.Itoa(pheno) + ".txt")
	if err != nil {
		t.Fatalf("loadRevealed: %v", err)
	}
	defer f.Close()

	var rows []revealedRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) != 10 {
			t.Fatalf("loadRevealed: expected 10 fields, got %d: %q", len(fields), sc.Text())
		}
		parse := func(i int) float64 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				t.Fatalf("loadRevealed: %v", err)
			}
			return v
		}
		rows = append(rows, revealedRow{
			betaA: parse(0), seA: parse(1), pA: parse(2),
			betaM: parse(3), seM: parse(4), pM: parse(5),
			betaE: parse(6), seE: parse(7), pE: parse(8),
			valid: fields[9] == "true",
		})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("loadRevealed: %v", err)
	}
	return rows
}

// loadFixture reconstructs the full n-individual Z (with an intercept column prepended,
// matching what GetTractorStatsPlainMult adds internally since the fixture's
// cov_all_ones=false), Y, A, X_AMR, X_EUR from both parties' raw fixture files.
func loadFixture(t *testing.T, dir string, npheno int) (Z, Y, A, Xamr, Xeur *mat.Dense) {
	t.Helper()

	cov1 := gwas.LoadMatrixFromFile(dir+"/party1/cov.txt", '\t')
	cov2 := gwas.LoadMatrixFromFile(dir+"/party2/cov.txt", '\t')
	pheno1 := gwas.LoadMatrixFromFile(dir+"/party1/pheno.txt", '\t')
	pheno2 := gwas.LoadMatrixFromFile(dir+"/party2/pheno.txt", '\t')

	n1, ncov := cov1.Dims()
	n2, _ := cov2.Dims()
	n := n1 + n2

	Z = mat.NewDense(n, ncov+1, nil)
	for i := 0; i < n; i++ {
		Z.Set(i, 0, 1)
	}
	for i := 0; i < n1; i++ {
		for c := 0; c < ncov; c++ {
			Z.Set(i, c+1, cov1.At(i, c))
		}
	}
	for i := 0; i < n2; i++ {
		for c := 0; c < ncov; c++ {
			Z.Set(n1+i, c+1, cov2.At(i, c))
		}
	}

	Y = mat.NewDense(n, npheno, nil)
	for i := 0; i < n1; i++ {
		for k := 0; k < npheno; k++ {
			Y.Set(i, k, pheno1.At(i, k))
		}
	}
	for i := 0; i < n2; i++ {
		for k := 0; k < npheno; k++ {
			Y.Set(n1+i, k, pheno2.At(i, k))
		}
	}

	m := readBlockSize(t, dir+"/party1/geno_block_sizes.txt")

	A = mat.NewDense(n, m, nil)
	Xamr = mat.NewDense(n, m, nil)
	Xeur = mat.NewDense(n, m, nil)
	fillAncestryRows(t, A, Xamr, Xeur, 0, dir+"/party1", n1, m)
	fillAncestryRows(t, A, Xamr, Xeur, n1, dir+"/party2", n2, m)

	return
}

func fillAncestryRows(t *testing.T, A, Xamr, Xeur *mat.Dense, rowOffset int, partyDir string, nrow, m int) {
	t.Helper()
	gfsA := gwas.NewGenoFileStream(partyDir+"/tractor_a.0.bin", uint64(nrow), uint64(m), false)
	gfsM := gwas.NewGenoFileStream(partyDir+"/tractor_amr.0.bin", uint64(nrow), uint64(m), false)
	gfsE := gwas.NewGenoFileStream(partyDir+"/tractor_eur.0.bin", uint64(nrow), uint64(m), false)

	for i := 0; i < nrow; i++ {
		rowA := gfsA.NextRow()
		rowM := gfsM.NextRow()
		rowE := gfsE.NextRow()
		if rowA == nil {
			t.Fatalf("fillAncestryRows: %s: expected %d rows, ran out at %d", partyDir, nrow, i)
		}
		for j := 0; j < m; j++ {
			A.Set(rowOffset+i, j, float64(rowA[j]))
			Xamr.Set(rowOffset+i, j, float64(rowM[j]))
			Xeur.Set(rowOffset+i, j, float64(rowE[j]))
		}
	}
}

func readBlockSize(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readBlockSize: %v", err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("readBlockSize: %v", err)
	}
	return v
}
