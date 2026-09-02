// Command gen_tractor_fixture generates a tiny synthetic, ancestry-partitioned GWAS
// dataset split across two parties, in the exact file formats sfgwas's "blocks" genotype
// format and cov/pheno loaders expect (see gwas/filestream.go, gwas/utilities.go). It's
// the Tractor analog of scripts/plinkBedToBinary.py's role for the standard pipeline:
// producing real input files for a live 3-process run, not just a plaintext oracle.
//
// Run from the repo root: go run ./scripts/gen_tractor_fixture -out tractor_fixture
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
)

func main() {
	outDir := flag.String("out", "tractor_fixture", "output directory")
	n1 := flag.Int("n1", 20, "individuals in party 1")
	n2 := flag.Int("n2", 20, "individuals in party 2")
	m := flag.Int("m", 30, "number of SNPs")
	ncov := flag.Int("ncov", 2, "number of covariates (intercept added separately by the protocol)")
	npheno := flag.Int("npheno", 2, "number of phenotypes")
	seed := flag.Int64("seed", 20260902, "RNG seed")
	flag.Parse()

	rng := rand.New(rand.NewSource(*seed))
	n := *n1 + *n2

	// Per-SNP ancestry/allele-frequency parameters.
	pAnc := make([]float64, *m)
	qAmr := make([]float64, *m)
	qEur := make([]float64, *m)
	for j := 0; j < *m; j++ {
		pAnc[j] = 0.3 + 0.4*rng.Float64()
		qAmr[j] = 0.2 + 0.6*rng.Float64()
		qEur[j] = 0.2 + 0.6*rng.Float64()
	}

	A := make([][]int8, n)
	Xamr := make([][]int8, n)
	Xeur := make([][]int8, n)
	X := make([][]int8, n)
	for i := 0; i < n; i++ {
		A[i] = make([]int8, *m)
		Xamr[i] = make([]int8, *m)
		Xeur[i] = make([]int8, *m)
		X[i] = make([]int8, *m)
		for j := 0; j < *m; j++ {
			a := binomial(rng, 2, pAnc[j])
			xa := binomial(rng, a, qAmr[j])
			xe := binomial(rng, 2-a, qEur[j])
			A[i][j] = int8(a)
			Xamr[i][j] = int8(xa)
			Xeur[i][j] = int8(xe)
			X[i][j] = int8(xa + xe)
		}
	}

	// Covariates: continuous, standard normal.
	Z := make([][]float64, n)
	for i := 0; i < n; i++ {
		Z[i] = make([]float64, *ncov)
		for c := 0; c < *ncov; c++ {
			Z[i][c] = rng.NormFloat64()
		}
	}

	// Phenotypes: covariate effects + a real genetic effect from SNP 0 (A, X_AMR, X_EUR)
	// so the comparison downstream is non-degenerate, matching
	// tests/unit_tests/tractor_projection_test.go's construction + noise.
	Y := make([][]float64, n)
	for i := range Y {
		Y[i] = make([]float64, *npheno)
	}
	for k := 0; k < *npheno; k++ {
		gamma := make([]float64, *ncov)
		for c := range gamma {
			gamma[c] = rng.NormFloat64() * 0.5
		}
		wA := rng.NormFloat64()*0.8 + 0.8
		wM := rng.NormFloat64()*0.8 + 0.8
		wE := rng.NormFloat64()*0.8 + 0.8
		for i := 0; i < n; i++ {
			v := 0.0
			for c := 0; c < *ncov; c++ {
				v += Z[i][c] * gamma[c]
			}
			v += wA*float64(A[i][0]) + wM*float64(Xamr[i][0]) + wE*float64(Xeur[i][0])
			v += rng.NormFloat64() * 1.5
			Y[i][k] = v
		}
	}

	writeParty(*outDir, "party1", 0, *n1, *m, A, Xamr, Xeur, X, Z, Y)
	writeParty(*outDir, "party2", *n1, *n2, *m, A, Xamr, Xeur, X, Z, Y)

	fmt.Printf("Wrote fixture to %s: n1=%d n2=%d m=%d ncov=%d npheno=%d\n", *outDir, *n1, *n2, *m, *ncov, *npheno)
}

func binomial(rng *rand.Rand, ntrials int, p float64) int {
	c := 0
	for i := 0; i < ntrials; i++ {
		if rng.Float64() < p {
			c++
		}
	}
	return c
}

func writeParty(outDir, party string, startRow, nrow, m int, A, Xamr, Xeur, X [][]int8, Z, Y [][]float64) {
	dir := filepath.Join(outDir, party)
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}

	writeGenoBin(filepath.Join(dir, "geno.0.bin"), A[startRow:startRow+nrow])
	writeGenoBin(filepath.Join(dir, "tractor_a.0.bin"), A[startRow:startRow+nrow])
	writeGenoBin(filepath.Join(dir, "tractor_amr.0.bin"), Xamr[startRow:startRow+nrow])
	writeGenoBin(filepath.Join(dir, "tractor_eur.0.bin"), Xeur[startRow:startRow+nrow])
	// geno.0.bin above intentionally holds A (unused: QC/PCA are skipped in the fixture
	// config), not X = X_AMR+X_EUR -- kept as A for simplicity since MatMult4StreamPlain
	// et al. never read it when skip_qc/skip_pca are both true.

	writeFloatMatrix(filepath.Join(dir, "cov.txt"), Z[startRow:startRow+nrow])
	writeFloatMatrix(filepath.Join(dir, "pheno.txt"), Y[startRow:startRow+nrow])

	f, err := os.Create(filepath.Join(dir, "snp_pos.txt"))
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(f)
	for j := 0; j < m; j++ {
		fmt.Fprintf(w, "1\t%d\n", 1_000_000+100*j)
	}
	w.Flush()
	f.Close()

	f, err = os.Create(filepath.Join(dir, "geno_block_sizes.txt"))
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(f, "%d\n", m)
	f.Close()
}

func writeGenoBin(path string, rows [][]int8) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	buf := make([]byte, len(rows[0]))
	for _, row := range rows {
		for j, v := range row {
			buf[j] = byte(v)
		}
		if _, err := w.Write(buf); err != nil {
			panic(err)
		}
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
}

func writeFloatMatrix(path string, rows [][]float64) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, row := range rows {
		for j, v := range row {
			if j > 0 {
				w.WriteString("\t")
			}
			if math.IsNaN(v) {
				panic("unexpected NaN")
			}
			fmt.Fprintf(w, "%.10g", v)
		}
		w.WriteString("\n")
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
}
