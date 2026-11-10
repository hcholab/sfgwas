// Command gen_tractor_fixture generates a tiny synthetic, ancestry-partitioned GWAS
// dataset split across two parties, in the exact file formats sfgwas's "blocks" genotype
// format and cov/pheno loaders expect (see gwas/filestream.go, gwas/utilities.go). It's
// the Tractor analog of scripts/plinkBedToBinary.py's role for the standard pipeline:
// producing real input files for a live 3-process run, not just a plaintext oracle.
//
// Run from the repo root: go run ./scripts/gen_tractor_fixture -out tractor_fixture
//
// With default flags the output is the historical n=40, m=30, one-block fixture. The
// optional flags only add features on top of the same random draws: -nblocks splits the
// SNPs into contiguous blocks, -ymean/-yscale make the phenotypes uncentered, and
// -missing/-bad-inds/-bad-snps/-rare (which use a separate RNG stream, so the base data
// never changes) add missing calls (-1, jointly in all streams) and low-frequency SNPs
// for exercising QC and the count filter. geno.<b>.bin holds the total alt-allele dosage
// X = X_AMR + X_EUR, which is what QC/PCA read.
package main

import (
	"bufio"
	"encoding/binary"
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
	nblocks := flag.Int("nblocks", 1, "number of contiguous SNP blocks (geno/tractor files per block)")
	ymean := flag.Float64("ymean", 0, "phenotype offset: y = ymean + yscale*y0")
	yscale := flag.Float64("yscale", 1, "phenotype scale: y = ymean + yscale*y0")
	missing := flag.Float64("missing", 0, "fraction of genotype entries set to missing (-1 in every stream)")
	badInds := flag.Float64("bad-inds", 0, "fraction of individuals with an extra 30% missing calls (for sample QC)")
	badSnps := flag.Float64("bad-snps", 0, "fraction of SNPs with an extra 20% missing calls (for SNP missingness QC)")
	rare := flag.Float64("rare", 0, "fraction of SNPs whose allele frequencies are divided by 10 (for MAF QC / count filter)")
	flag.Parse()

	if *nblocks < 1 || *nblocks > *m {
		panic("need 1 <= nblocks <= m")
	}

	rng := rand.New(rand.NewSource(*seed))
	// Extra features draw from their own stream so the base data stays identical.
	rngX := rand.New(rand.NewSource(*seed + 1))
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

	rareSnp := make([]bool, *m)
	badSnp := make([]bool, *m)
	for j := 0; j < *m; j++ {
		rareSnp[j] = rngX.Float64() < *rare
		badSnp[j] = rngX.Float64() < *badSnps
		if rareSnp[j] {
			qAmr[j] /= 10
			qEur[j] /= 10
		}
	}
	badInd := make([]bool, n)
	for i := range badInd {
		badInd[i] = rngX.Float64() < *badInds
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

	// Missing calls, jointly in every stream (a missing genotype carries no ancestry or
	// dosage information). The phenotype below uses the zero-imputed dosages, the same
	// imputation the protocol and the oracles apply.
	nmiss := 0
	if *missing > 0 || *badInds > 0 || *badSnps > 0 {
		for i := 0; i < n; i++ {
			for j := 0; j < *m; j++ {
				rate := *missing
				if badInd[i] {
					rate += 0.3
				}
				if badSnp[j] {
					rate += 0.2
				}
				if rngX.Float64() < rate {
					A[i][j], Xamr[i][j], Xeur[i][j], X[i][j] = -1, -1, -1, -1
					nmiss++
				}
			}
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
			v += wA*float64(max(A[i][0], 0)) + wM*float64(max(Xamr[i][0], 0)) + wE*float64(max(Xeur[i][0], 0))
			v += rng.NormFloat64() * 1.5
			Y[i][k] = v
		}
	}

	for i := range Y {
		for k := range Y[i] {
			Y[i][k] = *ymean + *yscale*Y[i][k]
		}
	}

	// Contiguous blocks, sizes as even as possible (the first m mod nblocks get one more).
	sizes := make([]int, *nblocks)
	for b := range sizes {
		sizes[b] = *m / *nblocks
		if b < *m%*nblocks {
			sizes[b]++
		}
	}

	writeParty(*outDir, "party1", 0, *n1, *m, sizes, A, Xamr, Xeur, X, Z, Y)
	writeParty(*outDir, "party2", *n1, *n2, *m, sizes, A, Xamr, Xeur, X, Z, Y)

	fmt.Printf("Wrote fixture to %s: n1=%d n2=%d m=%d ncov=%d npheno=%d blocks=%v missing=%d entries\n",
		*outDir, *n1, *n2, *m, *ncov, *npheno, sizes, nmiss)
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

func writeParty(outDir, party string, startRow, nrow, m int, sizes []int, A, Xamr, Xeur, X [][]int8, Z, Y [][]float64) {
	dir := filepath.Join(outDir, party)
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}

	col := 0
	for b, size := range sizes {
		cols := func(M [][]int8) [][]int8 {
			out := make([][]int8, nrow)
			for i := range out {
				out[i] = M[startRow+i][col : col+size]
			}
			return out
		}
		writeGenoBin(filepath.Join(dir, fmt.Sprintf("geno.%d.bin", b)), cols(X))
		writeGenoBin(filepath.Join(dir, fmt.Sprintf("tractor_a.%d.bin", b)), cols(A))
		writeGenoBin(filepath.Join(dir, fmt.Sprintf("tractor_amr.%d.bin", b)), cols(Xamr))
		writeGenoBin(filepath.Join(dir, fmt.Sprintf("tractor_eur.%d.bin", b)), cols(Xeur))
		col += size
	}

	writeGenoCounts(filepath.Join(dir, "all.gcount.transpose.bin"), X[startRow:startRow+nrow], m)

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
	for _, size := range sizes {
		fmt.Fprintf(f, "%d\n", size)
	}
	f.Close()
}

// writeGenoCounts writes this party's per-SNP genotype counts of X in the layout
// gwas.ReadGenoStatsFromFile reads (what scripts/computeGenoCounts.py builds from plink2
// --geno-counts): six little-endian uint32 vectors of length m -- hom-ref, het, hom-alt,
// two haploid counts (always 0 here), missing -- for QC with use_precomputed_geno_count.
func writeGenoCounts(path string, rows [][]int8, m int) {
	counts := make([][]uint32, 6)
	for s := range counts {
		counts[s] = make([]uint32, m)
	}
	for _, row := range rows {
		for j, v := range row {
			switch {
			case v < 0:
				counts[5][j]++
			default:
				counts[v][j]++ // 0, 1, 2
			}
		}
	}
	buf := make([]byte, 0, 6*4*m)
	for _, c := range counts {
		for _, v := range c {
			buf = binary.LittleEndian.AppendUint32(buf, v)
		}
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		panic(err)
	}
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
