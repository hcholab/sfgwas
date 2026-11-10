package e2etests

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hcholab/sfgwas/gwas"
	"gonum.org/v1/gonum/mat"
)

// TestTractorOracle recomputes the Tractor statistics of a completed 3-party run in
// plaintext (gwas.TractorStatsPlain, which tests/unit_tests/tractor_projection_test.go
// validates against an explicit full regression) from the parties' raw input files, and
// compares them with out/party1*/tractor_<k>.txt, the values the MPC protocol revealed.
//
// Everything is read from the run's own configuration: the input paths, the thresholds
// (tractor_count_threshold, tractor_det_tol), the block layout, QC (the sample filter
// cache/party*/ikeep.txt and the SNP filters gkeep*.txt, applied exactly as the protocol
// applies them, and cross-checked against tractor_snp_index.txt) and PCs (pca.txt).
// Missing calls are imputed as 0, as in the protocol.
//
// Set SFGWAS_TRACTOR_RUN_DIR to the directory the parties ran in (the one holding
// config/tractor/); relative paths in the config are resolved against it. It defaults
// to the repository root. The test skips when that run has produced no output -- check
// `go test -v`, a skip prints as ok.
//
// Acceptance, for every phenotype and effect (A, AMR, EUR), on SNPs valid in both:
// validity flags identical; |Δbeta|/SE <= 1e-2, |ΔSE|/SE <= 1e-3, |Δt| <= 1e-2 + 1e-3|t|,
// |Δlog10 p| <= 1e-2; and at least a quarter of the SNPs actually compared.
//
//	go run ./scripts/gen_tractor_fixture -out tractor_fixture
//	for i in 0 1 2; do PID=$i PROTOCOL=tractor RUN_STAGE=all go run sfgwas.go & done; wait
//	go test ./tests/e2e_tests/ -run TestTractorOracle -v
//
// scripts/run_tractor_scenarios.sh runs scenario directories end to end.
func TestTractorOracle(t *testing.T) {
	const (
		tolBeta = 1e-2 // |Δbeta| / SE_ref
		tolSE   = 1e-3 // |ΔSE| / SE_ref
		tolT    = 1e-2 // |Δt| <= tolT + tolSE*|t_ref|
		tolLogP = 1e-2 // |Δ log10 p|
	)

	runDir := os.Getenv("SFGWAS_TRACTOR_RUN_DIR")
	if runDir == "" {
		runDir = repoRoot(t)
	}
	run := loadTractorRun(t, runDir)

	probe := filepath.Join(run.outDir, "tractor_0.txt")
	if _, err := os.Stat(probe); err != nil {
		t.Skipf("no Tractor run output at %s -- run the protocol first (see doc comment)", probe)
	}

	Z, Y, A, Xamr, Xeur, snpIndex := run.pooledInputs(t)
	t.Logf("run %s: n=%d, %d covariates incl. intercept, %d phenotypes, %d/%d SNPs after QC; count_threshold=%d det_tol=%g",
		runDir, Z.RawMatrix().Rows, Z.RawMatrix().Cols, Y.RawMatrix().Cols, len(snpIndex), run.global.NumSnps,
		run.global.TractorCountThreshold, run.global.TractorDetTol)

	indexFile := filepath.Join(run.outDir, "tractor_snp_index.txt")
	if _, err := os.Stat(indexFile); err != nil {
		t.Fatalf("%s has tractor_0.txt but no tractor_snp_index.txt: the output predates the current protocol; rerun it", run.outDir)
	}
	gotIndex := readIntLines(t, indexFile, 0)
	if fmt.Sprint(gotIndex) != fmt.Sprint(snpIndex) {
		t.Fatalf("tractor_snp_index.txt lists SNPs %v, expected %v from the QC filters", gotIndex, snpIndex)
	}

	want := gwas.TractorStatsPlain(Z, Y, A, Xamr, Xeur, run.global.TractorCountThreshold, run.global.TractorDetTol)
	m := len(snpIndex)
	_, npheno := Y.Dims()

	for k := 0; k < npheno; k++ {
		got := loadRevealed(t, run.outDir, k)
		if len(got) != m {
			t.Fatalf("phenotype %d: output has %d SNPs, oracle has %d", k, len(got), m)
		}

		var worst struct{ beta, se, tstat, logp float64 }
		var worstAt struct{ beta, se, tstat, logp string }
		nCompared, nMismatch := 0, 0
		for j := 0; j < m; j++ {
			wv := want.PhenoValid[k][j]
			if wv != got[j].valid {
				nMismatch++
				t.Errorf("SNP %d (global %d) pheno %d: validity mismatch: oracle=%v revealed=%v (oracle det=%.6g, counts %v/%v/%v/%v/%v/%v)",
					j, snpIndex[j], k, wv, got[j].valid, want.Det[j], want.NAMRHaps[j], want.NEURHaps[j],
					want.AltAMR[j], want.RefAMR[j], want.AltEUR[j], want.RefEUR[j])
				continue
			}
			if !wv {
				continue
			}
			nCompared++
			for _, e := range []struct {
				name                     string
				gb, gse, gp, wb, wse, wt float64
				wp                       float64
			}{
				{"A", got[j].betaA, got[j].seA, got[j].pA, want.BetaA.At(j, k), want.SEA.At(j, k), want.TA.At(j, k), want.PA.At(j, k)},
				{"AMR", got[j].betaM, got[j].seM, got[j].pM, want.BetaAMR.At(j, k), want.SEAMR.At(j, k), want.TAMR.At(j, k), want.PAMR.At(j, k)},
				{"EUR", got[j].betaE, got[j].seE, got[j].pE, want.BetaEUR.At(j, k), want.SEEUR.At(j, k), want.TEUR.At(j, k), want.PEUR.At(j, k)},
			} {
				where := fmt.Sprintf("SNP %d pheno %d %s", j, k, e.name)
				dBeta := math.Abs(e.gb-e.wb) / e.wse
				dSE := math.Abs(e.gse-e.wse) / e.wse
				gt := e.gb / e.gse
				dT := math.Abs(gt - e.wt)
				dLogP := math.Abs(log10p(e.gp) - log10p(e.wp))
				for _, c := range []struct {
					name    string
					v, tol  float64
					worst   *float64
					worstAt *string
				}{
					{"beta", dBeta, tolBeta, &worst.beta, &worstAt.beta},
					{"se", dSE, tolSE, &worst.se, &worstAt.se},
					{"t", dT, tolT + tolSE*math.Abs(e.wt), &worst.tstat, &worstAt.tstat},
					{"log10p", dLogP, tolLogP, &worst.logp, &worstAt.logp},
				} {
					if math.IsNaN(c.v) || c.v > c.tol {
						t.Errorf("%s: %s off by %.3g (tolerance %.3g): got beta=%g se=%g p=%g, want beta=%g se=%g p=%g",
							where, c.name, c.v, c.tol, e.gb, e.gse, e.gp, e.wb, e.wse, e.wp)
					}
					if !(c.v <= *c.worst) {
						*c.worst, *c.worstAt = c.v, where
					}
				}
			}
		}
		t.Logf("phenotype %d: %d/%d SNPs compared, %d validity mismatches; max |Δbeta|/SE=%.3g (%s), |ΔSE|/SE=%.3g (%s), |Δt|=%.3g (%s), |Δlog10p|=%.3g (%s)",
			k, nCompared, m, nMismatch, worst.beta, worstAt.beta, worst.se, worstAt.se, worst.tstat, worstAt.tstat, worst.logp, worstAt.logp)
		if minCompared := max(1, m/4); nCompared < minCompared {
			t.Errorf("phenotype %d: only %d SNPs valid in both (need %d); the comparison is close to vacuous", k, nCompared, minCompared)
		}
	}
}

// log10p is log10(p), with p = 0 (underflow) mapped to the smallest positive double so
// two underflowed p-values compare equal.
func log10p(p float64) float64 {
	return math.Log10(math.Max(p, math.SmallestNonzeroFloat64))
}

// tractorRun is a completed run's configuration with paths resolved.
type tractorRun struct {
	dir    string
	global *gwas.Config
	cfgs   []*gwas.Config // index = party id (1..N)
	outDir string         // party 1's output directory
}

func loadTractorRun(t *testing.T, runDir string) *tractorRun {
	t.Helper()
	cfgDir := filepath.Join(runDir, "config", "tractor")
	global := loadConfig(t, filepath.Join(cfgDir, "configGlobal.toml"), nil)
	r := &tractorRun{dir: runDir, global: global, cfgs: make([]*gwas.Config, global.NumMainParties+1)}
	for p := 1; p <= global.NumMainParties; p++ {
		r.cfgs[p] = loadConfig(t, filepath.Join(cfgDir, fmt.Sprintf("configLocal.Party%d.toml", p)), global)
	}
	r.outDir = r.path(r.cfgs[1].OutDir)
	return r
}

// path resolves a config path the way the protocol did: relative to the run directory.
func (r *tractorRun) path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(r.dir, p)
}

func (r *tractorRun) qcEnabled() bool { return !r.global.SkipQC || r.global.UseCachedQC }

// snpFilter reproduces the protocol's SNP selection: the QC filter over all SNPs (the
// precomputed-counts path writes gkeep.txt; the per-block path gkeep_miss.txt and then
// gkeep_maf_hwe.txt over the SNPs that survived it), restricted to the blocks under test.
func (r *tractorRun) snpFilter(t *testing.T) []bool {
	t.Helper()
	g := r.global
	keep := make([]bool, g.NumSnps)
	for i := range keep {
		keep[i] = true
	}
	if r.qcEnabled() {
		cache := r.path(r.cfgs[1].CacheDir)
		if g.UsePrecomputedGenoCount {
			keep = readBoolLines(t, filepath.Join(cache, "gkeep.txt"), g.NumSnps)
		} else {
			miss := readBoolLines(t, filepath.Join(cache, "gkeep_miss.txt"), g.NumSnps)
			nmiss := 0
			for _, v := range miss {
				if v {
					nmiss++
				}
			}
			mafHwe := readBoolLines(t, filepath.Join(cache, "gkeep_maf_hwe.txt"), nmiss)
			idx := 0
			for i := range keep {
				keep[i] = false
				if miss[i] {
					keep[i] = mafHwe[idx]
					idx++
				}
			}
		}
	}
	sizes := readIntLines(t, r.path(r.cfgs[1].GenoBlockSizeFile), g.GenoNumBlocks)
	shift := 0
	for b, size := range sizes {
		if !blockInAssocTest(g, b) {
			for i := shift; i < shift+size; i++ {
				keep[i] = false
			}
		}
		shift += size
	}
	return keep
}

// pooledInputs stacks every party's QC-filtered samples (party 1 first, as in the
// protocol's PCA/pheno ordering) and returns Z = [1 | cov | PCs], Y, and the three
// ancestry matrices over the kept SNPs, plus the kept SNPs' global indices.
func (r *tractorRun) pooledInputs(t *testing.T) (Z, Y, A, Xamr, Xeur *mat.Dense, snpIndex []int) {
	t.Helper()
	g := r.global
	snpKeep := r.snpFilter(t)
	for i, v := range snpKeep {
		if v {
			snpIndex = append(snpIndex, i)
		}
	}
	m := len(snpIndex)
	sizes := readIntLines(t, r.path(r.cfgs[1].GenoBlockSizeFile), g.GenoNumBlocks)
	npc := 0
	if g.NumPCs > 0 && (!g.SkipPCA || g.UseCachedPCA) {
		npc = g.NumPCs
	}

	var zRows, yRows, aRows, mRows, eRows [][]float64
	for p := 1; p <= g.NumMainParties; p++ {
		cfg := r.cfgs[p]
		nInd := g.NumInds[p]
		cov := gwas.LoadMatrixFromFile(r.path(cfg.CovFile), '\t')
		pheno := gwas.LoadMatrixFromFile(r.path(cfg.PhenoFile), '\t')
		if rr, _ := cov.Dims(); rr != nInd {
			t.Fatalf("party %d: %d covariate rows, num_inds says %d", p, rr, nInd)
		}
		if rr, _ := pheno.Dims(); rr != nInd {
			t.Fatalf("party %d: %d phenotype rows, num_inds says %d", p, rr, nInd)
		}

		sampleKeep := make([]bool, nInd)
		for i := range sampleKeep {
			sampleKeep[i] = true
		}
		if r.qcEnabled() && !g.UsePrecomputedGenoCount {
			sampleKeep = readBoolLines(t, filepath.Join(r.path(cfg.CacheDir), "ikeep.txt"), nInd)
		}

		var pcs *mat.Dense
		if npc > 0 {
			pcs = gwas.LoadMatrixFromFile(filepath.Join(r.path(cfg.OutDir), "pca.txt"), ',') // npc-by-kept samples
		}

		// Ancestry streams, all blocks side by side, kept SNPs only.
		streams := [3][][]float64{}
		for x, prefix := range []string{cfg.TractorGenoPrefixA, cfg.TractorGenoPrefixAMR, cfg.TractorGenoPrefixEUR} {
			streams[x] = make([][]float64, nInd)
			for i := range streams[x] {
				streams[x][i] = make([]float64, 0, m)
			}
			shift := 0
			for b, size := range sizes {
				raw, err := os.ReadFile(fmt.Sprintf("%s.%d.bin", r.path(prefix), b))
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) != nInd*size {
					t.Fatalf("%s.%d.bin: %d bytes, expected %d x %d", prefix, b, len(raw), nInd, size)
				}
				for i := 0; i < nInd; i++ {
					for j := 0; j < size; j++ {
						if snpKeep[shift+j] {
							streams[x][i] = append(streams[x][i], float64(int8(raw[i*size+j])))
						}
					}
				}
				shift += size
			}
		}

		kept := 0
		_, ncov := cov.Dims()
		_, nph := pheno.Dims()
		for i := 0; i < nInd; i++ {
			if !sampleKeep[i] {
				continue
			}
			z := []float64{1}
			for c := 0; c < ncov; c++ {
				z = append(z, cov.At(i, c))
			}
			for c := 0; c < npc; c++ {
				z = append(z, pcs.At(c, kept))
			}
			y := make([]float64, nph)
			for c := range y {
				y[c] = pheno.At(i, c)
			}
			zRows, yRows = append(zRows, z), append(yRows, y)
			aRows, mRows, eRows = append(aRows, streams[0][i]), append(mRows, streams[1][i]), append(eRows, streams[2][i])
			kept++
		}
		if npc > 0 {
			if _, pc := pcs.Dims(); pc != kept {
				t.Fatalf("party %d: pca.txt has %d samples, QC kept %d", p, pc, kept)
			}
		}
	}

	return denseFromRows(zRows), denseFromRows(yRows), denseFromRows(aRows), denseFromRows(mRows), denseFromRows(eRows), snpIndex
}

func denseFromRows(rows [][]float64) *mat.Dense {
	d := mat.NewDense(len(rows), len(rows[0]), nil)
	for i, r := range rows {
		d.SetRow(i, r)
	}
	return d
}

type revealedRow struct {
	betaA, seA, pA float64
	betaM, seM, pM float64
	betaE, seE, pE float64
	valid          bool
}

func loadRevealed(t *testing.T, dir string, pheno int) []revealedRow {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "tractor_"+strconv.Itoa(pheno)+".txt"))
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
