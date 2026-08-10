package e2etests

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/hcholab/sfgwas/gwas"
	"github.com/hcholab/sfgwas/tests/testutil"
	"gonum.org/v1/gonum/mat"
)

// TestAssocPlaintextOracle recomputes the association statistics of a completed run
// entirely in plaintext float64 and compares them against out/party*/assoc_*.txt.
//
// This is an absolute reference, not an A-vs-B check: it catches the case where the
// legacy and lazy paths agree with each other but are both wrong. It reuses the run's
// QC filter (cache/party*/gkeep.txt) and its PCs (out/party*/pca.txt), since those are
// inputs to phase 3 rather than part of what phase 3 computes; everything downstream —
// orthonormalization, projection, and the correlation itself — is computed here
// independently, with an explicit Gram-Schmidt basis and no eigendecomposition.
//
// The test skips unless a run has already produced output. It reads both parties' data
// directly, which is fine for the local synthetic dataset and is exactly what makes an
// absolute reference possible.
//
// Prerequisites are the same as the pipeline's: plink2 and python3 on PATH.
//
//	./compare_assoc_paths.sh && go test ./tests/e2e_tests/ -run TestAssocPlaintextOracle -v
func TestAssocPlaintextOracle(t *testing.T) {
	runAssocPlaintextOracle(t, "", func(t *testing.T, Z *mat.Dense, ntot int, dumpDir string) *mat.Dense {
		return testutil.GramSchmidt(Z)
	})
}

// TestAssocPlaintextOracleCholesky is TestAssocPlaintextOracle's same absolute
// reference, but projects out covariates via Cholesky-QR (testutil.Cholesky)
// instead of Gram-Schmidt -- the identical mathematical path as the secure
// protocol's default covariate-orthogonalization branch (mpc.MPC.CholeskyInvSqrt,
// wired up in gwas.computeCovOrthoFactor), just in plain float64 instead of
// truncated fixed-point secret shares.
//
// Two comparisons this enables that TestAssocPlaintextOracle alone can't:
//
//   - A divergence from TestAssocPlaintextOracle's Gram-Schmidt result that shows up
//     HERE too (both plaintext, both full float64 precision) points at Z'Z's
//     conditioning, not fixed-point truncation -- Cholesky-QR is exactly as
//     sensitive to an ill-conditioned Z'Z as the secure protocol's CholeskyInvSqrt
//     is (see its doc comment), where Gram-Schmidt sidesteps the question entirely.
//   - With SFGWAS_ORACLE_DUMP set, this dumps oracle_cholesky_L.txt and
//     oracle_cholesky_Linv.txt at the same scale (alpha=1/sqrt(n)) the protocol
//     itself uses, so they're directly diffable against a debug=true run's own
//     cache/party*/cholesky_L.txt and cholesky_Linv.txt -- isolating a divergence to
//     the exact Cholesky-Crout step where the two stop agreeing, rather than only
//     seeing it show up several stages later in sxx/sxy.
func TestAssocPlaintextOracleCholesky(t *testing.T) {
	runAssocPlaintextOracle(t, "cholesky_", func(t *testing.T, Z *mat.Dense, ntot int, dumpDir string) *mat.Dense {
		alpha := 1 / math.Sqrt(float64(ntot)) // matches ZtZss's scale in gwas.GetAssociationStatsPlainMult
		Q, L, Linv, err := testutil.Cholesky(Z, alpha)
		if err != nil {
			t.Fatalf("cholesky: %v", err)
		}
		if dumpDir != "" {
			gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, "oracle_cholesky_L.txt"), denseRows(L))
			gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, "oracle_cholesky_Linv.txt"), denseRows(Linv))

			// S = scaling*Linv, matching gwas.CholeskyInvSqrt's returned S (the actual
			// factor applied to ZtX/ZtY1, distinct from the un-scaled Linv above) --
			// compare against cache/party*/cholesky_S.txt.
			var S mat.Dense
			S.Scale(math.Pow(float64(ntot), 0.25), Linv)
			gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, "oracle_cholesky_S.txt"), denseRows(&S))

			t.Logf("dumped oracle Cholesky L/Linv/S to %s", dumpDir)
		}
		return Q
	})
}

// denseRows converts m to row-major [][]float64, e.g. for gwas.SaveFloatMatrixToFileRowMajor.
func denseRows(m *mat.Dense) [][]float64 {
	r, c := m.Dims()
	rows := make([][]float64, r)
	for i := range rows {
		rows[i] = make([]float64, c)
		for j := 0; j < c; j++ {
			rows[i][j] = m.At(i, j)
		}
	}
	return rows
}

// runAssocPlaintextOracle holds the logic shared by TestAssocPlaintextOracle and
// TestAssocPlaintextOracleCholesky: load the pooled data, compute an orthonormal
// covariate basis via computeQ, stream the genotype blocks, and compare the
// resulting per-SNP statistics against the protocol's own assoc_*.txt output.
// filePrefix (e.g. "" or "cholesky_") namespaces the SFGWAS_ORACLE_DUMP output so
// two variants can dump to the same directory without overwriting each other.
func runAssocPlaintextOracle(t *testing.T, filePrefix string, computeQ func(t *testing.T, Z *mat.Dense, ntot int, dumpDir string) *mat.Dense) {
	root := repoRoot(t)
	if err := os.Chdir(root); err != nil { // FilterMatrixFilePgen shells out via a relative path
		t.Fatalf("chdir %s: %v", root, err)
	}

	global := loadConfig(t, "config/gwas/configGlobal.toml", nil)
	if !strings.EqualFold(global.GenoFileFormat, "pgen") {
		t.Skipf("oracle only implements the pgen input path; config says %q", global.GenoFileFormat)
	}
	if _, err := exec.LookPath("plink2"); err != nil {
		t.Skip("plink2 not on PATH; the pipeline needs it too")
	}

	nparty := global.NumMainParties
	cfgs := make([]*gwas.Config, nparty+1)
	for p := 1; p <= nparty; p++ {
		cfgs[p] = loadConfig(t, fmt.Sprintf("config/gwas/configLocal.Party%d.toml", p), global)
	}

	// Must check party 1's OWN configured OutDir, not a hardcoded "out/party1": that
	// hardcoding happened to match the local example config (output_dir = "out/party1")
	// but silently mismatches any deployment using a different output_dir (e.g.
	// "../out/party1"), which makes this Stat always fail and the whole test silently
	// Skip -- reporting as a pass (exit 0), with no comparison ever having run.
	assocProbe := filepath.Join(cfgs[1].OutDir, "assoc_0.txt")
	if _, err := os.Stat(assocProbe); err != nil {
		t.Skipf("no run output found at %s; run the pipeline first", assocProbe)
	}

	blockSizes := readIntLines(t, cfgs[1].GenoBlockSizeFile, cfgs[1].GenoNumBlocks)

	// The QC filter is computed jointly, so every party must hold the same one.
	gkeep := readBoolLines(t, filepath.Join(cfgs[1].CacheDir, "gkeep.txt"), global.NumSnps)
	for p := 2; p <= nparty; p++ {
		other := readBoolLines(t, filepath.Join(cfgs[p].CacheDir, "gkeep.txt"), global.NumSnps)
		for i := range gkeep {
			if gkeep[i] != other[i] {
				t.Fatalf("gkeep.txt differs between party 1 and party %d at index %d", p, i)
			}
		}
	}

	// ---- Pooled covariate/phenotype matrices, individuals stacked party by party ----
	type partyData struct {
		nind   int
		offset int // row offset into the pooled matrices
	}
	parties := make([]partyData, nparty+1)

	var Zrows, Yrows [][]float64
	npheno, ncovIn, npc := 0, 0, global.NumPCs
	for p := 1; p <= nparty; p++ {
		pheno := gwas.LoadMatrixFromFile(cfgs[p].PhenoFile, '\t')
		cov := gwas.LoadMatrixFromFile(cfgs[p].CovFile, '\t')
		qpc := gwas.LoadMatrixFromFile(filepath.Join(cfgs[p].OutDir, "pca.txt"), ',') // npc-by-nind

		nind, nph := pheno.Dims()
		ncr, ncc := cov.Dims()
		qr, qc := qpc.Dims()
		if ncr != nind || qc != nind {
			t.Fatalf("party %d: %d individuals in pheno, %d in cov, %d in pca.txt", p, nind, ncr, qc)
		}
		if p == 1 {
			npheno, ncovIn = nph, ncc
			if qr != npc {
				t.Fatalf("pca.txt has %d rows, config says num_pcs_to_remove=%d", qr, npc)
			}
		} else if nph != npheno || ncc != ncovIn {
			t.Fatalf("party %d: pheno/cov widths %d/%d differ from party 1's %d/%d", p, nph, ncc, npheno, ncovIn)
		}

		parties[p] = partyData{nind: nind, offset: len(Zrows)}
		for i := 0; i < nind; i++ {
			z := make([]float64, 0, 1+ncovIn+npc)
			z = append(z, 1) // intercept
			for j := 0; j < ncovIn; j++ {
				z = append(z, cov.At(i, j))
			}
			for j := 0; j < npc; j++ {
				z = append(z, qpc.At(j, i))
			}
			Zrows = append(Zrows, z)

			y := make([]float64, npheno)
			for j := 0; j < npheno; j++ {
				y[j] = pheno.At(i, j)
			}
			Yrows = append(Yrows, y)
		}
	}

	ntot := len(Zrows)
	k := 1 + ncovIn + npc
	Z := mat.NewDense(ntot, k, nil)
	Y := mat.NewDense(ntot, npheno, nil)
	for i := 0; i < ntot; i++ {
		Z.SetRow(i, Zrows[i])
		Y.SetRow(i, Yrows[i])
	}
	t.Logf("pooled: %d individuals, %d covariates (incl. intercept and %d PCs), %d phenotypes", ntot, k, npc, npheno)

	dumpDir := os.Getenv("SFGWAS_ORACLE_DUMP")

	if dumpDir != "" {
		nInvSqrt := math.Sqrt(1 / float64(ntot))
		var A mat.SymDense
		A.SymOuterK(nInvSqrt, mat.DenseCopyOf(Z.T()))

		// A is exactly ZtZss from gwas.GetAssociationStatsPlainMult (same alpha=1/sqrt(n)
		// scale) -- the earliest checkpoint in the whole covariate-orthogonalization
		// chain, dumped unprefixed since it doesn't depend on Gram-Schmidt vs. Cholesky.
		gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, "oracle_ZtZ.txt"), denseRows(mat.DenseCopyOf(&A)))

		var eig mat.EigenSym
		if !eig.Factorize(&A, true) {
			t.Fatalf("eigendecomposition failed")
		}
		lambda := eig.Values(nil)
		invSqrt := make([]float64, len(lambda))
		for i, l := range lambda {
			invSqrt[i] = 1 / math.Sqrt(l)
		}
		writeFloatLine(t, filepath.Join(dumpDir, "oracle_eigenvalues.txt"), lambda)
		writeFloatLine(t, filepath.Join(dumpDir, "oracle_invsqrt_eigenvalues.txt"), invSqrt)
		t.Logf("dumped Z'Z/n eigenvalues to %s", dumpDir)
	}

	// ---- Explicit orthonormal basis and the residualized phenotypes ----
	Q := computeQ(t, Z, ntot, dumpDir)

	if dumpDir != "" {
		// QtY1 = Qᵀ[Y|1] is the same S-application step as the per-block ztx/qtx below,
		// but computed once -- a cheap, early checkpoint against cache/party*/QtY1.txt.
		Y1 := mat.NewDense(ntot, npheno+1, nil)
		for i := 0; i < ntot; i++ {
			Y1.SetRow(i, append(append([]float64{}, Yrows[i]...), 1))
		}
		var QtY1 mat.Dense
		QtY1.Mul(Q.T(), Y1)
		gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, fmt.Sprintf("oracle_%sQtY1.txt", filePrefix)), denseRows(&QtY1))
	}

	var QtY, QQtY, Ynew mat.Dense
	QtY.Mul(Q.T(), Y)
	QQtY.Mul(Q, &QtY)
	Ynew.Sub(Y, &QQtY)

	syy := make([]float64, npheno)
	for j := 0; j < npheno; j++ {
		var s float64
		for i := 0; i < ntot; i++ {
			s += Ynew.At(i, j) * Ynew.At(i, j)
		}
		syy[j] = s
	}

	// ---- Stream the genotype blocks and accumulate the per-SNP statistics ----
	var gotR [][]float64 // [pheno][snp], in the protocol's output order
	for i := 0; i < npheno; i++ {
		gotR = append(gotR, nil)
	}

	// Debugging aid: dump the intermediate sxx/sxy/syy this oracle computes, not just
	// the final ratio, so a divergent path's own debug output (sxx.txt, sxy.txt,
	// syy.txt) can be compared stage by stage instead of only at the end.
	var sxxAll []float64
	sxyAll := make([][]float64, npheno)

	// ztx/qtx bracket the same S-application step as gwas.GetAssociationStatsPlainMult's
	// ztxBlocks/qtxBlocks (ztx = (ZtX)/sqrt(n) pre-projection, qtx = QtX post-projection);
	// xtxAll is diag(XtX) before the proj2 subtraction that turns it into sxx. k rows
	// each, one per covariate/PC dimension, growing across blocks like sxyAll.
	ztxAll := make([][]float64, k)
	qtxAll := make([][]float64, k)
	var xtxAll []float64
	nrowsTotalInvSqrt := 1 / math.Sqrt(float64(ntot))

	tmpDir := t.TempDir()
	shift := 0
	for b := 0; b < cfgs[1].GenoNumBlocks; b++ {
		blockFilt := gkeep[shift : shift+blockSizes[b]]
		nsnp := 0
		for _, v := range blockFilt {
			if v {
				nsnp++
			}
		}
		if nsnp == 0 || !blockInAssocTest(global, b) {
			shift += blockSizes[b]
			continue
		}

		QtX := mat.NewDense(k, nsnp, nil)       // Qᵀ X, accumulated across parties
		ZtX := mat.NewDense(k, nsnp, nil)       // Zᵀ X, accumulated across parties (pre-projection)
		YntX := mat.NewDense(npheno, nsnp, nil) // Ynewᵀ X
		xtx := make([]float64, nsnp)            // diag(XᵀX)

		for p := 1; p <= nparty; p++ {
			X := readGenoBlock(t, cfgs[p], b, shift, blockFilt, parties[p].nind, nsnp,
				filepath.Join(tmpDir, fmt.Sprintf("gfs.%d.%d", p, b)))

			off, nind := parties[p].offset, parties[p].nind
			Qp := Q.Slice(off, off+nind, 0, k)
			Zp := Z.Slice(off, off+nind, 0, k)
			Yp := Ynew.Slice(off, off+nind, 0, npheno)

			var qtx, ztx, yntx mat.Dense
			qtx.Mul(Qp.T(), X)
			ztx.Mul(Zp.T(), X)
			yntx.Mul(Yp.T(), X)
			QtX.Add(QtX, &qtx)
			ZtX.Add(ZtX, &ztx)
			YntX.Add(YntX, &yntx)

			for j := 0; j < nsnp; j++ {
				for i := 0; i < nind; i++ {
					v := X.At(i, j)
					xtx[j] += v * v
				}
			}
		}

		ZtX.Scale(nrowsTotalInvSqrt, ZtX) // (ZᵀX)/sqrt(n), matching gwas's ZtXscaled

		for j := 0; j < nsnp; j++ {
			var proj2 float64
			for c := 0; c < k; c++ {
				proj2 += QtX.At(c, j) * QtX.At(c, j)
			}
			sxx := xtx[j] - proj2
			sxxAll = append(sxxAll, sxx)
			xtxAll = append(xtxAll, xtx[j])
			for c := 0; c < k; c++ {
				ztxAll[c] = append(ztxAll[c], ZtX.At(c, j))
				qtxAll[c] = append(qtxAll[c], QtX.At(c, j))
			}
			for i := 0; i < npheno; i++ {
				sxyAll[i] = append(sxyAll[i], YntX.At(i, j))
				gotR[i] = append(gotR[i], YntX.At(i, j)/(math.Sqrt(sxx)*math.Sqrt(syy[i])))
			}
		}

		shift += blockSizes[b]
		t.Logf("block %d/%d: %d SNPs", b+1, cfgs[1].GenoNumBlocks, nsnp)
	}

	if dumpDir != "" {
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%ssxx.txt", filePrefix)), sxxAll)
		for i := 0; i < npheno; i++ {
			writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%ssxy_%d.txt", filePrefix, i)), sxyAll[i])
		}
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%ssyy.txt", filePrefix)), syy)

		// sx/sy/varx/vary mirror gwas.GetAssociationStatsPlainMult's own debug dump
		// (sx.txt, sy.txt, varx.txt, vary.txt): Z there always has the intercept
		// prepended, forcing covAllOnes=true, which forces sx/sy to the zero vector and
		// varx/vary to plain aliases of sxx/syy (see assoc.go's "else { varx = sxx; vary
		// = syy }" branch). Z here is built the same way (z = append(z, 1) first), so
		// the same identities hold -- dumped explicitly so the file-for-file diff
		// against cache/party*/{sx,sy,varx,vary}.txt doesn't require remembering that.
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%ssx.txt", filePrefix)), make([]float64, len(sxxAll)))
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%ssy.txt", filePrefix)), make([]float64, npheno))
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%svarx.txt", filePrefix)), sxxAll)
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%svary.txt", filePrefix)), syy)

		// ztx/qtx/xtxdiag bracket the S-application step and the BtB subtraction --
		// compare against cache/party*/{ztx,qtx,xtxdiag}.txt (after masking with
		// xfilt.bin) to isolate a divergence to before S is applied, to the S-multiply
		// itself, or to the final BtB subtraction that produces sxx.
		gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, fmt.Sprintf("oracle_%sztx.txt", filePrefix)), ztxAll)
		gwas.SaveFloatMatrixToFileRowMajor(filepath.Join(dumpDir, fmt.Sprintf("oracle_%sqtx.txt", filePrefix)), qtxAll)
		writeFloatLine(t, filepath.Join(dumpDir, fmt.Sprintf("oracle_%sxtxdiag.txt", filePrefix)), xtxAll)

		// gotR is the final statistic this oracle computes, in the same one-value-per-line
		// %.6e format gwas.go's Phase3 uses for out/party*/assoc_%d.txt (via the same
		// gwas.SaveFloatVectorToFile helper) -- diff these directly against assoc_%d.txt
		// rather than only seeing the aggregate max/mean this test already logs.
		for i := 0; i < npheno; i++ {
			gwas.SaveFloatVectorToFile(filepath.Join(dumpDir, fmt.Sprintf("oracle_%sassoc_%d.txt", filePrefix, i)), gotR[i])
		}

		t.Logf("dumped oracle intermediates to %s", dumpDir)
	}

	// ---- Compare against the protocol output ----
	const tol = 2e-3
	for i := 0; i < npheno; i++ {
		want := readFloatLines(t, filepath.Join(cfgs[1].OutDir, fmt.Sprintf("assoc_%d.txt", i)))
		if len(want) != len(gotR[i]) {
			t.Errorf("phenotype %d: protocol emitted %d SNPs, oracle computed %d", i, len(want), len(gotR[i]))
			continue
		}
		maxDiff, maxAt, over := 0.0, -1, 0
		for j := range want {
			d := math.Abs(want[j] - gotR[i][j])
			if d > maxDiff {
				maxDiff, maxAt = d, j
			}
			if d > tol {
				over++
			}
		}
		t.Logf("phenotype %d: n=%d  max|diff|=%.3e (snp %d)  over-tol=%d", i, len(want), maxDiff, maxAt, over)
		if over > 0 {
			t.Errorf("phenotype %d: %d/%d SNPs differ from the plaintext oracle by more than %g (max %.3e at snp %d)",
				i, over, len(want), tol, maxDiff, maxAt)
		}
	}
}

// readGenoBlock materializes one QC-filtered genotype block for a party as a dense
// nind-by-nsnp matrix, with missing calls replaced by zero exactly as
// MatMult4StreamPlain does.
func readGenoBlock(t *testing.T, cfg *gwas.Config, block, shift int, blockFilt []bool, nind, nsnp int, tmpFile string) *mat.Dense {
	t.Helper()

	gwas.FilterMatrixFilePgen(fmt.Sprintf(cfg.GenoFilePrefix, block+1), nind, nsnp,
		cfg.SampleKeepFile, cfg.SnpIdsFile, shift, blockFilt, tmpFile, cfg.LocalNumThreads)

	gfs := gwas.NewGenoFileStream(tmpFile, uint64(nind), uint64(nsnp), true)
	gfs.Reset()

	X := mat.NewDense(nind, nsnp, nil)
	for i := 0; i < nind; i++ {
		row := gfs.NextRow()
		if row == nil {
			t.Fatalf("block %d: genotype stream ended after %d of %d rows", block, i, nind)
		}
		for j := 0; j < nsnp; j++ {
			if row[j] > 0 {
				X.Set(i, j, float64(row[j]))
			} // negative (missing) and zero both stay 0
		}
	}
	return X
}

func blockInAssocTest(cfg *gwas.Config, block int) bool {
	if len(cfg.BlocksForAssoc) == 0 {
		return true
	}
	for _, b := range cfg.BlocksForAssoc {
		if b == block {
			return true
		}
	}
	return false
}

func loadConfig(t *testing.T, path string, base *gwas.Config) *gwas.Config {
	t.Helper()
	cfg := new(gwas.Config)
	if base != nil {
		*cfg = *base
	}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return cfg
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

func readIntLines(t *testing.T, path string, want int) []int {
	t.Helper()
	lines := readLines(t, path)
	if want > 0 && len(lines) != want {
		t.Fatalf("%s: got %d lines, want %d", path, len(lines), want)
	}
	out := make([]int, len(lines))
	for i, l := range lines {
		v, err := strconv.Atoi(l)
		if err != nil {
			t.Fatalf("%s line %d: %v", path, i+1, err)
		}
		out[i] = v
	}
	return out
}

func readBoolLines(t *testing.T, path string, want int) []bool {
	t.Helper()
	v := readIntLines(t, path, want)
	out := make([]bool, len(v))
	for i := range v {
		out[i] = v[i] != 0
	}
	return out
}

func writeFloatLine(t *testing.T, path string, v []float64) {
	t.Helper()
	strs := make([]string, len(v))
	for i, x := range v {
		strs[i] = strconv.FormatFloat(x, 'e', 6, 64)
	}
	if err := os.WriteFile(path, []byte(strings.Join(strs, ",")+"\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFloatLines(t *testing.T, path string) []float64 {
	t.Helper()
	lines := readLines(t, path)
	out := make([]float64, len(lines))
	for i, l := range lines {
		v, err := strconv.ParseFloat(l, 64)
		if err != nil {
			t.Fatalf("%s line %d: %v", path, i+1, err)
		}
		out[i] = v
	}
	return out
}
