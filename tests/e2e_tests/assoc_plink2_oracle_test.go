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

	"github.com/hcholab/sfgwas/gwas"
	"gonum.org/v1/gonum/mat"
)

// TestAssocPlink2Oracle cross-checks phase 3's per-SNP statistics against plink2's own
// --glm: a widely-used, independently developed tool with no relationship to this
// codebase. Where TestAssocPlaintextOracle re-derives the same formula independently
// (a different numerical route, but the same understanding of the statistical model),
// this compares against an external implementation, so it can catch a conceptual error
// in that shared understanding -- one both the protocol and TestAssocPlaintextOracle
// would silently agree on.
//
// Like TestAssocPlaintextOracle, it treats the run's QC filter (gkeep.txt) and PCs
// (pca.txt) as fixed inputs rather than letting plink2 recompute them: plink2's own
// --pca or MAF/HWE filtering would select different PCs/SNPs than the protocol did, and
// any diff would be filter noise, not a real signal.
//
// plink2 operates on one dataset, not federated data, so all parties' individuals are
// pooled into a single VCF and covariate/phenotype file here, reusing the exact
// dosages readGenoBlock already resolves (missing calls as hard 0, same as
// MatMult4StreamPlain) -- rather than asking plink2 to --pmerge/--bmerge the parties'
// own filesets, which risks silent allele/strand mismatches unrelated to any real bug
// here. REF/ALT in the generated VCF are placeholder alleles assigned by this test
// (dosage always counts ALT), not read from the source .pvar. --glm's 'omit-ref'
// modifier is required to keep plink2's reported statistic pinned to that same fixed
// allele: without it, plink2 reports whichever allele is "nonmajor" at each SNP, which
// flips with allele frequency and would randomly flip the sign of the comparison
// SNP-by-SNP.
//
// assoc_*.txt stores a partial correlation r; plink2 --glm reports a T-statistic for
// the OLS coefficient on the SNP term. They are related by r = T/sqrt(T^2+df), with
// df = n-k-1 (k = intercept + covariates + PCs), so the comparison converts rather
// than diffing raw output.
//
// A phenotype that happens to take only values in {0,1,2} looks like case/control
// coding to plink2's autodetection, which would silently switch it to logistic
// regression -- a different statistic, not comparable via the r/T identity above.
// Shifting every value by a large constant escapes that heuristic without changing the
// actual statistic: both the correlation and the OLS t-statistic on an
// intercept-containing model are invariant to an additive shift of Y.
//
//	./compare_assoc_paths.sh && go test ./tests/e2e_tests/ -run TestAssocPlink2Oracle -v
func TestAssocPlink2Oracle(t *testing.T) {
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

	assocProbe := filepath.Join(cfgs[1].OutDir, "assoc_0.txt")
	if _, err := os.Stat(assocProbe); err != nil {
		t.Skipf("no run output found at %s; run the pipeline first", assocProbe)
	}

	blockSizes := readIntLines(t, cfgs[1].GenoBlockSizeFile, cfgs[1].GenoNumBlocks)

	gkeep := readBoolLines(t, filepath.Join(cfgs[1].CacheDir, "gkeep.txt"), global.NumSnps)
	for p := 2; p <= nparty; p++ {
		other := readBoolLines(t, filepath.Join(cfgs[p].CacheDir, "gkeep.txt"), global.NumSnps)
		for i := range gkeep {
			if gkeep[i] != other[i] {
				t.Fatalf("gkeep.txt differs between party 1 and party %d at index %d", p, i)
			}
		}
	}

	// ---- Pool sample IDs, covariates (no intercept -- plink2 adds its own), PCs, and
	// phenotypes across parties, individuals in the same party-by-party row order
	// readGenoBlock produces. ----
	type partyData struct {
		nind   int
		offset int
	}
	parties := make([]partyData, nparty+1)

	var fid, iid []string
	var covarRows, phenoRows [][]float64
	npheno, ncovIn, npc := 0, 0, global.NumPCs
	for p := 1; p <= nparty; p++ {
		ids := readSampleIDs(t, cfgs[p].SampleKeepFile)
		pheno := gwas.LoadMatrixFromFile(cfgs[p].PhenoFile, '\t')
		cov := gwas.LoadMatrixFromFile(cfgs[p].CovFile, '\t')
		qpc := gwas.LoadMatrixFromFile(filepath.Join(cfgs[p].OutDir, "pca.txt"), ',') // npc-by-nind

		nind, nph := pheno.Dims()
		ncr, ncc := cov.Dims()
		qr, qc := qpc.Dims()
		if len(ids) != nind || ncr != nind || qc != nind {
			t.Fatalf("party %d: %d IDs, %d individuals in pheno, %d in cov, %d in pca.txt", p, len(ids), nind, ncr, qc)
		}
		if p == 1 {
			npheno, ncovIn = nph, ncc
			if qr != npc {
				t.Fatalf("pca.txt has %d rows, config says num_pcs_to_remove=%d", qr, npc)
			}
		} else if nph != npheno || ncc != ncovIn {
			t.Fatalf("party %d: pheno/cov widths %d/%d differ from party 1's %d/%d", p, nph, ncc, npheno, ncovIn)
		}

		parties[p] = partyData{nind: nind, offset: len(fid)}
		for i := 0; i < nind; i++ {
			fid = append(fid, ids[i][0])
			iid = append(iid, ids[i][1])

			row := make([]float64, 0, ncovIn+npc)
			for j := 0; j < ncovIn; j++ {
				row = append(row, cov.At(i, j))
			}
			for j := 0; j < npc; j++ {
				row = append(row, qpc.At(j, i))
			}
			covarRows = append(covarRows, row)

			y := make([]float64, npheno)
			for j := 0; j < npheno; j++ {
				y[j] = pheno.At(i, j)
			}
			phenoRows = append(phenoRows, y)
		}
	}
	ntot := len(fid)
	k := 1 + ncovIn + npc // intercept + covariates + PCs, matching TestAssocPlaintextOracle's k
	t.Logf("pooled: %d individuals, %d covariates (incl. intercept and %d PCs), %d phenotypes", ntot, k, npc, npheno)

	tmpDir := t.TempDir()

	// A large, arbitrary shift: see doc comment for why this is required and why it's
	// a no-op for the actual statistic.
	const phenoShift = 1000.0
	covarFile := filepath.Join(tmpDir, "covar.txt")
	phenoFile := filepath.Join(tmpDir, "pheno.txt")
	writeCovarFile(t, covarFile, fid, iid, covarRows, ncovIn, npc)
	phenoNames := writePhenoFile(t, phenoFile, fid, iid, phenoRows, npheno, phenoShift)

	// ---- Pooled VCF, streamed one block at a time. ----
	vcfFile := filepath.Join(tmpDir, "pooled.vcf")
	vf, err := os.Create(vcfFile)
	if err != nil {
		t.Fatalf("create %s: %v", vcfFile, err)
	}
	vw := bufio.NewWriterSize(vf, 1<<20)
	fmt.Fprintln(vw, "##fileformat=VCFv4.2")
	fmt.Fprint(vw, "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT")
	for i := 0; i < ntot; i++ {
		fmt.Fprintf(vw, "\t%s", iid[i])
	}
	fmt.Fprintln(vw)

	nsnpTotal := 0
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

		X := mat.NewDense(ntot, nsnp, nil)
		for p := 1; p <= nparty; p++ {
			Xp := readGenoBlock(t, cfgs[p], b, shift, blockFilt, parties[p].nind, nsnp,
				filepath.Join(tmpDir, fmt.Sprintf("gfs.%d.%d", p, b)))
			off := parties[p].offset
			for i := 0; i < parties[p].nind; i++ {
				for j := 0; j < nsnp; j++ {
					X.Set(off+i, j, Xp.At(i, j))
				}
			}
		}

		for j := 0; j < nsnp; j++ {
			nsnpTotal++
			fmt.Fprintf(vw, "1\t%d\tsnp%d\tA\tC\t.\t.\t.\tGT", nsnpTotal, nsnpTotal)
			for i := 0; i < ntot; i++ {
				switch X.At(i, j) {
				case 0:
					vw.WriteString("\t0/0")
				case 1:
					vw.WriteString("\t0/1")
				case 2:
					vw.WriteString("\t1/1")
				default:
					t.Fatalf("block %d snp %d individual %d: dosage %v out of range", b, j, i, X.At(i, j))
				}
			}
			vw.WriteByte('\n')
		}
		shift += blockSizes[b]
		t.Logf("block %d/%d: %d SNPs", b+1, cfgs[1].GenoNumBlocks, nsnp)
	}
	if err := vw.Flush(); err != nil {
		t.Fatalf("flush %s: %v", vcfFile, err)
	}
	if err := vf.Close(); err != nil {
		t.Fatalf("close %s: %v", vcfFile, err)
	}

	// ---- Run plink2 once over the pooled dataset. ----
	outPrefix := filepath.Join(tmpDir, "plink2run")
	cmd := exec.Command("plink2",
		"--vcf", vcfFile, "--double-id",
		"--pheno", phenoFile, "--no-psam-pheno",
		"--covar", covarFile,
		"--glm", "omit-ref", "hide-covar",
		"--out", outPrefix,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("plink2 --glm failed: %v\n%s", err, out)
	}

	// ---- Convert plink2's T-statistic to a partial correlation and compare. ----
	const tol = 5e-3
	for i, name := range phenoNames {
		want := readFloatLines(t, filepath.Join(cfgs[1].OutDir, fmt.Sprintf("assoc_%d.txt", i)))
		got := readPlink2Corr(t, fmt.Sprintf("%s.%s.glm.linear", outPrefix, name), k)
		if len(want) != len(got) {
			t.Errorf("phenotype %d: protocol emitted %d SNPs, plink2 reported %d", i, len(want), len(got))
			continue
		}
		maxDiff, maxAt, over := 0.0, -1, 0
		for j := range want {
			d := math.Abs(want[j] - got[j])
			if d > maxDiff {
				maxDiff, maxAt = d, j
			}
			if d > tol {
				over++
			}
		}
		t.Logf("phenotype %d: n=%d  max|diff|=%.3e (snp %d)  over-tol=%d", i, len(want), maxDiff, maxAt, over)
		if over > 0 {
			t.Errorf("phenotype %d: %d/%d SNPs differ from plink2 --glm by more than %g (max %.3e at snp %d)",
				i, over, len(want), tol, maxDiff, maxAt)
		}
	}
}

// readSampleIDs reads "FID IID" pairs (plink2 --keep / sample_keep_file format), in
// file order -- the same order the pheno/cov files and the genotype stream use.
func readSampleIDs(t *testing.T, path string) [][2]string {
	t.Helper()
	lines := readLines(t, path)
	out := make([][2]string, len(lines))
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			t.Fatalf("%s line %d: expected \"FID IID\", got %q", path, i+1, l)
		}
		out[i] = [2]string{f[0], f[1]}
	}
	return out
}

func writeCovarFile(t *testing.T, path string, fid, iid []string, rows [][]float64, ncov, npc int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprint(w, "FID\tIID")
	for j := 0; j < ncov; j++ {
		fmt.Fprintf(w, "\tCOV%d", j+1)
	}
	for j := 0; j < npc; j++ {
		fmt.Fprintf(w, "\tPC%d", j+1)
	}
	fmt.Fprintln(w)
	for i, row := range rows {
		fmt.Fprintf(w, "%s\t%s", fid[i], iid[i])
		for _, v := range row {
			fmt.Fprintf(w, "\t%.10g", v)
		}
		fmt.Fprintln(w)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writePhenoFile writes the pooled phenotypes, shifted by phenoShift, and returns the
// column names it assigned (Y0, Y1, ...) in the same order as assoc_<i>.txt.
func writePhenoFile(t *testing.T, path string, fid, iid []string, rows [][]float64, npheno int, phenoShift float64) []string {
	t.Helper()
	names := make([]string, npheno)
	for j := range names {
		names[j] = fmt.Sprintf("Y%d", j)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprint(w, "FID\tIID")
	for _, name := range names {
		fmt.Fprintf(w, "\t%s", name)
	}
	fmt.Fprintln(w)
	for i, row := range rows {
		fmt.Fprintf(w, "%s\t%s", fid[i], iid[i])
		for _, v := range row {
			fmt.Fprintf(w, "\t%.10g", v+phenoShift)
		}
		fmt.Fprintln(w)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return names
}

// readPlink2Corr parses a plink2 .glm.linear file (one ADD row per SNP, in the order
// plink2 read the VCF, since 'hide-covar' suppresses every other row) and converts
// each row's T_STAT to a partial correlation coefficient.
func readPlink2Corr(t *testing.T, path string, k int) []float64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	if !sc.Scan() {
		t.Fatalf("%s: empty file", path)
	}
	cols := strings.Split(strings.TrimPrefix(sc.Text(), "#"), "\t")
	idx := make(map[string]int, len(cols))
	for i, c := range cols {
		idx[c] = i
	}
	tIdx, ok := idx["T_STAT"]
	if !ok {
		t.Fatalf("%s: no T_STAT column (header: %v)", path, cols)
	}
	obsIdx, ok := idx["OBS_CT"]
	if !ok {
		t.Fatalf("%s: no OBS_CT column (header: %v)", path, cols)
	}

	var out []float64
	for lineno := 2; sc.Scan(); lineno++ {
		f := strings.Split(sc.Text(), "\t")
		if f[tIdx] == "NA" {
			t.Fatalf("%s line %d: plink2 reported T_STAT=NA (degenerate/multicollinear SNP?)", path, lineno)
		}
		tstat, err := strconv.ParseFloat(f[tIdx], 64)
		if err != nil {
			t.Fatalf("%s line %d: parse T_STAT %q: %v", path, lineno, f[tIdx], err)
		}
		obs, err := strconv.Atoi(f[obsIdx])
		if err != nil {
			t.Fatalf("%s line %d: parse OBS_CT %q: %v", path, lineno, f[obsIdx], err)
		}
		df := float64(obs - k - 1)
		out = append(out, tstat/math.Sqrt(tstat*tstat+df))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}
