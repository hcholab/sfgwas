package gwas

import (
	"bufio"
	"fmt"
	"math"
	"os"

	"go.dedis.ch/onet/v3/log"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat/distuv"
)

// Tractor: per-SNP local-ancestry-aware association, y ~ Z + A + X_AMR + X_EUR, where A
// is the AMR haplotype count (0..2) and X_AMR / X_EUR are the ancestry-specific
// alternate-allele dosages. This file holds the plaintext math shared by the plaintext
// reference (TractorStatsPlain) and the secure protocol (GetTractorStatsPlainMult in
// tractor_mpc.go), which reveals exactly the quantities in TractorRevealed.
//
// Notation, per SNP (all residualized against Z, i.e. ·ᵀ(I - P_Z)·):
//
//	S  = [s11 s12 s13; s12 s22 s23; s13 s23 s33]   3x3 Gram matrix of (A, X_AMR, X_EUR)
//	b  = (bA, bM, bE)                               per phenotype, Gᵀ(I - P_Z)y
//	sy = yᵀ(I - P_Z)y                               per phenotype
//
// The protocol divides S and b by 2^k, k = TractorNormExp(n), before the secret-shared
// solve (S, b and det(S) ~ n, n, n³ would otherwise overflow the fixed-point range), and
// reveals, with S' = S/2^k and b' = b/2^k:
//
//	det' = det(S')                      (so det(S) = 2^{3k}·det')
//	c'_ii                               diagonal cofactors of S'
//	num' = adj(S')·b'                   (so beta = num'/det')
//	T'   = sy·det'/2^k - num'ᵀb'        (so RSS = sy - betaᵀb = 2^k·T'/det')
//
// which determine, and are determined by, the classical {det, inv_ii, beta, sigma2} for
// det != 0 (inv_ii = c'_ii/(2^k·det'), sigma2 = RSS/df). Everything except det' and the
// dosage sums is revealed only for SNPs that pass the det/count filter.
//
// Missing genotype calls (negative entries) are imputed as 0 in every stream, the
// convention MatMult4StreamPlain uses for the standard pipeline.

// TractorRevealed carries what GetTractorStatsPlainMult reveals (see the notation above).
// Arrays are indexed by output SNP j (kept SNPs only, in output order) and phenotype k.
type TractorRevealed struct {
	NTot    int // total individuals across all parties (after QC)
	DF      int // n - rank(Z) - 3
	NormExp int // k: S and b were divided by 2^k

	Det                  []float64 // det(S'), every SNP
	SumA, SumAMR, SumEUR []float64 // aggregate dosage sums, every SNP (CKKS-decoded; rounded before use)

	// Revealed[j] is true where the values below were revealed (the SNP passed the
	// det/count prefilter); they are NaN elsewhere.
	Revealed             []bool
	C11, C22, C33        []float64   // diagonal cofactors of S'
	NumA, NumAMR, NumEUR [][]float64 // p-by-m: adj(S')·b'
	T                    [][]float64 // p-by-m: sy·det'/2^k - num'ᵀb'
}

// TractorResult holds per-SNP, per-phenotype Tractor association statistics. All
// matrices are m-by-p (SNPs-by-phenotypes); entries that are not valid are NaN.
type TractorResult struct {
	BetaA, BetaAMR, BetaEUR *mat.Dense
	SEA, SEAMR, SEEUR       *mat.Dense
	TA, TAMR, TEUR          *mat.Dense
	PA, PAMR, PEUR          *mat.Dense

	Det         []float64 // det(S) in raw units (2^{3k}·det')
	ValidDesign []bool    // det(S) > detTol (finite)
	ValidCounts []bool    // ancestry-specific haplotype/allele counts >= countThreshold
	Valid       []bool    // ValidDesign && ValidCounts && every (S⁻¹)_ii > 0
	// PhenoValid[k][j]: Valid[j] and every statistic for phenotype k is finite (a
	// perfect fit, RSS = 0, gives SE = 0 and an infinite t, and is reported invalid).
	PhenoValid [][]bool

	NAMRHaps, NEURHaps []float64
	AltAMR, RefAMR     []float64
	AltEUR, RefEUR     []float64

	DF int
}

// TractorNormExp is the k of the 2^-k normalization: ceil(log2 n), at least 1.
func TractorNormExp(n int) int {
	k := 1
	for k < 62 && (1<<k) < n {
		k++
	}
	return k
}

// tractorCounts derives the six haplotype/allele counts Tractor filters on from the
// aggregate dosage sums, rounding the sums first (CKKS-decoded integers can land just
// below their true value, which would flip a count sitting exactly at the threshold).
type tractorCounts struct {
	nAMR, nEUR, altAMR, refAMR, altEUR, refEUR float64
}

func newTractorCounts(sumA, sumM, sumE float64, n int) tractorCounts {
	sumA, sumM, sumE = math.Round(sumA), math.Round(sumM), math.Round(sumE)
	twoN := 2 * float64(n)
	return tractorCounts{
		nAMR: sumA, nEUR: twoN - sumA,
		altAMR: sumM, refAMR: sumA - sumM,
		altEUR: sumE, refEUR: twoN - sumA - sumE,
	}
}

// pass reports whether every count is >= countThreshold; countThreshold <= 0 disables
// the filter (the notebook's count_threshold=None).
func (c tractorCounts) pass(countThreshold int) bool {
	if countThreshold <= 0 {
		return true
	}
	thr := float64(countThreshold)
	return c.nAMR >= thr && c.nEUR >= thr && c.altAMR >= thr && c.refAMR >= thr && c.altEUR >= thr && c.refEUR >= thr
}

// tractorRawDet converts det' to raw units, det(S) = 2^{3k}·det'.
func tractorRawDet(detNorm float64, normExp int) float64 {
	return math.Ldexp(detNorm, 3*normExp)
}

// tractorDesignOK is the det_tol test, applied to det(S) in raw units so det_tol means
// what it means in the reference notebook. S is a Gram matrix, so a negative det is a
// numerical artifact and fails the test too.
func tractorDesignOK(rawDet, detTol float64) bool {
	return !math.IsNaN(rawDet) && !math.IsInf(rawDet, 0) && rawDet > detTol
}

// TractorPrefilter returns which SNPs pass the det/count filter, from det' and the
// dosage sums alone. GetTractorStatsPlainMult reveals the remaining quantities only for
// these SNPs.
func TractorPrefilter(det, sumA, sumM, sumE []float64, n, normExp, countThreshold int, detTol float64) []bool {
	keep := make([]bool, len(det))
	for j := range det {
		keep[j] = tractorDesignOK(tractorRawDet(det[j], normExp), detTol) &&
			newTractorCounts(sumA[j], sumM[j], sumE[j], n).pass(countThreshold)
	}
	return keep
}

// TractorFinishFromRevealed computes beta/SE/t/p and the validity masks from the
// revealed quantities, in plaintext. Validity: det(S) > detTol in raw units, all six
// counts >= countThreshold, every (S⁻¹)_ii > 0, and finite statistics (per phenotype).
// RSS is clamped at 0 as in the notebook.
func TractorFinishFromRevealed(r *TractorRevealed, countThreshold int, detTol float64) *TractorResult {
	m := len(r.Det)
	npheno := len(r.T)

	nan := func() *mat.Dense {
		d := mat.NewDense(max(m, 1), max(npheno, 1), nil)
		for i := range d.RawMatrix().Data {
			d.RawMatrix().Data[i] = math.NaN()
		}
		return d
	}

	res := &TractorResult{
		BetaA: nan(), BetaAMR: nan(), BetaEUR: nan(),
		SEA: nan(), SEAMR: nan(), SEEUR: nan(),
		TA: nan(), TAMR: nan(), TEUR: nan(),
		PA: nan(), PAMR: nan(), PEUR: nan(),
		Det: make([]float64, m), ValidDesign: make([]bool, m), ValidCounts: make([]bool, m), Valid: make([]bool, m),
		PhenoValid: make([][]bool, npheno),
		NAMRHaps:   make([]float64, m), NEURHaps: make([]float64, m),
		AltAMR: make([]float64, m), RefAMR: make([]float64, m),
		AltEUR: make([]float64, m), RefEUR: make([]float64, m),
		DF: r.DF,
	}
	for k := range res.PhenoValid {
		res.PhenoValid[k] = make([]bool, m)
	}

	if r.DF <= 0 {
		log.Warn("Tractor: non-positive degrees of freedom ", r.DF, "; every SNP is invalid")
	}
	tdist := distuv.StudentsT{Mu: 0, Sigma: 1, Nu: float64(r.DF)}
	twoK := math.Ldexp(1, r.NormExp)
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

	for j := 0; j < m; j++ {
		c := newTractorCounts(r.SumA[j], r.SumAMR[j], r.SumEUR[j], r.NTot)
		res.NAMRHaps[j], res.NEURHaps[j] = c.nAMR, c.nEUR
		res.AltAMR[j], res.RefAMR[j] = c.altAMR, c.refAMR
		res.AltEUR[j], res.RefEUR[j] = c.altEUR, c.refEUR

		res.Det[j] = tractorRawDet(r.Det[j], r.NormExp)
		res.ValidDesign[j] = tractorDesignOK(res.Det[j], detTol)
		res.ValidCounts[j] = c.pass(countThreshold)
		if !res.ValidDesign[j] || !res.ValidCounts[j] || r.DF <= 0 {
			continue
		}
		if !r.Revealed[j] {
			log.Fatalf("TractorFinishFromRevealed: SNP %d passes the det/count filter but was not revealed", j)
		}

		det := r.Det[j]
		inv11 := r.C11[j] / (twoK * det)
		inv22 := r.C22[j] / (twoK * det)
		inv33 := r.C33[j] / (twoK * det)
		if !(inv11 > 0 && inv22 > 0 && inv33 > 0) || !finite(inv11) || !finite(inv22) || !finite(inv33) {
			continue
		}
		res.Valid[j] = true

		for k := 0; k < npheno; k++ {
			betaA := r.NumA[k][j] / det
			betaM := r.NumAMR[k][j] / det
			betaE := r.NumEUR[k][j] / det

			rss := math.Max(twoK*r.T[k][j]/det, 0)
			sigma2 := rss / float64(r.DF)

			seA, seM, seE := math.Sqrt(sigma2*inv11), math.Sqrt(sigma2*inv22), math.Sqrt(sigma2*inv33)
			tA, tM, tE := betaA/seA, betaM/seM, betaE/seE
			pA := 2 * tdist.Survival(math.Abs(tA))
			pM := 2 * tdist.Survival(math.Abs(tM))
			pE := 2 * tdist.Survival(math.Abs(tE))

			ok := true
			for _, v := range []float64{betaA, betaM, betaE, seA, seM, seE, tA, tM, tE, pA, pM, pE} {
				if !finite(v) {
					ok = false
				}
			}
			if !ok {
				continue
			}
			res.PhenoValid[k][j] = true

			res.BetaA.Set(j, k, betaA)
			res.BetaAMR.Set(j, k, betaM)
			res.BetaEUR.Set(j, k, betaE)
			res.SEA.Set(j, k, seA)
			res.SEAMR.Set(j, k, seM)
			res.SEEUR.Set(j, k, seE)
			res.TA.Set(j, k, tA)
			res.TAMR.Set(j, k, tM)
			res.TEUR.Set(j, k, tE)
			res.PA.Set(j, k, pA)
			res.PAMR.Set(j, k, pM)
			res.PEUR.Set(j, k, pE)
		}
	}

	return res
}

// TractorRevealedFromStats is the float64 counterpart of the secure solve: from the exact
// residualized statistics it computes the same normalized quantities the protocol
// reveals (for every SNP). S entries are length-m vectors; bA/bM/bE are m-by-p.
func TractorRevealedFromStats(s11, s22, s33, s12, s13, s23 []float64, bA, bM, bE *mat.Dense, sy []float64,
	sumA, sumM, sumE []float64, n, df int) *TractorRevealed {

	m := len(s11)
	npheno := len(sy)
	k := TractorNormExp(n)
	inv2k := math.Ldexp(1, -k)

	r := &TractorRevealed{
		NTot: n, DF: df, NormExp: k,
		Det:  make([]float64, m),
		SumA: append([]float64(nil), sumA...), SumAMR: append([]float64(nil), sumM...), SumEUR: append([]float64(nil), sumE...),
		Revealed: make([]bool, m),
		C11:      make([]float64, m), C22: make([]float64, m), C33: make([]float64, m),
		NumA: make([][]float64, npheno), NumAMR: make([][]float64, npheno), NumEUR: make([][]float64, npheno),
		T: make([][]float64, npheno),
	}
	for p := 0; p < npheno; p++ {
		r.NumA[p], r.NumAMR[p], r.NumEUR[p], r.T[p] = make([]float64, m), make([]float64, m), make([]float64, m), make([]float64, m)
	}

	for j := 0; j < m; j++ {
		a11, a22, a33 := s11[j]*inv2k, s22[j]*inv2k, s33[j]*inv2k
		a12, a13, a23 := s12[j]*inv2k, s13[j]*inv2k, s23[j]*inv2k

		c11 := a22*a33 - a23*a23
		c22 := a11*a33 - a13*a13
		c33 := a11*a22 - a12*a12
		c12 := a13*a23 - a12*a33
		c13 := a12*a23 - a13*a22
		c23 := a12*a13 - a11*a23
		det := a11*c11 + a12*c12 + a13*c13

		r.Det[j], r.C11[j], r.C22[j], r.C33[j] = det, c11, c22, c33
		r.Revealed[j] = true

		for p := 0; p < npheno; p++ {
			ba, bm, be := bA.At(j, p)*inv2k, bM.At(j, p)*inv2k, bE.At(j, p)*inv2k
			na := c11*ba + c12*bm + c13*be
			nm := c12*ba + c22*bm + c23*be
			ne := c13*ba + c23*bm + c33*be
			r.NumA[p][j], r.NumAMR[p][j], r.NumEUR[p][j] = na, nm, ne
			r.T[p][j] = sy[p]*det*inv2k - (na*ba + nm*bm + ne*be)
		}
	}
	return r
}

// TractorStatsPlain computes Tractor statistics in plaintext float64, mirroring
// precompute_tractor_stats + tractor_from_precomputed from the reference notebook, and
// finishing through the same code path (TractorRevealedFromStats +
// TractorFinishFromRevealed) as the secure protocol. For each SNP j and phenotype k it
// fits
//
//	y_k = Z*gamma + beta_A*A[:,j] + beta_AMR*X_AMR[:,j] + beta_EUR*X_EUR[:,j] + eps
//
// by residualizing against Z via the lazy S-projection (SᵀS = n·(ZᵀZ)⁺) and solving the
// 3x3 normal equations in closed form. Z must include an intercept column if one is
// wanted. Negative genotype entries (missing calls) are treated as 0. countThreshold <= 0
// disables the count filter.
func TractorStatsPlain(Z, Y, A, Xamr, Xeur *mat.Dense, countThreshold int, detTol float64) *TractorResult {
	n, ncov := Z.Dims()
	nY, npheno := Y.Dims()
	nA, m := A.Dims()
	nM, mM := Xamr.Dims()
	nE, mE := Xeur.Dims()
	if nY != n || nA != n || nM != n || nE != n {
		panic("TractorStatsPlain: Z, Y, A, X_AMR, X_EUR must all have n rows")
	}
	if mM != m || mE != m {
		panic("TractorStatsPlain: A, X_AMR, X_EUR must all have m columns")
	}

	A, Xamr, Xeur = zeroMissing(A), zeroMissing(Xamr), zeroMissing(Xeur)

	S, rank := tractorCovOrthoFactor(Z)
	nInvSqrt := math.Sqrt(1 / float64(n))

	BA := tractorProjectThroughS(S, Z, A, nInvSqrt)    // ncov-by-m
	BM := tractorProjectThroughS(S, Z, Xamr, nInvSqrt) // ncov-by-m
	BE := tractorProjectThroughS(S, Z, Xeur, nInvSqrt) // ncov-by-m
	QtY := tractorProjectThroughS(S, Z, Y, nInvSqrt)   // ncov-by-p

	s11, s22, s33 := make([]float64, m), make([]float64, m), make([]float64, m)
	s12, s13, s23 := make([]float64, m), make([]float64, m), make([]float64, m)
	sumA, sumM, sumE := make([]float64, m), make([]float64, m), make([]float64, m)

	for j := 0; j < m; j++ {
		var aa, mm, ee, am, ae, me, sa, sm, se float64
		for i := 0; i < n; i++ {
			a, x, e := A.At(i, j), Xamr.At(i, j), Xeur.At(i, j)
			aa += a * a
			mm += x * x
			ee += e * e
			am += a * x
			ae += a * e
			me += x * e
			sa += a
			sm += x
			se += e
		}
		var pa, pm, pe, pam, pae, pme float64
		for c := 0; c < ncov; c++ {
			ba, bm, be := BA.At(c, j), BM.At(c, j), BE.At(c, j)
			pa += ba * ba
			pm += bm * bm
			pe += be * be
			pam += ba * bm
			pae += ba * be
			pme += bm * be
		}
		s11[j], s22[j], s33[j] = aa-pa, mm-pm, ee-pe
		s12[j], s13[j], s23[j] = am-pam, ae-pae, me-pme
		sumA[j], sumM[j], sumE[j] = sa, sm, se
	}

	bA := mat.NewDense(m, npheno, nil)
	bM := mat.NewDense(m, npheno, nil)
	bE := mat.NewDense(m, npheno, nil)
	sy := make([]float64, npheno)

	for k := 0; k < npheno; k++ {
		var syy, proj float64
		for i := 0; i < n; i++ {
			syy += Y.At(i, k) * Y.At(i, k)
		}
		for c := 0; c < ncov; c++ {
			proj += QtY.At(c, k) * QtY.At(c, k)
		}
		sy[k] = syy - proj

		for j := 0; j < m; j++ {
			var ay, my, ey, pay, pmy, pey float64
			for i := 0; i < n; i++ {
				y := Y.At(i, k)
				ay += A.At(i, j) * y
				my += Xamr.At(i, j) * y
				ey += Xeur.At(i, j) * y
			}
			for c := 0; c < ncov; c++ {
				q := QtY.At(c, k)
				pay += BA.At(c, j) * q
				pmy += BM.At(c, j) * q
				pey += BE.At(c, j) * q
			}
			bA.Set(j, k, ay-pay)
			bM.Set(j, k, my-pmy)
			bE.Set(j, k, ey-pey)
		}
	}

	r := TractorRevealedFromStats(s11, s22, s33, s12, s13, s23, bA, bM, bE, sy, sumA, sumM, sumE, n, n-rank-3)
	return TractorFinishFromRevealed(r, countThreshold, detTol)
}

// zeroMissing returns X with negative entries (missing calls) replaced by 0, copying
// only if there are any.
func zeroMissing(X *mat.Dense) *mat.Dense {
	r, c := X.Dims()
	var out *mat.Dense
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			if X.At(i, j) < 0 {
				if out == nil {
					out = mat.DenseCopyOf(X)
				}
				out.Set(i, j, 0)
			}
		}
	}
	if out == nil {
		return X
	}
	return out
}

// SaveTractorResultToFile writes one line per SNP for phenotype k, tab-separated, in the
// order beta_A, se_A, p_A, beta_AMR, se_AMR, p_AMR, beta_EUR, se_EUR, p_EUR, valid --
// matching the plain, headerless style of SaveFloatVectorToFile (gwas/utilities.go).
// valid is PhenoValid[k][j]; invalid rows carry NaN statistics. Row j corresponds to
// the SNP on line j of the tractor_snp_index.txt file written next to it.
func SaveTractorResultToFile(filename string, result *TractorResult, pheno int) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for j := range result.Valid {
		writer.WriteString(fmt.Sprintf("%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%v\n",
			result.BetaA.At(j, pheno), result.SEA.At(j, pheno), result.PA.At(j, pheno),
			result.BetaAMR.At(j, pheno), result.SEAMR.At(j, pheno), result.PAMR.At(j, pheno),
			result.BetaEUR.At(j, pheno), result.SEEUR.At(j, pheno), result.PEUR.At(j, pheno),
			result.PhenoValid[pheno][j]))
	}

	if err := writer.Flush(); err != nil {
		log.Fatalf("SaveTractorResultToFile: flush failed for %s: %v", filename, err)
	}
}

// SaveTractorSNPIndexFile writes the 0-based global index (position in the full,
// pre-QC SNP list across all genotype blocks) of each output row, one per line.
func SaveTractorSNPIndexFile(filename string, index []int) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, v := range index {
		fmt.Fprintf(writer, "%d\n", v)
	}
	if err := writer.Flush(); err != nil {
		log.Fatalf("SaveTractorSNPIndexFile: flush failed for %s: %v", filename, err)
	}
}

// tractorCovOrthoFactor builds S (ncov-by-ncov) with SᵀS = n·(ZᵀZ)⁺ via
// eigendecomposition, mirroring the secret-shared eigendecomposition branch of
// computeCovOrthoFactor in gwas/assoc.go. Eigen-directions with λ <= 1e-8·λmax are
// dropped (pseudo-inverse), so a rank-deficient Z projects onto its column space instead
// of dividing by ~0. Also returns rank(Z), used for the degrees of freedom (the
// notebook's q = matrix_rank(ZᵀZ)).
func tractorCovOrthoFactor(Z *mat.Dense) (S *mat.Dense, rank int) {
	n, ncov := Z.Dims()
	nInvSqrt := math.Sqrt(1 / float64(n))

	Zt := mat.DenseCopyOf(Z.T())

	var ZtZss mat.SymDense
	ZtZss.SymOuterK(nInvSqrt, Zt)

	var eig mat.EigenSym
	if !eig.Factorize(&ZtZss, true) {
		panic("tractorCovOrthoFactor: eigendecomposition failed")
	}
	var V mat.Dense
	eig.VectorsTo(&V)
	lambda := eig.Values(nil)

	maxLambda := 0.0
	for _, l := range lambda {
		maxLambda = math.Max(maxLambda, l)
	}
	const relRankTol = 1e-8

	scaling := math.Sqrt(math.Sqrt(float64(n)))
	S = mat.NewDense(ncov, ncov, nil)
	for i := 0; i < ncov; i++ {
		if !(lambda[i] > relRankTol*maxLambda) {
			continue // null direction of ZᵀZ: leave row i of S zero
		}
		rank++
		lsqrtInv := scaling / math.Sqrt(lambda[i])
		for j := 0; j < ncov; j++ {
			S.Set(i, j, lsqrtInv*V.At(j, i))
		}
	}
	return S, rank
}

// tractorProjectThroughS computes B = QᵀM = S*(ZᵀM/sqrt(n)), the lazy-projection
// counterpart of forming an explicit orthonormal Q and computing QᵀM.
func tractorProjectThroughS(S, Z, M *mat.Dense, nInvSqrt float64) *mat.Dense {
	Zt := mat.DenseCopyOf(Z.T())
	var ZtM mat.Dense
	ZtM.Mul(Zt, M)
	ZtM.Scale(nInvSqrt, &ZtM)
	var B mat.Dense
	B.Mul(S, &ZtM)
	return &B
}
