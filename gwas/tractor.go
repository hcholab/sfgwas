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

// TractorResult holds per-SNP, per-phenotype Tractor association statistics: separate
// effects for local ancestry dosage (A), the AMR-specific allele dosage (X_AMR), and the
// EUR-specific allele dosage (X_EUR). All matrices are m-by-p (SNPs-by-phenotypes);
// entries for SNPs where Valid[j] is false are NaN.
type TractorResult struct {
	BetaA, BetaAMR, BetaEUR *mat.Dense
	SEA, SEAMR, SEEUR       *mat.Dense
	TA, TAMR, TEUR          *mat.Dense
	PA, PAMR, PEUR          *mat.Dense

	Det         []float64
	Valid       []bool
	ValidDesign []bool // |det| > detTol
	ValidCounts []bool // ancestry-specific haplotype/allele counts >= countThreshold

	NAMRHaps, NEURHaps []float64
	AltAMR, RefAMR     []float64
	AltEUR, RefEUR     []float64

	DF int
}

// TractorStatsPlain computes Tractor-style local-ancestry-aware association statistics
// in plaintext float64, mirroring precompute_tractor_stats + tractor_from_precomputed
// from the reference notebook. For each SNP j and phenotype k, it fits
//
//	y_k = Z*gamma + beta_A*A[:,j] + beta_AMR*X_AMR[:,j] + beta_EUR*X_EUR[:,j] + eps
//
// by residualizing A, X_AMR, X_EUR, and y against Z via the same lazy S-projection
// (SᵀS=(ZᵀZ)⁻¹, Q never formed) that GetAssociationStatsPlainMult uses for the
// single-variant test (gwas/assoc.go), then solving the resulting 3x3 per-SNP normal
// equations in closed form via Cramer's rule.
//
// Z must include an intercept column if one is desired (not added automatically).
// countThreshold <= 0 disables the ancestry-count filter (equivalent to the notebook's
// count_threshold=None).
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

	S, rank := tractorCovOrthoFactor(Z)
	nInvSqrt := math.Sqrt(1 / float64(n))

	BA := tractorProjectThroughS(S, Z, A, nInvSqrt)    // ncov-by-m
	BM := tractorProjectThroughS(S, Z, Xamr, nInvSqrt) // ncov-by-m
	BE := tractorProjectThroughS(S, Z, Xeur, nInvSqrt) // ncov-by-m
	QtY := tractorProjectThroughS(S, Z, Y, nInvSqrt)   // ncov-by-p

	s11 := make([]float64, m)
	s22 := make([]float64, m)
	s33 := make([]float64, m)
	s12 := make([]float64, m)
	s13 := make([]float64, m)
	s23 := make([]float64, m)

	sumA := make([]float64, m)
	sumM := make([]float64, m)
	sumE := make([]float64, m)

	for j := 0; j < m; j++ {
		var aa, mm, ee, am, ae, me, sa, sm, se float64
		for i := 0; i < n; i++ {
			a := A.At(i, j)
			x := Xamr.At(i, j)
			e := Xeur.At(i, j)
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

		s11[j] = aa - pa
		s22[j] = mm - pm
		s33[j] = ee - pe
		s12[j] = am - pam
		s13[j] = ae - pae
		s23[j] = me - pme

		sumA[j] = sa
		sumM[j] = sm
		sumE[j] = se
	}

	bA := mat.NewDense(m, npheno, nil)
	bM := mat.NewDense(m, npheno, nil)
	bE := mat.NewDense(m, npheno, nil)
	sy := make([]float64, npheno)

	for k := 0; k < npheno; k++ {
		var syy float64
		for i := 0; i < n; i++ {
			y := Y.At(i, k)
			syy += y * y
		}
		var proj float64
		for c := 0; c < ncov; c++ {
			q := QtY.At(c, k)
			proj += q * q
		}
		sy[k] = syy - proj

		for j := 0; j < m; j++ {
			var ay, my, ey float64
			for i := 0; i < n; i++ {
				y := Y.At(i, k)
				ay += A.At(i, j) * y
				my += Xamr.At(i, j) * y
				ey += Xeur.At(i, j) * y
			}
			var pay, pmy, pey float64
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

	res := &TractorResult{
		BetaA: mat.NewDense(m, npheno, nil), BetaAMR: mat.NewDense(m, npheno, nil), BetaEUR: mat.NewDense(m, npheno, nil),
		SEA: mat.NewDense(m, npheno, nil), SEAMR: mat.NewDense(m, npheno, nil), SEEUR: mat.NewDense(m, npheno, nil),
		TA: mat.NewDense(m, npheno, nil), TAMR: mat.NewDense(m, npheno, nil), TEUR: mat.NewDense(m, npheno, nil),
		PA: mat.NewDense(m, npheno, nil), PAMR: mat.NewDense(m, npheno, nil), PEUR: mat.NewDense(m, npheno, nil),
		Det: make([]float64, m), Valid: make([]bool, m), ValidDesign: make([]bool, m), ValidCounts: make([]bool, m),
		NAMRHaps: make([]float64, m), NEURHaps: make([]float64, m),
		AltAMR: make([]float64, m), RefAMR: make([]float64, m),
		AltEUR: make([]float64, m), RefEUR: make([]float64, m),
		DF: n - rank - 3,
	}

	nTot := float64(n)
	tdist := distuv.StudentsT{Mu: 0, Sigma: 1, Nu: float64(res.DF)}

	for j := 0; j < m; j++ {
		nAMR := sumA[j]
		nEUR := 2*nTot - sumA[j]
		altAMR := sumM[j]
		refAMR := sumA[j] - sumM[j]
		altEUR := sumE[j]
		refEUR := 2*nTot - sumA[j] - sumE[j]

		res.NAMRHaps[j], res.NEURHaps[j] = nAMR, nEUR
		res.AltAMR[j], res.RefAMR[j] = altAMR, refAMR
		res.AltEUR[j], res.RefEUR[j] = altEUR, refEUR

		c11 := s22[j]*s33[j] - s23[j]*s23[j]
		c22 := s11[j]*s33[j] - s13[j]*s13[j]
		c33 := s11[j]*s22[j] - s12[j]*s12[j]
		c12 := s13[j]*s23[j] - s12[j]*s33[j]
		c13 := s12[j]*s23[j] - s13[j]*s22[j]
		c23 := s12[j]*s13[j] - s11[j]*s23[j]

		det := s11[j]*c11 + s12[j]*c12 + s13[j]*c13
		res.Det[j] = det

		validDesign := !math.IsNaN(det) && !math.IsInf(det, 0) && math.Abs(det) > detTol
		res.ValidDesign[j] = validDesign

		validCounts := true
		if countThreshold > 0 {
			thr := float64(countThreshold)
			validCounts = nAMR >= thr && nEUR >= thr && altAMR >= thr && refAMR >= thr && altEUR >= thr && refEUR >= thr
		}
		res.ValidCounts[j] = validCounts

		valid := validDesign && validCounts
		res.Valid[j] = valid

		if !valid {
			for k := 0; k < npheno; k++ {
				res.BetaA.Set(j, k, math.NaN())
				res.BetaAMR.Set(j, k, math.NaN())
				res.BetaEUR.Set(j, k, math.NaN())
				res.SEA.Set(j, k, math.NaN())
				res.SEAMR.Set(j, k, math.NaN())
				res.SEEUR.Set(j, k, math.NaN())
				res.TA.Set(j, k, math.NaN())
				res.TAMR.Set(j, k, math.NaN())
				res.TEUR.Set(j, k, math.NaN())
				res.PA.Set(j, k, math.NaN())
				res.PAMR.Set(j, k, math.NaN())
				res.PEUR.Set(j, k, math.NaN())
			}
			continue
		}

		inv11 := c11 / det
		inv22 := c22 / det
		inv33 := c33 / det

		for k := 0; k < npheno; k++ {
			ba, bm, be := bA.At(j, k), bM.At(j, k), bE.At(j, k)

			betaA := (c11*ba + c12*bm + c13*be) / det
			betaM := (c12*ba + c22*bm + c23*be) / det
			betaE := (c13*ba + c23*bm + c33*be) / det

			rss := sy[k] - betaA*ba - betaM*bm - betaE*be
			if rss < 0 {
				rss = 0
			}
			sigma2 := rss / float64(res.DF)

			seA := math.Sqrt(sigma2 * inv11)
			seM := math.Sqrt(sigma2 * inv22)
			seE := math.Sqrt(sigma2 * inv33)

			tA := betaA / seA
			tM := betaM / seM
			tE := betaE / seE

			res.BetaA.Set(j, k, betaA)
			res.BetaAMR.Set(j, k, betaM)
			res.BetaEUR.Set(j, k, betaE)
			res.SEA.Set(j, k, seA)
			res.SEAMR.Set(j, k, seM)
			res.SEEUR.Set(j, k, seE)
			res.TA.Set(j, k, tA)
			res.TAMR.Set(j, k, tM)
			res.TEUR.Set(j, k, tE)
			res.PA.Set(j, k, 2*tdist.Survival(math.Abs(tA)))
			res.PAMR.Set(j, k, 2*tdist.Survival(math.Abs(tM)))
			res.PEUR.Set(j, k, 2*tdist.Survival(math.Abs(tE)))
		}
	}

	return res
}

// TractorFinishFromRevealed is the plaintext "back half" of TractorStatsPlain, shared
// with the encrypted path: given the quantities GetTractorStatsPlainMult reveals from
// the MPC protocol (gwas/tractor_mpc.go) -- det, the cofactor/det ratios, beta
// numerators already divided by det, sigma2, and the raw ancestry/allele dosage sums --
// compute SE/t/p and apply the count_threshold/det_tol validity mask. No MPC-computed
// value is more raw than det/inv11/inv22/inv33/beta/sigma2 here; SE=sqrt(sigma2*invii)
// and t/p-value conversion happen entirely in plaintext, mirroring how the existing
// single-variant path only reveals a raw correlation-like statistic and finishes t/p
// outside MPC.
func TractorFinishFromRevealed(r *TractorRevealed, countThreshold int, detTol float64) *TractorResult {
	m := len(r.Det)
	npheno := len(r.BetaA)
	nTot := float64(r.NTot)

	res := &TractorResult{
		BetaA: mat.NewDense(m, npheno, nil), BetaAMR: mat.NewDense(m, npheno, nil), BetaEUR: mat.NewDense(m, npheno, nil),
		SEA: mat.NewDense(m, npheno, nil), SEAMR: mat.NewDense(m, npheno, nil), SEEUR: mat.NewDense(m, npheno, nil),
		TA: mat.NewDense(m, npheno, nil), TAMR: mat.NewDense(m, npheno, nil), TEUR: mat.NewDense(m, npheno, nil),
		PA: mat.NewDense(m, npheno, nil), PAMR: mat.NewDense(m, npheno, nil), PEUR: mat.NewDense(m, npheno, nil),
		Det: append([]float64(nil), r.Det...), Valid: make([]bool, m), ValidDesign: make([]bool, m), ValidCounts: make([]bool, m),
		NAMRHaps: make([]float64, m), NEURHaps: make([]float64, m),
		AltAMR: make([]float64, m), RefAMR: make([]float64, m),
		AltEUR: make([]float64, m), RefEUR: make([]float64, m),
	}

	tdist := distuv.StudentsT{Mu: 0, Sigma: 1, Nu: float64(r.DF)}

	for j := 0; j < m; j++ {
		nAMR := r.SumA[j]
		nEUR := 2*nTot - r.SumA[j]
		altAMR := r.SumAMR[j]
		refAMR := r.SumA[j] - r.SumAMR[j]
		altEUR := r.SumEUR[j]
		refEUR := 2*nTot - r.SumA[j] - r.SumEUR[j]

		res.NAMRHaps[j], res.NEURHaps[j] = nAMR, nEUR
		res.AltAMR[j], res.RefAMR[j] = altAMR, refAMR
		res.AltEUR[j], res.RefEUR[j] = altEUR, refEUR

		det := r.Det[j]
		validDesign := !math.IsNaN(det) && !math.IsInf(det, 0) && math.Abs(det) > detTol
		res.ValidDesign[j] = validDesign

		validCounts := true
		if countThreshold > 0 {
			thr := float64(countThreshold)
			validCounts = nAMR >= thr && nEUR >= thr && altAMR >= thr && refAMR >= thr && altEUR >= thr && refEUR >= thr
		}
		res.ValidCounts[j] = validCounts

		valid := validDesign && validCounts
		res.Valid[j] = valid

		if !valid {
			for k := 0; k < npheno; k++ {
				res.BetaA.Set(j, k, math.NaN())
				res.BetaAMR.Set(j, k, math.NaN())
				res.BetaEUR.Set(j, k, math.NaN())
				res.SEA.Set(j, k, math.NaN())
				res.SEAMR.Set(j, k, math.NaN())
				res.SEEUR.Set(j, k, math.NaN())
				res.TA.Set(j, k, math.NaN())
				res.TAMR.Set(j, k, math.NaN())
				res.TEUR.Set(j, k, math.NaN())
				res.PA.Set(j, k, math.NaN())
				res.PAMR.Set(j, k, math.NaN())
				res.PEUR.Set(j, k, math.NaN())
			}
			continue
		}

		for k := 0; k < npheno; k++ {
			betaA, betaM, betaE := r.BetaA[k][j], r.BetaAMR[k][j], r.BetaEUR[k][j]
			sigma2 := r.Sigma2[k][j]

			seA := math.Sqrt(sigma2 * r.Inv11[j])
			seM := math.Sqrt(sigma2 * r.Inv22[j])
			seE := math.Sqrt(sigma2 * r.Inv33[j])

			tA := betaA / seA
			tM := betaM / seM
			tE := betaE / seE

			res.BetaA.Set(j, k, betaA)
			res.BetaAMR.Set(j, k, betaM)
			res.BetaEUR.Set(j, k, betaE)
			res.SEA.Set(j, k, seA)
			res.SEAMR.Set(j, k, seM)
			res.SEEUR.Set(j, k, seE)
			res.TA.Set(j, k, tA)
			res.TAMR.Set(j, k, tM)
			res.TEUR.Set(j, k, tE)
			res.PA.Set(j, k, 2*tdist.Survival(math.Abs(tA)))
			res.PAMR.Set(j, k, 2*tdist.Survival(math.Abs(tM)))
			res.PEUR.Set(j, k, 2*tdist.Survival(math.Abs(tE)))
		}
	}

	res.DF = r.DF
	return res
}

// SaveTractorResultToFile writes one line per SNP for phenotype k, tab-separated, in the
// order beta_A, se_A, p_A, beta_AMR, se_AMR, p_AMR, beta_EUR, se_EUR, p_EUR, valid --
// matching the plain, headerless style of SaveFloatVectorToFile (gwas/utilities.go).
func SaveTractorResultToFile(filename string, result *TractorResult, pheno int) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	m, _ := result.BetaA.Dims()
	for j := 0; j < m; j++ {
		writer.WriteString(fmt.Sprintf("%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%.6e\t%v\n",
			result.BetaA.At(j, pheno), result.SEA.At(j, pheno), result.PA.At(j, pheno),
			result.BetaAMR.At(j, pheno), result.SEAMR.At(j, pheno), result.PAMR.At(j, pheno),
			result.BetaEUR.At(j, pheno), result.SEEUR.At(j, pheno), result.PEUR.At(j, pheno),
			result.Valid[j]))
	}

	if err := writer.Flush(); err != nil {
		log.Fatalf("SaveTractorResultToFile: flush failed for %s: %v", filename, err)
	}
}

// tractorCovOrthoFactor builds S (ncov-by-ncov) with SᵀS=(ZᵀZ)⁻¹ via eigendecomposition,
// exactly mirroring lazyCorr's construction in
// tests/unit_tests/assoc_projection_test.go (itself mirroring the secret-shared
// eigendecomposition branch of computeCovOrthoFactor in gwas/assoc.go). Also returns an
// estimate of rank(Z) from the eigenvalue spectrum, used for the regression's degrees of
// freedom.
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
		if l > maxLambda {
			maxLambda = l
		}
	}
	const relRankTol = 1e-8
	rank = 0
	for _, l := range lambda {
		if l > relRankTol*maxLambda {
			rank++
		}
	}

	scaling := math.Sqrt(math.Sqrt(float64(n)))
	S = mat.NewDense(ncov, ncov, nil)
	for i := 0; i < ncov; i++ {
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
