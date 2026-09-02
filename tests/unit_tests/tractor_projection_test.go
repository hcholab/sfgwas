package unittests

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/hcholab/sfgwas/gwas"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat/distuv"
)

// TestTractorProjection checks gwas.TractorStatsPlain (the lazy S-projection,
// closed-form-Cramer's-rule Tractor implementation) against an independent reference:
// for each SNP, an explicit full multiple regression of y on [Z | A | X_AMR | X_EUR]
// via normal equations. By the Frisch-Waugh-Lovell theorem the two must agree exactly
// (up to float64 rounding) even though the reference never residualizes anything against
// Z first -- so this is a genuine cross-check of the closed-form 3x3 solve, not a
// restatement of the same formula. Mirrors the reference-vs-lazy structure of
// TestLazyCovariateProjection in assoc_projection_test.go.
func TestTractorProjection(t *testing.T) {
	const (
		n      = 200 // individuals
		ncov   = 6   // covariates including the intercept
		npheno = 3
		nsnp   = 12
		tol    = 1e-7
	)

	rng := rand.New(rand.NewSource(20260902))

	Z := mat.NewDense(n, ncov, nil)
	for i := 0; i < n; i++ {
		Z.Set(i, 0, 1) // intercept
		for j := 1; j < ncov; j++ {
			Z.Set(i, j, rng.NormFloat64())
		}
	}

	A := mat.NewDense(n, nsnp, nil)
	Xamr := mat.NewDense(n, nsnp, nil)
	Xeur := mat.NewDense(n, nsnp, nil)
	for j := 0; j < nsnp; j++ {
		pAnc := 0.3 + 0.4*rng.Float64()
		qAmr := 0.2 + 0.6*rng.Float64()
		qEur := 0.2 + 0.6*rng.Float64()
		for i := 0; i < n; i++ {
			a := binomial(rng, 2, pAnc)
			xamr := binomial(rng, a, qAmr)
			xeur := binomial(rng, 2-a, qEur)
			A.Set(i, j, float64(a))
			Xamr.Set(i, j, float64(xamr))
			Xeur.Set(i, j, float64(xeur))
		}
	}

	// Y = Z*gamma + a real genetic effect from SNP 0 + noise, so the comparison below is
	// non-degenerate (see the sanity check at the end) rather than trivially 0≈0.
	Y := mat.NewDense(n, npheno, nil)
	for k := 0; k < npheno; k++ {
		gamma := make([]float64, ncov)
		for c := range gamma {
			gamma[c] = rng.NormFloat64() * 0.5
		}
		wA := rng.NormFloat64()*0.8 + 0.8
		wM := rng.NormFloat64()*0.8 + 0.8
		wE := rng.NormFloat64()*0.8 + 0.8
		for i := 0; i < n; i++ {
			v := 0.0
			for c := 0; c < ncov; c++ {
				v += Z.At(i, c) * gamma[c]
			}
			v += wA*A.At(i, 0) + wM*Xamr.At(i, 0) + wE*Xeur.At(i, 0)
			v += rng.NormFloat64() * 1.5
			Y.Set(i, k, v)
		}
	}

	want := referenceTractor(Z, Y, A, Xamr, Xeur)
	got := gwas.TractorStatsPlain(Z, Y, A, Xamr, Xeur, 5, 1e-9)

	if got.DF != want.df {
		t.Fatalf("degrees of freedom mismatch: lazy=%d reference=%d", got.DF, want.df)
	}

	for j := 0; j < nsnp; j++ {
		if !got.Valid[j] {
			t.Errorf("SNP %d: lazy implementation marked invalid unexpectedly (det=%g)", j, got.Det[j])
			continue
		}
		for k := 0; k < npheno; k++ {
			checkClose(t, j, k, "beta_A", got.BetaA.At(j, k), want.betaA.At(j, k), tol)
			checkClose(t, j, k, "beta_AMR", got.BetaAMR.At(j, k), want.betaM.At(j, k), tol)
			checkClose(t, j, k, "beta_EUR", got.BetaEUR.At(j, k), want.betaE.At(j, k), tol)
			checkClose(t, j, k, "se_A", got.SEA.At(j, k), want.seA.At(j, k), tol)
			checkClose(t, j, k, "se_AMR", got.SEAMR.At(j, k), want.seM.At(j, k), tol)
			checkClose(t, j, k, "se_EUR", got.SEEUR.At(j, k), want.seE.At(j, k), tol)
			checkClose(t, j, k, "t_A", got.TA.At(j, k), want.tA.At(j, k), tol)
			checkClose(t, j, k, "t_AMR", got.TAMR.At(j, k), want.tM.At(j, k), tol)
			checkClose(t, j, k, "t_EUR", got.TEUR.At(j, k), want.tE.At(j, k), tol)
			checkClose(t, j, k, "p_A", got.PA.At(j, k), want.pA.At(j, k), tol)
			checkClose(t, j, k, "p_AMR", got.PAMR.At(j, k), want.pM.At(j, k), tol)
			checkClose(t, j, k, "p_EUR", got.PEUR.At(j, k), want.pE.At(j, k), tol)
		}
	}

	// Sanity: SNP 0's effects must be non-degenerate, or the comparison above is vacuous.
	degenerate := true
	for k := 0; k < npheno; k++ {
		if math.Abs(got.BetaA.At(0, k)) > 1e-3 || math.Abs(got.BetaAMR.At(0, k)) > 1e-3 || math.Abs(got.BetaEUR.At(0, k)) > 1e-3 {
			degenerate = false
		}
	}
	if degenerate {
		t.Fatalf("reference effects at SNP 0 are all ~0; test is not exercising anything")
	}
}

func checkClose(t *testing.T, j, k int, name string, got, want, tol float64) {
	t.Helper()
	if math.IsNaN(want) || math.IsNaN(got) {
		t.Errorf("SNP %d pheno %d %s: NaN (got=%v want=%v)", j, k, name, got, want)
		return
	}
	if math.Abs(got-want) > tol {
		t.Errorf("SNP %d pheno %d %s mismatch: got=%v want=%v diff=%g", j, k, name, got, want, math.Abs(got-want))
	}
}

// binomial draws a sample from Binomial(ntrials, p) by summing ntrials Bernoulli(p)
// trials. ntrials is always 0, 1, or 2 in this test (ancestry dosage / haplotype
// counts), so a trial loop is simpler and avoids mixing math/rand (v1, used everywhere
// else in this test) with distuv.Binomial's math/rand/v2 source.
func binomial(rng *rand.Rand, ntrials int, p float64) int {
	c := 0
	for i := 0; i < ntrials; i++ {
		if rng.Float64() < p {
			c++
		}
	}
	return c
}

type referenceResult struct {
	betaA, betaM, betaE *mat.Dense
	seA, seM, seE       *mat.Dense
	tA, tM, tE          *mat.Dense
	pA, pM, pE          *mat.Dense
	df                  int
}

// referenceTractor computes, for each SNP independently, the full multiple regression
// of y on [Z | A[:,j] | X_AMR[:,j] | X_EUR[:,j]] via explicit normal equations -- no
// residualization, no shortcuts -- and reads off the coefficients/SEs/t/p on the last
// three (genotype) columns.
func referenceTractor(Z, Y, A, Xamr, Xeur *mat.Dense) referenceResult {
	n, ncov := Z.Dims()
	_, npheno := Y.Dims()
	_, m := A.Dims()
	df := n - ncov - 3

	res := referenceResult{
		betaA: mat.NewDense(m, npheno, nil), betaM: mat.NewDense(m, npheno, nil), betaE: mat.NewDense(m, npheno, nil),
		seA: mat.NewDense(m, npheno, nil), seM: mat.NewDense(m, npheno, nil), seE: mat.NewDense(m, npheno, nil),
		tA: mat.NewDense(m, npheno, nil), tM: mat.NewDense(m, npheno, nil), tE: mat.NewDense(m, npheno, nil),
		pA: mat.NewDense(m, npheno, nil), pM: mat.NewDense(m, npheno, nil), pE: mat.NewDense(m, npheno, nil),
		df: df,
	}
	tdist := distuv.StudentsT{Mu: 0, Sigma: 1, Nu: float64(df)}

	ncolFull := ncov + 3
	for j := 0; j < m; j++ {
		Xd := mat.NewDense(n, ncolFull, nil)
		for i := 0; i < n; i++ {
			for c := 0; c < ncov; c++ {
				Xd.Set(i, c, Z.At(i, c))
			}
			Xd.Set(i, ncov, A.At(i, j))
			Xd.Set(i, ncov+1, Xamr.At(i, j))
			Xd.Set(i, ncov+2, Xeur.At(i, j))
		}

		var XtX mat.Dense
		XtX.Mul(Xd.T(), Xd)
		var XtXInv mat.Dense
		if err := XtXInv.Inverse(&XtX); err != nil {
			panic(fmt.Sprintf("referenceTractor: singular design at SNP %d: %v", j, err))
		}

		for k := 0; k < npheno; k++ {
			yk := mat.NewDense(n, 1, nil)
			for i := 0; i < n; i++ {
				yk.Set(i, 0, Y.At(i, k))
			}

			var Xty, beta, fitted, resid mat.Dense
			Xty.Mul(Xd.T(), yk)
			beta.Mul(&XtXInv, &Xty)
			fitted.Mul(Xd, &beta)
			resid.Sub(yk, &fitted)

			rss := 0.0
			for i := 0; i < n; i++ {
				r := resid.At(i, 0)
				rss += r * r
			}
			sigma2 := rss / float64(df)

			bA, bM, bE := beta.At(ncov, 0), beta.At(ncov+1, 0), beta.At(ncov+2, 0)
			sA := math.Sqrt(sigma2 * XtXInv.At(ncov, ncov))
			sM := math.Sqrt(sigma2 * XtXInv.At(ncov+1, ncov+1))
			sE := math.Sqrt(sigma2 * XtXInv.At(ncov+2, ncov+2))

			res.betaA.Set(j, k, bA)
			res.betaM.Set(j, k, bM)
			res.betaE.Set(j, k, bE)
			res.seA.Set(j, k, sA)
			res.seM.Set(j, k, sM)
			res.seE.Set(j, k, sE)
			res.tA.Set(j, k, bA/sA)
			res.tM.Set(j, k, bM/sM)
			res.tE.Set(j, k, bE/sE)
			res.pA.Set(j, k, 2*tdist.Survival(math.Abs(bA/sA)))
			res.pM.Set(j, k, 2*tdist.Survival(math.Abs(bM/sM)))
			res.pE.Set(j, k, 2*tdist.Survival(math.Abs(bE/sE)))
		}
	}

	return res
}
