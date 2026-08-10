package unittests

import (
	"math"
	"math/rand"
	"testing"

	"github.com/hcholab/sfgwas/tests/testutil"
	"gonum.org/v1/gonum/mat"
)

// TestLazyCovariateProjection checks the identity the plaintext-multiplication assoc
// test is built on:
//
//	I - QQᵀ  ==  I - Z(ZᵀZ)⁻¹Zᵀ,  where Q = QR(Z)
//
// realized as S = diag(L^{-1/2})Vᵀ with ZᵀZ = VLVᵀ, so that SZᵀ = Qᵀ. The reference
// side builds Q explicitly by Gram-Schmidt and projects; the lazy side never forms Q.
//
// It reproduces the exact scaling chain of GetAssociationStatsPlainMult — ZᵀZ and every
// operand of Qᵀ pre-scaled by 1/sqrt(n), compensated by folding n^{1/4} into L^{-1/2} —
// because those constants are the easiest thing to break and the hardest to spot in an
// encrypted end-to-end run. Everything here is plaintext float64: any disagreement is a
// bug in the formulation, not CKKS or fixed-point noise.
func TestLazyCovariateProjection(t *testing.T) {
	const (
		n      = 200 // individuals
		ncov   = 8   // covariates + PCs, including the intercept
		npheno = 3
		nsnp   = 12
		tol    = 1e-9
	)

	rng := rand.New(rand.NewSource(20260803))

	// Z: n-by-ncov, first column all ones (the intercept, as the protocol assumes).
	Z := mat.NewDense(n, ncov, nil)
	for i := 0; i < n; i++ {
		Z.Set(i, 0, 1)
		for j := 1; j < ncov; j++ {
			Z.Set(i, j, rng.NormFloat64())
		}
	}
	Y := randDense(rng, n, npheno) // phenotypes
	X := randDense(rng, n, nsnp)   // genotypes (dosages)
	scaleDense(X, 2, 0)            // roughly dosage-scaled, and not mean-centered
	scaleDense(Y, 1, 0.5)          // phenotypes offset from zero
	scaleDense(Z, 1, 0)            // Z left as is; keeps the call symmetric

	wantR := referenceCorr(Z, Y, X)
	gotR := lazyCorr(Z, Y, X)

	maxDiff := 0.0
	for i := 0; i < npheno; i++ {
		for j := 0; j < nsnp; j++ {
			d := math.Abs(wantR.At(i, j) - gotR.At(i, j))
			if d > maxDiff {
				maxDiff = d
			}
		}
	}
	if maxDiff > tol {
		t.Errorf("lazy projection disagrees with explicit QR projection: max |diff| = %g > %g\nwant:\n%v\ngot:\n%v",
			maxDiff, tol, mat.Formatted(wantR), mat.Formatted(gotR))
	}

	// Sanity: the statistics must be non-degenerate, or the comparison above is vacuous.
	if math.Abs(wantR.At(0, 0)) < 1e-12 {
		t.Fatalf("reference correlations are ~0; test is not exercising anything")
	}
}

// referenceCorr computes the per-(phenotype, SNP) correlation the way the original
// protocol does: form an orthonormal basis Q of Z, project it out of both Y and X.
func referenceCorr(Z, Y, X *mat.Dense) *mat.Dense {
	n, _ := Z.Dims()
	_, npheno := Y.Dims()
	_, nsnp := X.Dims()

	Q := testutil.GramSchmidt(Z)
	_, ncol := Q.Dims()

	// QtX (ncol-by-nsnp) and QtY (ncol-by-npheno)
	var QtX, QtY mat.Dense
	QtX.Mul(Q.T(), X)
	QtY.Mul(Q.T(), Y)

	// Ynew = (I - QQᵀ)Y
	var QQtY, Ynew mat.Dense
	QQtY.Mul(Q, &QtY)
	Ynew.Sub(Y, &QQtY)

	sxx := make([]float64, nsnp)
	for j := 0; j < nsnp; j++ {
		var norm2, proj2 float64
		for i := 0; i < n; i++ {
			norm2 += X.At(i, j) * X.At(i, j)
		}
		for c := 0; c < ncol; c++ {
			proj2 += QtX.At(c, j) * QtX.At(c, j)
		}
		sxx[j] = norm2 - proj2
	}

	syy := make([]float64, npheno)
	for i := 0; i < npheno; i++ {
		var s float64
		for r := 0; r < n; r++ {
			s += Ynew.At(r, i) * Ynew.At(r, i)
		}
		syy[i] = s
	}

	var sxy mat.Dense
	sxy.Mul(Ynew.T(), X) // npheno-by-nsnp

	return corrFrom(&sxy, sxx, syy)
}

// lazyCorr mirrors GetAssociationStatsPlainMult: Q is never formed. Comments cite the
// corresponding lines of gwas/assoc.go.
func lazyCorr(Z, Y, X *mat.Dense) *mat.Dense {
	n, ncov := Z.Dims()
	_, npheno := Y.Dims()
	_, nsnp := X.Dims()

	nInvSqrt := math.Sqrt(1 / float64(n))

	Zt := mat.DenseCopyOf(Z.T())

	// ZtZss: Zt*Z scaled by 1/sqrt(n).
	var A mat.SymDense
	A.SymOuterK(nInvSqrt, Zt)

	var eig mat.EigenSym
	if !eig.Factorize(&A, true) {
		panic("eigendecomposition failed")
	}
	var V mat.Dense
	eig.VectorsTo(&V) // columns are eigenvectors, so Vᵀ has them as rows
	lambda := eig.Values(nil)

	// S = diag(LsqrtInv) * Vᵀ, with sqrt(sqrt(n)) folded in so that every operand of
	// Qᵀ can be pre-scaled by 1/sqrt(n).
	scaling := math.Sqrt(math.Sqrt(float64(n)))
	S := mat.NewDense(ncov, ncov, nil)
	for i := 0; i < ncov; i++ {
		lsqrtInv := scaling / math.Sqrt(lambda[i])
		for j := 0; j < ncov; j++ {
			S.Set(i, j, lsqrtInv*V.At(j, i)) // V.At(j,i) is Vᵀ[i][j]
		}
	}

	// B = QᵀX = S * (ZᵀX / sqrt(n))
	var ZtX mat.Dense
	ZtX.Mul(Zt, X)
	ZtX.Scale(nInvSqrt, &ZtX)
	var B mat.Dense
	B.Mul(S, &ZtX) // ncov-by-nsnp

	// YtQ = (S * (ZᵀY / sqrt(n)))ᵀ
	var ZtY mat.Dense
	ZtY.Mul(Zt, Y)
	ZtY.Scale(nInvSqrt, &ZtY)
	var QtY mat.Dense
	QtY.Mul(S, &ZtY) // ncov-by-npheno
	YtQ := mat.DenseCopyOf(QtY.T())

	// sxx = diag(XᵀX) - diag(BᵀB)
	sxx := make([]float64, nsnp)
	for j := 0; j < nsnp; j++ {
		var norm2, proj2 float64
		for i := 0; i < n; i++ {
			norm2 += X.At(i, j) * X.At(i, j)
		}
		for c := 0; c < ncov; c++ {
			proj2 += B.At(c, j) * B.At(c, j)
		}
		sxx[j] = norm2 - proj2
	}

	// syy = diag(YᵀY) - diag((YᵀQ)(QᵀY))
	syy := make([]float64, npheno)
	for i := 0; i < npheno; i++ {
		var norm2, proj2 float64
		for r := 0; r < n; r++ {
			norm2 += Y.At(r, i) * Y.At(r, i)
		}
		for c := 0; c < ncov; c++ {
			proj2 += YtQ.At(i, c) * YtQ.At(i, c)
		}
		syy[i] = norm2 - proj2
	}

	// sxy = YᵀX - (YᵀQ)(QᵀX)
	var YtX, corr, sxy mat.Dense
	YtX.Mul(Y.T(), X)
	corr.Mul(YtQ, &B)
	sxy.Sub(&YtX, &corr)

	return corrFrom(&sxy, sxx, syy)
}

func corrFrom(sxy *mat.Dense, sxx, syy []float64) *mat.Dense {
	npheno, nsnp := sxy.Dims()
	out := mat.NewDense(npheno, nsnp, nil)
	for i := 0; i < npheno; i++ {
		for j := 0; j < nsnp; j++ {
			out.Set(i, j, sxy.At(i, j)/(math.Sqrt(sxx[j])*math.Sqrt(syy[i])))
		}
	}
	return out
}

func randDense(rng *rand.Rand, r, c int) *mat.Dense {
	m := mat.NewDense(r, c, nil)
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			m.Set(i, j, rng.NormFloat64())
		}
	}
	return m
}

func scaleDense(m *mat.Dense, mul, add float64) {
	r, c := m.Dims()
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			m.Set(i, j, m.At(i, j)*mul+add)
		}
	}
}
