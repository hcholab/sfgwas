package unittests

import (
	"math"
	"math/rand"
	"testing"

	"github.com/hcholab/sfgwas/gwas"
	"gonum.org/v1/gonum/mat"
)

// oneSNPRevealed builds the revealed quantities for one SNP and one phenotype from an
// exact S (3x3), b and sy, normalized the way the protocol normalizes them.
func oneSNPRevealed(S [3][3]float64, b [3]float64, sy float64, n, df int, sums [3]float64) *gwas.TractorRevealed {
	bm := func(v float64) *mat.Dense { return mat.NewDense(1, 1, []float64{v}) }
	return gwas.TractorRevealedFromStats(
		[]float64{S[0][0]}, []float64{S[1][1]}, []float64{S[2][2]},
		[]float64{S[0][1]}, []float64{S[0][2]}, []float64{S[1][2]},
		bm(b[0]), bm(b[1]), bm(b[2]), []float64{sy},
		[]float64{sums[0]}, []float64{sums[1]}, []float64{sums[2]}, n, df)
}

// TestTractorFinishFromRevealed checks the normalized revealed representation against a
// direct 3x3 solve, and the validity, clamping and rounding rules.
func TestTractorFinishFromRevealed(t *testing.T) {
	const n, df = 1000, 994
	S := [3][3]float64{{420, 130, -150}, {130, 250, -40}, {-150, -40, 260}}
	b := [3]float64{35, -12, 20}
	sy := 980.0
	sums := [3]float64{700, 300, 500} // nAMR 700, nEUR 1300, alt/ref AMR 300/400, alt/ref EUR 500/800

	// Direct solve.
	Sd := mat.NewSymDense(3, []float64{S[0][0], S[0][1], S[0][2], S[1][0], S[1][1], S[1][2], S[2][0], S[2][1], S[2][2]})
	var inv mat.Dense
	if err := inv.Inverse(Sd); err != nil {
		t.Fatal(err)
	}
	var beta mat.VecDense
	beta.MulVec(&inv, mat.NewVecDense(3, b[:]))
	rss := sy - mat.Dot(&beta, mat.NewVecDense(3, b[:]))
	sigma2 := rss / df

	res := gwas.TractorFinishFromRevealed(oneSNPRevealed(S, b, sy, n, df, sums), 20, 1e-6)
	if !res.Valid[0] || !res.PhenoValid[0][0] {
		t.Fatalf("valid SNP reported invalid: %+v", res)
	}
	if want := mat.Det(Sd); math.Abs(res.Det[0]/want-1) > 1e-12 {
		t.Errorf("raw det %g, want %g", res.Det[0], want)
	}
	for i, got := range []float64{res.BetaA.At(0, 0), res.BetaAMR.At(0, 0), res.BetaEUR.At(0, 0)} {
		if math.Abs(got-beta.AtVec(i)) > 1e-12*math.Abs(beta.AtVec(i))+1e-15 {
			t.Errorf("beta[%d] = %.17g, want %.17g", i, got, beta.AtVec(i))
		}
	}
	for i, got := range []float64{res.SEA.At(0, 0), res.SEAMR.At(0, 0), res.SEEUR.At(0, 0)} {
		want := math.Sqrt(sigma2 * inv.At(i, i))
		if math.Abs(got/want-1) > 1e-12 {
			t.Errorf("se[%d] = %.17g, want %.17g", i, got, want)
		}
	}

	finish := func(r *gwas.TractorRevealed, thr int, tol float64) *gwas.TractorResult {
		return gwas.TractorFinishFromRevealed(r, thr, tol)
	}

	t.Run("count rounding at the threshold", func(t *testing.T) {
		// altAMR exactly at the threshold, but decoded slightly low (as CKKS does).
		r := oneSNPRevealed(S, b, sy, n, df, [3]float64{700, 20 - 3e-5, 500})
		if got := finish(r, 20, 1e-6); !got.Valid[0] || got.AltAMR[0] != 20 {
			t.Errorf("count 19.99997 not rounded to the threshold: valid=%v alt=%v", got.Valid[0], got.AltAMR[0])
		}
		r = oneSNPRevealed(S, b, sy, n, df, [3]float64{700, 19.4, 500})
		if got := finish(r, 20, 1e-6); got.Valid[0] || got.ValidCounts[0] {
			t.Error("count 19 accepted at threshold 20")
		}
		if got := finish(r, 0, 1e-6); !got.Valid[0] {
			t.Error("count filter not disabled by threshold 0")
		}
	})

	t.Run("det_tol in raw units, negative det", func(t *testing.T) {
		r := oneSNPRevealed(S, b, sy, n, df, sums)
		raw := gwas.TractorFinishFromRevealed(r, 20, 0).Det[0]
		if got := finish(r, 20, raw*1.0001); got.Valid[0] || got.ValidDesign[0] {
			t.Error("det below det_tol accepted")
		}
		if got := finish(r, 20, raw*0.9999); !got.Valid[0] {
			t.Error("det above det_tol rejected")
		}
		neg := oneSNPRevealed(S, b, sy, n, df, sums)
		neg.Det[0] = -neg.Det[0]
		if got := finish(neg, 20, 1e-6); got.Valid[0] || got.ValidDesign[0] {
			t.Error("negative det accepted (|det| > det_tol)")
		}
		nan := oneSNPRevealed(S, b, sy, n, df, sums)
		nan.Det[0] = math.NaN()
		if got := finish(nan, 20, 1e-6); got.Valid[0] {
			t.Error("NaN det accepted")
		}
	})

	t.Run("non-positive inverse diagonal", func(t *testing.T) {
		r := oneSNPRevealed(S, b, sy, n, df, sums)
		r.C22[0] = -r.C22[0]
		got := finish(r, 20, 1e-6)
		if got.Valid[0] || got.PhenoValid[0][0] || !math.IsNaN(got.SEAMR.At(0, 0)) {
			t.Errorf("negative (S^-1)_22 accepted: valid=%v se=%v", got.Valid[0], got.SEAMR.At(0, 0))
		}
	})

	t.Run("RSS clamped at zero", func(t *testing.T) {
		r := oneSNPRevealed(S, b, sy, n, df, sums)
		r.T[0][0] = -1e-9 // tiny negative RSS from rounding
		got := finish(r, 20, 1e-6)
		if !got.Valid[0] {
			t.Fatal("design rejected")
		}
		// RSS clamps to 0, so SE = 0 and t is infinite: reported invalid rather than p = 0.
		if got.PhenoValid[0][0] || !math.IsNaN(got.PA.At(0, 0)) {
			t.Errorf("perfect fit reported valid: p=%v", got.PA.At(0, 0))
		}
	})

	t.Run("degrees of freedom", func(t *testing.T) {
		r := oneSNPRevealed(S, b, sy, n, 0, sums)
		if got := finish(r, 20, 1e-6); got.Valid[0] {
			t.Error("df = 0 accepted")
		}
	})

	t.Run("prefilter agrees with finish", func(t *testing.T) {
		r := oneSNPRevealed(S, b, sy, n, df, [3]float64{700, 19.4, 500})
		pre := gwas.TractorPrefilter(r.Det, r.SumA, r.SumAMR, r.SumEUR, n, r.NormExp, 20, 1e-6)
		if pre[0] {
			t.Error("prefilter passes a SNP the finish rejects on counts")
		}
	})
}

// TestTractorStatsPlainEdgeCases: missing calls are imputed as 0, and a rank-deficient Z
// (a duplicated covariate) gives the same statistics as the full-rank Z, with
// df = n - rank(Z) - 3.
func TestTractorStatsPlainEdgeCases(t *testing.T) {
	const n, m = 300, 6
	rng := rand.New(rand.NewSource(11))
	Z := mat.NewDense(n, 3, nil)
	Zdup := mat.NewDense(n, 4, nil)
	Y := mat.NewDense(n, 1, nil)
	A, M, E := mat.NewDense(n, m, nil), mat.NewDense(n, m, nil), mat.NewDense(n, m, nil)
	Amiss, Mmiss, Emiss := mat.NewDense(n, m, nil), mat.NewDense(n, m, nil), mat.NewDense(n, m, nil)
	for i := 0; i < n; i++ {
		z1, z2 := rng.NormFloat64(), rng.NormFloat64()
		Z.SetRow(i, []float64{1, z1, z2})
		Zdup.SetRow(i, []float64{1, z1, z2, 2 * z1})
		for j := 0; j < m; j++ {
			a := binomial(rng, 2, 0.5)
			x := binomial(rng, a, 0.4)
			e := binomial(rng, 2-a, 0.6)
			A.Set(i, j, float64(a))
			M.Set(i, j, float64(x))
			E.Set(i, j, float64(e))
			if rng.Float64() < 0.05 { // missing call, jointly in all streams
				A.Set(i, j, 0)
				M.Set(i, j, 0)
				E.Set(i, j, 0)
				Amiss.Set(i, j, -1)
				Mmiss.Set(i, j, -1)
				Emiss.Set(i, j, -1)
			} else {
				Amiss.Set(i, j, float64(a))
				Mmiss.Set(i, j, float64(x))
				Emiss.Set(i, j, float64(e))
			}
		}
		Y.Set(i, 0, 0.3*z1+0.5*A.At(i, 0)+rng.NormFloat64())
	}

	ref := gwas.TractorStatsPlain(Z, Y, A, M, E, 5, 1e-9)
	miss := gwas.TractorStatsPlain(Z, Y, Amiss, Mmiss, Emiss, 5, 1e-9)
	dup := gwas.TractorStatsPlain(Zdup, Y, A, M, E, 5, 1e-9)

	if ref.DF != n-3-3 || dup.DF != ref.DF {
		t.Fatalf("df: full-rank %d, rank-deficient %d, want %d", ref.DF, dup.DF, n-6)
	}
	for j := 0; j < m; j++ {
		if !ref.Valid[j] || !miss.Valid[j] || !dup.Valid[j] {
			t.Fatalf("SNP %d invalid: %v %v %v", j, ref.Valid[j], miss.Valid[j], dup.Valid[j])
		}
		for _, c := range []struct {
			name      string
			a, b1, b2 float64
		}{
			{"beta_A", ref.BetaA.At(j, 0), miss.BetaA.At(j, 0), dup.BetaA.At(j, 0)},
			{"beta_EUR", ref.BetaEUR.At(j, 0), miss.BetaEUR.At(j, 0), dup.BetaEUR.At(j, 0)},
			{"se_AMR", ref.SEAMR.At(j, 0), miss.SEAMR.At(j, 0), dup.SEAMR.At(j, 0)},
			{"p_A", ref.PA.At(j, 0), miss.PA.At(j, 0), dup.PA.At(j, 0)},
		} {
			if math.Abs(c.a-c.b1) > 1e-12*(1+math.Abs(c.a)) {
				t.Errorf("SNP %d %s: missing-as--1 %g vs zero-imputed %g", j, c.name, c.b1, c.a)
			}
			if math.Abs(c.a-c.b2) > 1e-7*(1+math.Abs(c.a)) {
				t.Errorf("SNP %d %s: rank-deficient Z %g vs full-rank %g", j, c.name, c.b2, c.a)
			}
		}
	}
}
