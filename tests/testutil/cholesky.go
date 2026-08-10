package testutil

import (
	"fmt"
	"math"

	"gonum.org/v1/gonum/mat"
)

// Cholesky returns an orthonormal basis for the column space of M via Cholesky-QR:
// factor alpha*(M'M) = L*L' (L lower triangular), then Q = sqrt(alpha) * M * L^-T, so
// Q'Q = alpha * L^-1 (M'M) L^-T = L^-1 (alpha*M'M) L^-T = L^-1 (L L') L^-T = I --
// orthonormal for any alpha > 0.
//
// alpha exists only so L and Linv can be computed at the same scale the secure
// protocol uses: mpc.MPC.CholeskyInvSqrt factors Z'Z/sqrt(n), not Z'Z, so a caller
// wanting L/Linv comparable to the protocol's own revealed cholesky_L.txt /
// cholesky_Linv.txt must pass the matching alpha (e.g. 1/sqrt(n)) rather than 1 --
// otherwise the two L's differ by a constant factor of sqrt(alpha) and any diff is
// meaningless. Q is always the correctly-normalized orthonormal basis regardless of
// alpha, since the sqrt(alpha) factor on Q exactly cancels the one baked into L.
//
// This takes the identical mathematical path as CholeskyInvSqrt (Cholesky-factor
// the Gram matrix, then invert L), just in plain float64 instead of truncated
// fixed-point secret shares. That makes L and Linv here directly comparable to the
// protocol's own revealed L/Linv, and isolates whether a divergence downstream
// comes from fixed-point truncation or from the method itself (e.g. an
// ill-conditioned M'M) -- unlike GramSchmidt, which avoids the Cholesky/(M'M)
// conditioning question entirely and so can't be used for that comparison.
func Cholesky(M *mat.Dense, alpha float64) (Q, L, Linv *mat.Dense, err error) {
	_, k := M.Dims()

	var mtm mat.SymDense
	mtm.SymOuterK(alpha, M.T())

	var chol mat.Cholesky
	if ok := chol.Factorize(&mtm); !ok {
		return nil, nil, nil, fmt.Errorf("testutil.Cholesky: alpha*(M'M) is not positive definite")
	}

	var Ltri mat.TriDense
	chol.LTo(&Ltri)
	L = mat.NewDense(k, k, nil)
	L.Copy(&Ltri)

	Linv = mat.NewDense(k, k, nil)
	if invErr := Linv.Inverse(L); invErr != nil {
		// Inverse always returns a *mat.Condition on any nonzero rcond, even a merely
		// large (not infinite) one -- that's exactly the ill-conditioning this pathway
		// is meant to expose (see mpc.MPC.CholeskyInvSqrt's doc comment), so only treat
		// it as fatal when L was exactly singular (rcond == Inf, Getrf found no pivot).
		if cond, ok := invErr.(mat.Condition); !ok || math.IsInf(float64(cond), 1) {
			return nil, nil, nil, fmt.Errorf("testutil.Cholesky: inverting L: %w", invErr)
		}
	}

	Q = new(mat.Dense)
	Q.Mul(M, Linv.T())
	Q.Scale(math.Sqrt(alpha), Q)
	return Q, L, Linv, nil
}
