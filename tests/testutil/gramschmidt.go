// Package testutil holds small helpers shared by the unit and e2e test packages,
// which otherwise can't see each other's unexported identifiers.
package testutil

import (
	"math"

	"gonum.org/v1/gonum/mat"
)

// GramSchmidt returns an orthonormal basis for the column space of M, computed
// independently of any eigendecomposition so it is a genuine reference.
func GramSchmidt(M *mat.Dense) *mat.Dense {
	n, k := M.Dims()
	Q := mat.NewDense(n, k, nil)
	for j := 0; j < k; j++ {
		v := make([]float64, n)
		for i := 0; i < n; i++ {
			v[i] = M.At(i, j)
		}
		for c := 0; c < j; c++ { // twice, for numerical stability
			for pass := 0; pass < 2; pass++ {
				var dot float64
				for i := 0; i < n; i++ {
					dot += Q.At(i, c) * v[i]
				}
				for i := 0; i < n; i++ {
					v[i] -= dot * Q.At(i, c)
				}
			}
		}
		var norm float64
		for i := 0; i < n; i++ {
			norm += v[i] * v[i]
		}
		norm = math.Sqrt(norm)
		if norm == 0 {
			// Column j is exactly linearly dependent on columns 0..j-1 (e.g. an
			// all-zero covariate) -- its residual is the zero vector, so v[i]/norm
			// would be 0/0 = NaN for every row, which then poisons every downstream
			// dot product against this column (every SNP's projection, every
			// phenotype's residual -- not just this one column). A zero-information
			// column should contribute nothing, so leave it as the zero vector
			// instead of NaN.
			continue
		}
		for i := 0; i < n; i++ {
			Q.Set(i, j, v[i]/norm)
		}
	}
	return Q
}
