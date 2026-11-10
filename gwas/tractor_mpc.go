package gwas

import (
	"fmt"
	"math"
	"runtime"
	"time"

	mpc_core "github.com/hhcho/mpc-core"
	"github.com/ldsec/lattigo/v2/ckks"
	"go.dedis.ch/onet/v3/log"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/hcholab/sfgwas/mpc"

	"gonum.org/v1/gonum/mat"
)

// Stream order used throughout: 0 = A (local ancestry), 1 = X_AMR, 2 = X_EUR.
const tractorNumStreams = 3

// tractorCtBoostBits: S and YtQ enter CKKS at scale Δ·2^16 (mpc.SSToCMatBoosted).
// The projection terms multiply two ciphertexts, and in the intercept direction both
// are large for an uncentered phenotype (YtQ_0 ≈ √n·mean(y)); at the default scale the
// ~1e-5 absolute CKKS noise on B then dominated the error of b (measured: |Δbeta|/SE
// up to 4e-3 at n = 10^4, mean(y) = 170).
const tractorCtBoostBits = 16

// tractorPairs lists the six entries of the 3x3 Gram matrix S in the order
// s11, s22, s33, s12, s13, s23, as (stream, stream) pairs.
var tractorPairs = [6][2]int{{0, 0}, {1, 1}, {2, 2}, {0, 1}, {0, 2}, {1, 2}}

// tractorLocalBlock is one party's local (unaggregated) sums over one genotype block's
// kept SNPs, from a single pass over the three ancestry streams.
type tractorLocalBlock struct {
	nsnp  int
	ZtX   [tractorNumStreams][][]float64 // ncov-by-nsnp: Zᵀ·X (unscaled)
	YtX   [tractorNumStreams][][]float64 // npheno-by-nsnp: Yᵀ·X
	sum   [tractorNumStreams][]float64   // Σ x (dosage sums, for the count filter)
	gram  [6][]float64                   // Σ x·y for the pairs in tractorPairs
	nrows int
}

// tractorFusedPass streams the three ancestry files of one block in lockstep, once, and
// returns every local sum the protocol needs: Zᵀ·X and Yᵀ·X for each stream (matIn is
// [Zt; Yt], ncov+npheno rows by local samples) and the per-SNP dosage sums and raw Gram
// entries. Missing calls (negative entries) are imputed as 0 in all of them.
//
// Rows are read in chunks; each chunk is multiplied tile by tile (columns) in parallel
// with gonum, and the elementwise sums are accumulated in the same tiles.
func tractorFusedPass(matIn *mat.Dense, ncov int, streams [tractorNumStreams]*GenoFileStream, nproc int) *tractorLocalBlock {
	nrow, ncol := int(streams[0].NumRowsToKeep()), int(streams[0].NumColsToKeep())
	for x := 1; x < tractorNumStreams; x++ {
		if int(streams[x].NumRowsToKeep()) != nrow || int(streams[x].NumColsToKeep()) != ncol {
			log.Fatalf("Tractor: ancestry streams disagree on dimensions: %dx%d vs %dx%d",
				nrow, ncol, streams[x].NumRowsToKeep(), streams[x].NumColsToKeep())
		}
	}
	s, samples := matIn.Dims()
	if samples != nrow {
		log.Fatalf("Tractor: %d samples in phenotype/covariate matrix, %d in the ancestry streams", samples, nrow)
	}
	if nproc <= 0 {
		nproc = runtime.GOMAXPROCS(0)
	}

	out := &tractorLocalBlock{nsnp: ncol, nrows: nrow}
	proj := [tractorNumStreams][][]float64{}
	for x := 0; x < tractorNumStreams; x++ {
		proj[x] = make([][]float64, s)
		for i := range proj[x] {
			proj[x][i] = make([]float64, ncol)
		}
		out.sum[x] = make([]float64, ncol)
	}
	for p := range out.gram {
		out.gram[p] = make([]float64, ncol)
	}

	for x := range streams {
		streams[x].Reset()
	}

	// Chunk height: keep the three int8 row buffers around 32 MB.
	chunk := 32 << 20 / (tractorNumStreams * Max(ncol, 1))
	chunk = Max(16, Min(2048, chunk))
	const tile = 256
	numTiles := (ncol + tile - 1) / tile

	rows := [tractorNumStreams][][]int8{}
	for r0 := 0; r0 < nrow; r0 += chunk {
		r1 := Min(r0+chunk, nrow)
		for x := range streams {
			rows[x] = rows[x][:0]
			for i := r0; i < r1; i++ {
				row := streams[x].NextRow()
				if row == nil {
					log.Fatalf("Tractor: ancestry stream %d ended after %d of %d rows", x, i, nrow)
				}
				for j, v := range row {
					if v < 0 {
						row[j] = 0
					}
				}
				rows[x] = append(rows[x], row)
			}
		}
		nr := r1 - r0
		inChunk := matIn.Slice(0, s, r0, r1)

		parallelBlocks(numTiles, nproc, func(t0, t1 int) {
			for t := t0; t < t1; t++ {
				c0, c1 := t*tile, Min((t+1)*tile, ncol)
				w := c1 - c0
				var X [tractorNumStreams]*mat.Dense
				for x := 0; x < tractorNumStreams; x++ {
					X[x] = mat.NewDense(nr, w, nil)
					for i := 0; i < nr; i++ {
						dst := X[x].RawRowView(i)
						for j, v := range rows[x][i][c0:c1] {
							dst[j] = float64(v)
						}
					}
					var prod mat.Dense
					prod.Mul(inChunk, X[x])
					for i := 0; i < s; i++ {
						src, dst := prod.RawRowView(i), proj[x][i][c0:c1]
						for j := range dst {
							dst[j] += src[j]
						}
					}
				}
				for i := 0; i < nr; i++ {
					a, m, e := X[0].RawRowView(i), X[1].RawRowView(i), X[2].RawRowView(i)
					for j := 0; j < w; j++ {
						col := c0 + j
						out.sum[0][col] += a[j]
						out.sum[1][col] += m[j]
						out.sum[2][col] += e[j]
						out.gram[0][col] += a[j] * a[j]
						out.gram[1][col] += m[j] * m[j]
						out.gram[2][col] += e[j] * e[j]
						out.gram[3][col] += a[j] * m[j]
						out.gram[4][col] += a[j] * e[j]
						out.gram[5][col] += m[j] * e[j]
					}
				}
			}
		})
	}

	for x := 0; x < tractorNumStreams; x++ {
		out.ZtX[x] = proj[x][:ncov]
		out.YtX[x] = proj[x][ncov:]
	}
	return out
}

// tractorProjectionTerms computes, in CKKS, the covariate-projection terms that are
// subtracted from the raw sums, for one block. B holds the three streams' projections
// B_x = QᵀX side by side (row c = covariate c; ciphertexts [x·numCtx, (x+1)·numCtx) are
// stream x). Output rows: 0..5 are Σ_c B_x[c]⊙B_y[c] for the pairs in tractorPairs;
// row 6 + x·npheno + k is YtQ_k·B_x.
//
// Each output is a sum of same-scale products rescaled once, so nothing here mixes
// scales; the subtraction from the raw sums happens later, in the secret-shared domain.
func tractorProjectionTerms(cryptoParams *crypto.CryptoParams, B, YtQ crypto.CipherMatrix, numCtx, numThreads int) crypto.CipherMatrix {
	ncov := len(B)
	npheno := len(YtQ)

	for c := range B {
		for t := range B[c] {
			crypto.MustSameScale("Tractor: B = QᵀX ciphertexts", B[0][0], B[c][t])
		}
	}

	out := make(crypto.CipherMatrix, len(tractorPairs)+tractorNumStreams*npheno)
	for i := range tractorPairs {
		out[i] = make(crypto.CipherVector, numCtx)
	}

	var failure firstError
	parallelBlocks(len(tractorPairs)*numCtx, Max(1, numThreads), func(start, end int) {
		failure.record(cryptoParams.WithEvaluator(func(eval ckks.Evaluator) error {
			for job := start; job < end; job++ {
				pi, t := job/numCtx, job%numCtx
				x, y := tractorPairs[pi][0], tractorPairs[pi][1]
				var acc *ckks.Ciphertext
				for c := 0; c < ncov; c++ {
					prod := eval.MulRelinNew(B[c][x*numCtx+t], B[c][y*numCtx+t])
					if acc == nil {
						acc = prod
					} else {
						eval.Add(acc, prod, acc)
					}
				}
				if err := eval.Rescale(acc, cryptoParams.Params.Scale(), acc); err != nil {
					return err
				}
				out[pi][t] = acc
			}
			return nil
		}))
	})
	if err := failure.get(); err != nil {
		log.Fatalf("Tractor: projection Gram terms: %v", err)
	}

	R := CMultMatRowTimesRow(cryptoParams, YtQ, B, numThreads) // npheno-by-(3·numCtx)
	for x := 0; x < tractorNumStreams; x++ {
		for k := 0; k < npheno; k++ {
			out[len(tractorPairs)+x*npheno+k] = R[k][x*numCtx : (x+1)*numCtx]
		}
	}
	return out
}

// tractorShares turns this party's raw local values into its additive share of their
// sum over parties: the values themselves on data parties, zeros on party 0. Such shares
// must never be revealed directly (that would disclose each party's local value); they
// only feed masked operations (Beaver products, truncation).
func tractorShares(rtype mpc_core.RElem, pid int, vals []float64, n, fracBits int) mpc_core.RVec {
	out := mpc_core.InitRVec(rtype.Zero(), n)
	if pid > 0 {
		if len(vals) != n {
			log.Fatalf("Tractor: %d local values, expected %d", len(vals), n)
		}
		for i, v := range vals {
			out[i] = rtype.FromFloat64(v, fracBits)
		}
	}
	return out
}

// compactRVec keeps the entries of v at the positions where filt is true.
func compactRVec(v mpc_core.RVec, filt []bool, n int) mpc_core.RVec {
	out := make(mpc_core.RVec, 0, n)
	for i, keep := range filt {
		if keep {
			out = append(out, v[i])
		}
	}
	if len(out) != n {
		log.Fatalf("Tractor: compaction kept %d entries, expected %d", len(out), n)
	}
	return out
}

// concatRVec concatenates vectors; splitRVec undoes it for equal-length pieces.
func concatRVec(vs ...mpc_core.RVec) mpc_core.RVec {
	n := 0
	for _, v := range vs {
		n += len(v)
	}
	out := make(mpc_core.RVec, 0, n)
	for _, v := range vs {
		out = append(out, v...)
	}
	return out
}

func splitRVec(v mpc_core.RVec, pieces, length int) []mpc_core.RVec {
	if len(v) != pieces*length {
		log.Fatalf("Tractor: cannot split %d entries into %d pieces of %d", len(v), pieces, length)
	}
	out := make([]mpc_core.RVec, pieces)
	for i := range out {
		out[i] = v[i*length : (i+1)*length]
	}
	return out
}

// beaverVec is a vector split for Beaver multiplication (see mpc.BeaverPartitionVec):
// partitioned once, it can enter any number of products, whose sums are formed locally
// and reconstructed in one round. This is what lets the whole 3x3 solve run in three
// multiplication rounds.
type beaverVec struct{ r, m mpc_core.RVec }

// beaverPartition partitions several vectors with a single reveal.
func beaverPartition(mpcObj *mpc.MPC, vs ...mpc_core.RVec) []beaverVec {
	all := concatRVec(vs...)
	r, m := mpcObj.BeaverPartitionVec(all)
	out := make([]beaverVec, len(vs))
	off := 0
	for i, v := range vs {
		out[i] = beaverVec{r[off : off+len(v)], m[off : off+len(v)]}
		off += len(v)
	}
	return out
}

// mul is this party's (unreconstructed) share of x⊙y.
func (x beaverVec) mul(mpcObj *mpc.MPC, y beaverVec) mpc_core.RVec {
	return mpcObj.BeaverMultElemVec(x.r, x.m, y.r, y.m)
}

// broadcast repeats element i of a partitioned vector n times (a scalar factor in an
// elementwise product); partitioning the scalar once and expanding locally is valid
// because the expanded pieces are identical on every party.
func (x beaverVec) broadcast(i, n int) beaverVec {
	r, m := make(mpc_core.RVec, n), make(mpc_core.RVec, n)
	for j := range r {
		r[j], m[j] = x.r[i], x.m[i]
	}
	return beaverVec{r, m}
}

func rvAdd(a mpc_core.RVec, bs ...mpc_core.RVec) mpc_core.RVec {
	out := a.Copy()
	for _, b := range bs {
		out.Add(b)
	}
	return out
}

func rvSub(a, b mpc_core.RVec) mpc_core.RVec {
	out := a.Copy()
	out.Sub(b)
	return out
}

// GetTractorStatsPlainMult computes the Tractor association statistics over the
// encrypted/secret-shared protocol and returns what it reveals (see TractorRevealed in
// tractor.go for the quantities and why they are equivalent to {det, inv_ii, beta,
// sigma2}).
//
// Data flow, for per-SNP sufficient statistics S (3x3), b (per phenotype) and sy:
//
//  1. Covariate orthogonalization factor S_Z (SᵀS = n·(ZᵀZ)⁻¹) in the secret-shared
//     domain, shared with the single-variant test (computeCovOrthoFactor); YtQ = S_Z·ZᵀY/√n
//     stays secret-shared and is also converted to CKKS. Z is assumed to have full column
//     rank (degrees of freedom n - ncov - 3); CholeskyInvSqrt does not detect a rank-
//     deficient Z.
//  2. Per block, one fused local pass over the three ancestry streams gives every local
//     sum (tractorFusedPass). Only the covariate projections need CKKS: B_x = QᵀX via
//     applyCTAdditive (one call for all three streams), then Σ_c B_x⊙B_y and YtQ·B_x
//     (tractorProjectionTerms). These are converted to secret shares in one batched
//     CMatToSS after the last block and compacted to the kept SNPs (each block is padded
//     to whole ciphertexts).
//  3. The raw local sums (Σ x·y, Yᵀx, yᵀy) are already additive shares of the global sums
//     and enter the secret-shared domain directly, so "raw - projection" is a
//     secret-shared subtraction: no CKKS addition ever mixes a fresh ciphertext with a
//     rescaled one (Lattigo misreads such scale mismatches; see crypto.SameScaleTol).
//  4. S and b are divided by 2^k, k = ceil(log2 n), with one truncation, then the solve
//     runs in three Beaver rounds (cofactors and ‖YtQ‖²; det' and adj(S')·b'; T'), each a
//     single partition/reconstruct/truncate over concatenated vectors. No secret-shared
//     division: Divide's input must stay below 2^(dataBits-fracBits), which det ~ n³ does
//     not, and its output 1/det falls below the fixed-point resolution.
//  5. det' is revealed, the dosage sums are aggregated and decrypted in CKKS, the
//     det/count prefilter is evaluated in plaintext, and the remaining quantities are
//     revealed only for the SNPs that pass it.
//
// Party 0 takes part in every secret-shared step with zero shares and learns only the
// counts the hub sends it (numCtx, nsnps).
func (ast *AssocTestPlainMult) GetTractorStatsPlainMult() (*TractorRevealed, []int) {
	numThreads := ast.general.config.LocalNumThreads
	config := ast.general.config

	cryptoParams := ast.general.cps
	slots := cryptoParams.GetSlots()

	mpcObj := ast.general.mpcObj[0]
	fracBits, dataBits := mpcObj.GetFracBits(), mpcObj.GetDataBits()
	rtype := mpcObj.GetRType()
	pid, hub := mpcObj.GetPid(), mpcObj.GetHubPid()

	gwasParams := ast.general.gwasParams
	numBlocks := config.GenoNumBlocks

	nrowsAll := gwasParams.FiltNumInds()
	nrowsTotal := 0
	for i := 1; i < len(nrowsAll); i++ {
		nrowsTotal += nrowsAll[i]
	}
	nInvSqrt := math.Sqrt(1.0 / float64(nrowsTotal))

	ncov := gwasParams.NumCov() + gwasParams.NumPC()
	npheno := gwasParams.NumPheno()

	Zt := ast.covPc
	Yt := ast.pheno

	// Guarantee Z carries an intercept row, exactly as GetAssociationStatsPlainMult does.
	// The intercept is stored as 1/sqrt(n), matching the ZtZ/sqrt(n) scaling below.
	if !config.CovAllOnes {
		_, cols := Zt.Dims()
		ones := mat.NewDense(1, cols, nil)
		if pid > 0 {
			for i := 0; i < cols; i++ {
				ones.Set(0, i, nInvSqrt)
			}
		}
		covWithIntercept := mat.NewDense(ncov+1, cols, nil)
		covWithIntercept.Stack(ones, Zt)
		Zt = covWithIntercept
		ncov++
	} else {
		log.LLvl1("Warning: assumes the first covariate is all ones (if not, reorder input)")
	}

	if config.UseEigenCovOrtho {
		// Measured (n = 1000, 2 covariates + intercept): |Δbeta|/SE up to ~0.1 against the
		// plaintext reference, from EigenDecomp's fixed-point precision on ZᵀZ (see its doc
		// comment); the default Cholesky construction is accurate to ~1e-5.
		log.Warn("Tractor: use_eigen_cov_ortho = true is markedly less accurate than the default Cholesky " +
			"covariate orthogonalization; use it only for diagnostics")
	}

	normExp := TractorNormExp(nrowsTotal)
	df := nrowsTotal - ncov - 3 // full-rank Z assumed (see step 1 above)

	log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: covariates (incl. intercept)", ncov, "phenotypes", npheno,
		"individuals", nrowsTotal, "normalization 2^-", normExp)

	/* 1. Covariate orthogonalization factor and YtQ */

	var tmp mat.SymDense
	tmp.SymOuterK(nInvSqrt, Zt)
	ZtZss := mpc.DenseToRMat(rtype, &tmp, fracBits)
	tmp.Reset()

	scaling := rtype.FromFloat64(math.Sqrt(math.Sqrt(float64(nrowsTotal))), fracBits)
	covOrtho := ast.computeCovOrthoFactor(cryptoParams, ZtZss, scaling, nil, numThreads, tractorCtBoostBits)
	ZtZss = nil

	var ZtYss mpc_core.RMat
	if pid > 0 {
		var ZtY mat.Dense
		ZtY.Mul(Zt, Yt.T())
		ZtY.Scale(nInvSqrt, &ZtY)
		ZtYss = mpc.DenseToRMat(rtype, &ZtY, fracBits)
	} else {
		ZtYss = mpc_core.InitRMat(rtype.Zero(), ncov, npheno)
	}
	QtYss := covOrtho.applySS(ZtYss) // ncov-by-npheno, QᵀY

	YtQss := mpc_core.InitRMat(rtype.Zero(), npheno, ncov)
	for c := 0; c < ncov; c++ {
		for k := 0; k < npheno; k++ {
			YtQss[k][c] = QtYss[c][k].Copy()
		}
	}
	YtQ := mpcObj.SSToCMatBoosted(cryptoParams, YtQss, tractorCtBoostBits) // dummy on party 0

	/* 2-3. Per-block local sums and CKKS projection terms (data parties only) */

	nproj := len(tractorPairs) + tractorNumStreams*npheno
	var projAll crypto.CipherMatrix
	var outFilter []bool
	var snpIndex []int
	var numCtx, nsnps int

	rawGram := [6][]float64{}
	rawYtX := make([][]float64, tractorNumStreams*npheno) // row x·npheno + k
	rawSum := [tractorNumStreams][]float64{}
	YtY := make([]float64, npheno)

	if pid > 0 {
		matIn := mat.NewDense(ncov+npheno, nrowsAll[pid], nil)
		matIn.Stack(Zt, Yt)

		for k := 0; k < npheno; k++ {
			for _, v := range Yt.RawRowView(k) {
				YtY[k] += v * v
			}
		}

		var projBlocks []crypto.CipherMatrix
		shift := 0
		for b := 0; b < numBlocks; b++ {
			blockShift := shift
			shift += ast.general.genoBlockSizes[b]

			if !ast.general.IsBlockForAssocTest(b) {
				log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "skipped")
				continue
			}
			streams := [tractorNumStreams]*GenoFileStream{
				ast.general.genoBlocksA[b], ast.general.genoBlocksAMR[b], ast.general.genoBlocksEUR[b]}
			nsnpBlock := int(streams[0].NumColsToKeep())
			if nsnpBlock == 0 {
				log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "has no SNPs after QC")
				continue
			}

			loc := tractorFusedPass(matIn, ncov, streams, 0)
			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "local sums computed,", nsnpBlock, "SNPs")

			// B_x = QᵀX_x for the three streams in one applyCTAdditive call: each stream's
			// ZᵀX/√n rows are padded to whole ciphertexts and laid side by side.
			numCtxB := (nsnpBlock + slots - 1) / slots
			padded := make([][]float64, ncov)
			for c := 0; c < ncov; c++ {
				padded[c] = make([]float64, tractorNumStreams*numCtxB*slots)
				for x := 0; x < tractorNumStreams; x++ {
					dst := padded[c][x*numCtxB*slots:]
					for j, v := range loc.ZtX[x][c] {
						dst[j] = v * nInvSqrt
					}
				}
			}
			B := covOrtho.applyCTAdditive(padded)
			projBlocks = append(projBlocks, tractorProjectionTerms(cryptoParams, B, YtQ, numCtxB, numThreads))
			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "projection terms computed")

			for t := 0; t < numCtxB*slots; t++ {
				outFilter = append(outFilter, t < nsnpBlock)
			}
			numCtx += numCtxB
			nsnps += nsnpBlock

			cols := streams[0].ColFilt()
			for j := 0; j < ast.general.genoBlockSizes[b]; j++ {
				if cols == nil || cols[j] {
					snpIndex = append(snpIndex, blockShift+j)
				}
			}

			for p := range rawGram {
				rawGram[p] = append(rawGram[p], loc.gram[p]...)
			}
			for x := 0; x < tractorNumStreams; x++ {
				rawSum[x] = append(rawSum[x], loc.sum[x]...)
				for k := 0; k < npheno; k++ {
					rawYtX[x*npheno+k] = append(rawYtX[x*npheno+k], loc.YtX[x][k]...)
				}
			}
		}

		if len(snpIndex) != nsnps {
			log.Fatalf("Tractor: %d SNP indices for %d output SNPs", len(snpIndex), nsnps)
		}
		if nsnps > 0 {
			projAll = crypto.ConcatCipherMatrix(projBlocks)
			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: projection terms at level", projAll[0][0].Level(),
				"(Gram) /", projAll[nproj-1][0].Level(), "(YtQ·B)")
		}

		if pid == hub {
			mpcObj.Network.SendInt(numCtx, 0)
			mpcObj.Network.SendInt(nsnps, 0)
		}
	} else {
		numCtx = mpcObj.Network.ReceiveInt(hub)
		nsnps = mpcObj.Network.ReceiveInt(hub)
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "Tractor:", nsnps, "SNPs in", numCtx, "ciphertexts per row")
	mpcObj.AssertSync()

	if nsnps == 0 {
		log.Warn("Tractor: no SNPs to test")
		return &TractorRevealed{NTot: nrowsTotal, DF: df, NormExp: normExp, T: make([][]float64, npheno),
			NumA: make([][]float64, npheno), NumAMR: make([][]float64, npheno), NumEUR: make([][]float64, npheno)}, nil
	}

	/* Projection terms to secret shares (one batched conversion), compacted */

	projSS := mpcObj.CMatToSS(cryptoParams, rtype, projAll, -1, nproj, numCtx, numCtx*slots) // zeros on party 0
	proj := make([]mpc_core.RVec, nproj)
	for r := range proj {
		if pid > 0 {
			proj[r] = compactRVec(projSS[r], outFilter, nsnps)
		} else {
			proj[r] = mpc_core.InitRVec(rtype.Zero(), nsnps)
		}
	}
	projSS = nil

	// Debug only: reveal the aggregate projection terms (rows as in tractorProjectionTerms)
	// to cache/tractor_projection_debug.txt, for comparison against a plaintext oracle.
	if config.Debug {
		dbg := make([][]float64, nproj)
		for r := range proj {
			dbg[r] = mpcObj.RevealSymVec(proj[r]).ToFloat(fracBits)
		}
		if pid > 0 {
			SaveFloatMatrixToFileRowMajor(ast.general.CachePath("tractor_projection_debug.txt"), dbg)
		}
	}

	/* 4. Residualize (raw - projection), normalize by 2^-k */

	resid := make([]mpc_core.RVec, nproj)
	for p := range tractorPairs {
		resid[p] = rvSub(tractorShares(rtype, pid, rawGram[p], nsnps, fracBits), proj[p])
	}
	for i := 0; i < tractorNumStreams*npheno; i++ {
		resid[len(tractorPairs)+i] = rvSub(tractorShares(rtype, pid, rawYtX[i], nsnps, fracBits), proj[len(tractorPairs)+i])
	}
	norm := splitRVec(mpcObj.TruncVec(concatRVec(resid...), dataBits, normExp), nproj, nsnps)
	sN := norm[:len(tractorPairs)] // s'11, s'22, s'33, s'12, s'13, s'23
	bN := norm[len(tractorPairs):] // b'_x,k at x·npheno + k

	/* Round 1: cofactors of S' and ‖YtQ_k‖² */

	YtQflat := concatRVec(YtQss...)
	l1 := beaverPartition(mpcObj, append(append(append([]mpc_core.RVec{}, sN...), bN...), YtQflat)...)
	s11, s22, s33, s12, s13, s23 := l1[0], l1[1], l1[2], l1[3], l1[4], l1[5]
	bP := l1[len(tractorPairs) : len(tractorPairs)+len(bN)]
	yq := l1[len(l1)-1]

	cof := []mpc_core.RVec{
		rvSub(s22.mul(mpcObj, s33), s23.mul(mpcObj, s23)), // c11
		rvSub(s11.mul(mpcObj, s33), s13.mul(mpcObj, s13)), // c22
		rvSub(s11.mul(mpcObj, s22), s12.mul(mpcObj, s12)), // c33
		rvSub(s13.mul(mpcObj, s23), s12.mul(mpcObj, s33)), // c12
		rvSub(s12.mul(mpcObj, s23), s13.mul(mpcObj, s22)), // c13
		rvSub(s12.mul(mpcObj, s13), s11.mul(mpcObj, s23)), // c23
	}
	yqSq := yq.mul(mpcObj, yq)
	yqNorm := mpc_core.InitRVec(rtype.Zero(), npheno)
	for k := 0; k < npheno; k++ {
		for c := 0; c < ncov; c++ {
			yqNorm[k] = yqNorm[k].Add(yqSq[k*ncov+c])
		}
	}
	r1 := mpcObj.TruncVec(mpcObj.BeaverReconstructVec(concatRVec(append(cof, yqNorm)...)), dataBits, fracBits)
	cofT := splitRVec(r1[:6*nsnps], 6, nsnps) // c'11, c'22, c'33, c'12, c'13, c'23
	// sy = yᵀy - ‖YtQ‖², in raw units (it enters T' through the final 2^-k truncation)
	sy := rvSub(tractorShares(rtype, pid, YtY, npheno, fracBits), r1[6*nsnps:])

	/* Round 2: det' = s'·c' (first row) and num' = adj(S')·b' */

	l2 := beaverPartition(mpcObj, cofT...)
	c11, c22, c33, c12, c13, c23 := l2[0], l2[1], l2[2], l2[3], l2[4], l2[5]
	out2 := []mpc_core.RVec{rvAdd(s11.mul(mpcObj, c11), s12.mul(mpcObj, c12), s13.mul(mpcObj, c13))}
	for _, row := range [3][3]beaverVec{{c11, c12, c13}, {c12, c22, c23}, {c13, c23, c33}} { // rows of adj(S')
		for k := 0; k < npheno; k++ {
			out2 = append(out2, rvAdd(row[0].mul(mpcObj, bP[0*npheno+k]),
				row[1].mul(mpcObj, bP[1*npheno+k]), row[2].mul(mpcObj, bP[2*npheno+k])))
		}
	}
	r2 := splitRVec(mpcObj.TruncVec(mpcObj.BeaverReconstructVec(concatRVec(out2...)), dataBits, fracBits), 1+3*npheno, nsnps)
	detN := r2[0]
	numN := r2[1:] // num'_x,k at x·npheno + k

	/* Round 3: T'_k = (sy_k·det' - 2^k·num'_kᵀb'_k) / 2^k */

	l3 := beaverPartition(mpcObj, append([]mpc_core.RVec{detN, sy}, numN...)...)
	detP, syP, numP := l3[0], l3[1], l3[2:]
	twoK := rtype.FromInt(1 << normExp)
	out3 := make([]mpc_core.RVec, npheno)
	for k := 0; k < npheno; k++ {
		quad := rvAdd(numP[0*npheno+k].mul(mpcObj, bP[0*npheno+k]),
			numP[1*npheno+k].mul(mpcObj, bP[1*npheno+k]), numP[2*npheno+k].mul(mpcObj, bP[2*npheno+k]))
		quad.MulScalar(twoK)
		out3[k] = rvSub(syP.broadcast(k, nsnps).mul(mpcObj, detP), quad)
	}
	TN := splitRVec(mpcObj.TruncVec(mpcObj.BeaverReconstructVec(concatRVec(out3...)), dataBits, fracBits+normExp), npheno, nsnps)

	log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: secret-shared solve done")

	/* 5. Reveal det', decrypt the dosage sums, prefilter, reveal the rest where it passes */

	res := &TractorRevealed{NTot: nrowsTotal, DF: df, NormExp: normExp}
	detR := mpcObj.RevealSymVec(detN) // no-op on party 0
	if pid == 0 {
		return res, nil
	}
	res.Det = detR.ToFloat(fracBits)

	// Dosage sums: aggregated in CKKS and collectively decrypted, which reveals only the
	// totals (never a party's local sum); rounded in TractorPrefilter/Finish.
	sumsEnc, _, _, err := crypto.EncryptFloatMatrixRow(cryptoParams, rawSum[:])
	if err != nil {
		log.Fatal(err)
	}
	sumsEnc = mpcObj.Network.AggregateCMat(cryptoParams, sumsEnc)
	sumsDec := mpcObj.Network.CollectiveDecryptMat(cryptoParams, sumsEnc, -1)
	sums := make([][]float64, tractorNumStreams)
	for x := range sums {
		sums[x] = crypto.DecodeFloatVector(cryptoParams, sumsDec[x])[:nsnps]
	}
	res.SumA, res.SumAMR, res.SumEUR = sums[0], sums[1], sums[2]

	res.Revealed = TractorPrefilter(res.Det, res.SumA, res.SumAMR, res.SumEUR, nrowsTotal, normExp,
		config.TractorCountThreshold, config.TractorDetTol)
	var idx []int
	for j, ok := range res.Revealed {
		if ok {
			idx = append(idx, j)
		}
	}
	log.LLvl1(time.Now().Format(time.RFC3339), "Tractor:", len(idx), "/", nsnps, "SNPs pass the det/count filter")

	pick := func(v mpc_core.RVec) mpc_core.RVec {
		out := make(mpc_core.RVec, len(idx))
		for i, j := range idx {
			out[i] = v[j]
		}
		return out
	}
	toReveal := []mpc_core.RVec{pick(cofT[0]), pick(cofT[1]), pick(cofT[2])}
	for _, v := range numN {
		toReveal = append(toReveal, pick(v))
	}
	for _, v := range TN {
		toReveal = append(toReveal, pick(v))
	}
	var revealed []float64
	if len(idx) > 0 {
		revealed = mpcObj.RevealSymVec(concatRVec(toReveal...)).ToFloat(fracBits)
	}

	scatter := func(piece int) []float64 {
		out := make([]float64, nsnps)
		for j := range out {
			out[j] = math.NaN()
		}
		for i, j := range idx {
			out[j] = revealed[piece*len(idx)+i]
		}
		return out
	}
	res.C11, res.C22, res.C33 = scatter(0), scatter(1), scatter(2)
	res.NumA, res.NumAMR, res.NumEUR = make([][]float64, npheno), make([][]float64, npheno), make([][]float64, npheno)
	res.T = make([][]float64, npheno)
	for k := 0; k < npheno; k++ {
		res.NumA[k] = scatter(3 + 0*npheno + k)
		res.NumAMR[k] = scatter(3 + 1*npheno + k)
		res.NumEUR[k] = scatter(3 + 2*npheno + k)
		res.T[k] = scatter(3 + 3*npheno + k)
	}

	if config.Debug {
		log.LLvl1(fmt.Sprintf("Tractor debug: det'[:3]=%v", res.Det[:Min(3, nsnps)]))
	}

	return res, snpIndex
}
