package gwas

import (
	"math"
	"time"

	mpc_core "github.com/hhcho/mpc-core"
	"github.com/ldsec/lattigo/v2/ckks"
	"go.dedis.ch/onet/v3/log"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/hcholab/sfgwas/mpc"

	"gonum.org/v1/gonum/mat"
)

// TractorRevealed carries the per-SNP, per-phenotype quantities GetTractorStatsPlainMult
// reveals from the encrypted/secret-shared protocol. It intentionally stops short of
// standard errors, t-statistics, and p-values -- those are finished in plaintext by
// TractorFinishFromRevealed, mirroring how the existing single-variant path only reveals
// a raw correlation-like statistic and leaves t/p-value conversion to post-processing.
type TractorRevealed struct {
	NTot int // total individuals across all parties
	DF   int // degrees of freedom used for sigma2 = RSS/DF and the Student's-t null

	Det                      []float64   // m
	Inv11, Inv22, Inv33      []float64   // m; cofactor/det, used for SE
	BetaA, BetaAMR, BetaEUR  [][]float64 // p-by-m
	Sigma2                   [][]float64 // p-by-m

	SumA, SumAMR, SumEUR []float64 // m; raw ancestry/allele dosage sums, for count filtering
}

// diagCrossProductSub subtracts diag(B1ᵀB2) from target in place, ciphertext-domain,
// generalizing the self-product idiom GetAssociationStatsPlainMult uses for sxx
// (gwas/assoc.go, the sxxBlocks computation) to two possibly-different projected
// genotype matrices B1, B2 (both ncov-by-nsnps). Passing the same matrix for B1 and B2
// reproduces the self case exactly.
func diagCrossProductSub(cryptoParams *crypto.CryptoParams, target crypto.CipherVector, B1, B2 crypto.CipherMatrix) {
	if err := cryptoParams.WithEvaluator(func(evaluator ckks.Evaluator) error {
		for c := range B1 {
			for j := range B1[c] {
				tmp := evaluator.MulRelinNew(B1[c][j], B2[c][j])
				if err := evaluator.Rescale(tmp, cryptoParams.Params.Scale(), tmp); err != nil {
					return err
				}
				evaluator.Sub(target[j], tmp, target[j])
			}
		}
		return nil
	}); err != nil {
		log.Fatalf("diagCrossProductSub: %v", err)
	}
}

// tractorStreamCrossSums streams three ancestry-partitioned genotype blocks in lockstep
// (the row-streaming idiom qualcontrol.go's HWE test uses, gwas/qualcontrol.go:443-465)
// to compute the three raw cross sums MatMult4StreamPlain can't provide (it only ever
// sees one genotype stream at a time): sum(A*X_AMR), sum(A*X_EUR), sum(X_AMR*X_EUR),
// per SNP, over this party's local individuals.
func tractorStreamCrossSums(gfsA, gfsM, gfsE *GenoFileStream, nsnp int) (sumAM, sumAE, sumME []float64) {
	gfsA.Reset()
	gfsM.Reset()
	gfsE.Reset()

	sumAM = make([]float64, nsnp)
	sumAE = make([]float64, nsnp)
	sumME = make([]float64, nsnp)

	for {
		rowA := gfsA.NextRow()
		rowM := gfsM.NextRow()
		rowE := gfsE.NextRow()
		if rowA == nil {
			break
		}
		for j := 0; j < nsnp; j++ {
			a, m, e := float64(rowA[j]), float64(rowM[j]), float64(rowE[j])
			sumAM[j] += a * m
			sumAE[j] += a * e
			sumME[j] += m * e
		}
	}
	return
}

// GetTractorStatsPlainMult computes Tractor-style local-ancestry-aware association
// statistics over the encrypted/secret-shared protocol. It mirrors
// GetAssociationStatsPlainMult's block-processing structure (gwas/assoc.go:1220), tripled
// for the local-ancestry (A), AMR-specific (X_AMR), and EUR-specific (X_EUR) genotype
// streams, reusing covOrtho.applyCTAdditive for the covariate projection unchanged. The
// per-SNP 3x3 Cramer's-rule solve is done in the secret-shared domain (one CVecToSS
// crossing, then local RVec ops + SSMultElemVec + a single Divide for 1/det), mirroring
// qualcontrol.go's HWE chi-square pattern (gwas/qualcontrol.go:440-580) rather than
// piling up ciphertext multiplicative depth.
func (ast *AssocTestPlainMult) GetTractorStatsPlainMult() *TractorRevealed {
	numThreads := ast.general.config.LocalNumThreads

	cryptoParams := ast.general.cps
	slots := cryptoParams.GetSlots()

	mpcPar := ast.general.mpcObj
	mpcObj := mpcPar[0]
	fracBits := mpcObj.GetFracBits()
	rtype := mpcObj.GetRType()
	useBoolean := mpcObj.GetBooleanShareFlag()

	gwasParams := ast.general.gwasParams
	numBlocks := ast.general.config.GenoNumBlocks

	covAllOnes := ast.general.config.CovAllOnes
	pid := mpcObj.GetPid()

	nrowsAll := gwasParams.FiltNumInds()
	nrowsTotal := 0
	for i := 1; i < len(nrowsAll); i++ {
		nrowsTotal += nrowsAll[i]
	}
	nrowsTotalInvSqrt := math.Sqrt(1.0 / float64(nrowsTotal))

	ncov := gwasParams.NumCov() + gwasParams.NumPC()
	npheno := gwasParams.NumPheno()

	Zt := ast.covPc
	Yt := ast.pheno

	// Guarantee Z carries an intercept row, exactly as GetAssociationStatsPlainMult does
	// (gwas/assoc.go:1257-1279). After this block covAllOnes is unconditionally true, so
	// (unlike the single-variant path) no separate sx/sy correction is needed anywhere
	// below: s11..s23/bA/bM/bE/sy are already fully residualized raw-minus-projection
	// quantities, matching TractorStatsPlain's plaintext math in gwas/tractor.go.
	if !covAllOnes {
		_, cols := Zt.Dims()
		ones := mat.NewDense(1, cols, nil)
		if pid > 0 {
			for i := 0; i < cols; i++ {
				ones.Set(0, i, nrowsTotalInvSqrt)
			}
		}
		covWithIntercept := mat.NewDense(ncov+1, cols, nil)
		covWithIntercept.Stack(ones, Zt)
		Zt = covWithIntercept
		ncov++
	} else {
		log.LLvl1("Warning: assumes the first covariate is all ones (if not, reorder input)")
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: covariate count", ncov, "phenotype count", npheno)

	/* Covariate orthogonalization factor S, SᵀS=(ZtZ)^-1 -- identical to the single-variant path */

	var tmp mat.SymDense
	tmp.SymOuterK(nrowsTotalInvSqrt, Zt)
	ZtZss := mpc.DenseToRMat(rtype, &tmp, fracBits)
	tmp.Reset()

	scaling := rtype.FromFloat64(math.Sqrt(math.Sqrt(float64(nrowsTotal))), fracBits)
	covOrtho := ast.computeCovOrthoFactor(cryptoParams, ZtZss, scaling, nil, numThreads)
	ZtZss = nil

	/* YtQ = Qᵀ Y (once, genotype-independent) */

	var YtQ crypto.CipherMatrix
	var OnetQ crypto.CipherVector
	if pid > 0 {
		Yt1 := mat.NewDense(npheno+1, nrowsAll[pid], nil)
		_, cols := Yt.Dims()
		ones := mat.NewDense(1, cols, nil)
		for i := 0; i < cols; i++ {
			ones.Set(0, i, 1)
		}
		Yt1.Stack(Yt, ones)

		var ZtY1 mat.Dense
		ZtY1.Mul(Zt, Yt1.T())
		ZtY1.Scale(nrowsTotalInvSqrt, &ZtY1)
		ZtY1ss := mpc.DenseToRMat(rtype, &ZtY1, fracBits)
		QtY1ss := covOrtho.applySS(ZtY1ss)

		YtQss := mpc_core.InitRMat(rtype.Zero(), npheno, ncov)
		OnetQss := mpc_core.InitRVec(rtype.Zero(), ncov)
		for i := 0; i < ncov; i++ {
			for j := 0; j < npheno; j++ {
				YtQss[j][i] = QtY1ss[i][j].Copy()
			}
			OnetQss[i] = QtY1ss[i][npheno].Copy()
		}
		OnetQ = mpcObj.SSToCVec(cryptoParams, OnetQss)
		YtQ = mpcObj.SSToCMat(cryptoParams, YtQss)
	} else {
		ZtY1ss := mpc_core.InitRMat(rtype.Zero(), ncov, npheno+1)
		QtY1ss := covOrtho.applySS(ZtY1ss)
		_ = QtY1ss
		OnetQss := mpc_core.InitRVec(rtype.Zero(), ncov)
		YtQss := mpc_core.InitRMat(rtype.Zero(), npheno, ncov)
		OnetQ = mpcObj.SSToCVec(cryptoParams, OnetQss)
		YtQ = mpcObj.SSToCMat(cryptoParams, YtQss)
	}
	_ = OnetQ // unused: covAllOnes guaranteed true above, no sy correction needed

	/* Per-block accumulation */

	var s11, s22, s33, s12, s13, s23 crypto.CipherVector
	var bA, bM, bE crypto.CipherMatrix
	var sumA, sumM, sumE crypto.CipherVector
	var nsnps, numCtx int
	var outFilter []bool

	if pid > 0 {
		s11Blocks := make([]crypto.CipherMatrix, numBlocks)
		s22Blocks := make([]crypto.CipherMatrix, numBlocks)
		s33Blocks := make([]crypto.CipherMatrix, numBlocks)
		s12Blocks := make([]crypto.CipherMatrix, numBlocks)
		s13Blocks := make([]crypto.CipherMatrix, numBlocks)
		s23Blocks := make([]crypto.CipherMatrix, numBlocks)
		bABlocks := make([]crypto.CipherMatrix, numBlocks)
		bMBlocks := make([]crypto.CipherMatrix, numBlocks)
		bEBlocks := make([]crypto.CipherMatrix, numBlocks)
		sumABlocks := make([]crypto.CipherMatrix, numBlocks)
		sumMBlocks := make([]crypto.CipherMatrix, numBlocks)
		sumEBlocks := make([]crypto.CipherMatrix, numBlocks)
		filtOut := make([][]bool, numBlocks)

		matIn := mat.NewDense(ncov+npheno, nrowsAll[pid], nil)
		matIn.Stack(Zt, Yt)

		for b := 0; b < numBlocks; b++ {
			if !ast.general.IsBlockForAssocTest(b) {
				log.LLvl1(time.Now().Format(time.RFC3339), "Tractor MatMult: block", b+1, "/", numBlocks, "skipped")
				continue
			}

			gfsA := ast.general.genoBlocksA[b]
			gfsM := ast.general.genoBlocksAMR[b]
			gfsE := ast.general.genoBlocksEUR[b]

			nsnpBlock := int(gfsA.NumColsToKeep())
			if nsnpBlock == 0 {
				continue
			}

			matOutA, sA, sqA := MatMult4StreamPlain(matIn, gfsA, true, 0)
			matOutM, sM, sqM := MatMult4StreamPlain(matIn, gfsM, true, 0)
			matOutE, sE, sqE := MatMult4StreamPlain(matIn, gfsE, true, 0)
			crossAM, crossAE, crossME := tractorStreamCrossSums(gfsA, gfsM, gfsE, nsnpBlock)

			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "local products computed")

			for i := 0; i < ncov; i++ {
				for j := range matOutA[i] {
					matOutA[i][j] *= nrowsTotalInvSqrt
					matOutM[i][j] *= nrowsTotalInvSqrt
					matOutE[i][j] *= nrowsTotalInvSqrt
				}
			}

			matOutAEnc, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, matOutA)
			matOutAEnc = mpcObj.Network.AggregateCMat(cryptoParams, matOutAEnc)
			matOutMEnc, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, matOutM)
			matOutMEnc = mpcObj.Network.AggregateCMat(cryptoParams, matOutMEnc)
			matOutEEnc, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, matOutE)
			matOutEEnc = mpcObj.Network.AggregateCMat(cryptoParams, matOutEEnc)

			numCtx = len(matOutAEnc[0])

			YtA := matOutAEnc[ncov:]
			YtM := matOutMEnc[ncov:]
			YtE := matOutEEnc[ncov:]

			OnetA, _ := crypto.EncryptFloatVector(cryptoParams, sA)
			OnetA = mpcObj.Network.AggregateCVec(cryptoParams, OnetA)
			OnetM, _ := crypto.EncryptFloatVector(cryptoParams, sM)
			OnetM = mpcObj.Network.AggregateCVec(cryptoParams, OnetM)
			OnetE, _ := crypto.EncryptFloatVector(cryptoParams, sE)
			OnetE = mpcObj.Network.AggregateCVec(cryptoParams, OnetE)

			OnetAsq, _ := crypto.EncryptFloatVector(cryptoParams, sqA)
			OnetAsq = mpcObj.Network.AggregateCVec(cryptoParams, OnetAsq)
			OnetMsq, _ := crypto.EncryptFloatVector(cryptoParams, sqM)
			OnetMsq = mpcObj.Network.AggregateCVec(cryptoParams, OnetMsq)
			OnetEsq, _ := crypto.EncryptFloatVector(cryptoParams, sqE)
			OnetEsq = mpcObj.Network.AggregateCVec(cryptoParams, OnetEsq)

			OnetAM, _ := crypto.EncryptFloatVector(cryptoParams, crossAM)
			OnetAM = mpcObj.Network.AggregateCVec(cryptoParams, OnetAM)
			OnetAE, _ := crypto.EncryptFloatVector(cryptoParams, crossAE)
			OnetAE = mpcObj.Network.AggregateCVec(cryptoParams, OnetAE)
			OnetME, _ := crypto.EncryptFloatVector(cryptoParams, crossME)
			OnetME = mpcObj.Network.AggregateCVec(cryptoParams, OnetME)

			// Project each genotype stream through covariates: B = QᵀX
			BA := covOrtho.applyCTAdditive(matOutA)
			BM := covOrtho.applyCTAdditive(matOutM)
			BE := covOrtho.applyCTAdditive(matOutE)

			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "computed B_A, B_M, B_E")

			s11b := crypto.CopyEncryptedVector(OnetAsq)
			s22b := crypto.CopyEncryptedVector(OnetMsq)
			s33b := crypto.CopyEncryptedVector(OnetEsq)
			s12b := crypto.CopyEncryptedVector(OnetAM)
			s13b := crypto.CopyEncryptedVector(OnetAE)
			s23b := crypto.CopyEncryptedVector(OnetME)

			diagCrossProductSub(cryptoParams, s11b, BA, BA)
			diagCrossProductSub(cryptoParams, s22b, BM, BM)
			diagCrossProductSub(cryptoParams, s33b, BE, BE)
			diagCrossProductSub(cryptoParams, s12b, BA, BM)
			diagCrossProductSub(cryptoParams, s13b, BA, BE)
			diagCrossProductSub(cryptoParams, s23b, BM, BE)

			s11Blocks[b] = crypto.CipherMatrix{s11b}
			s22Blocks[b] = crypto.CipherMatrix{s22b}
			s33Blocks[b] = crypto.CipherMatrix{s33b}
			s12Blocks[b] = crypto.CipherMatrix{s12b}
			s13Blocks[b] = crypto.CipherMatrix{s13b}
			s23Blocks[b] = crypto.CipherMatrix{s23b}
			sumABlocks[b] = crypto.CipherMatrix{OnetA}
			sumMBlocks[b] = crypto.CipherMatrix{OnetM}
			sumEBlocks[b] = crypto.CipherMatrix{OnetE}

			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "computed s11..s23")

			bABlocks[b] = make(crypto.CipherMatrix, npheno)
			bMBlocks[b] = make(crypto.CipherMatrix, npheno)
			bEBlocks[b] = make(crypto.CipherMatrix, npheno)
			tmpA := CMultMatRowTimesRow(cryptoParams, YtQ, BA, numThreads)
			tmpM := CMultMatRowTimesRow(cryptoParams, YtQ, BM, numThreads)
			tmpE := CMultMatRowTimesRow(cryptoParams, YtQ, BE, numThreads)
			for i := 0; i < npheno; i++ {
				bABlocks[b][i] = crypto.CSub(cryptoParams, YtA[i], tmpA[i])
				bMBlocks[b][i] = crypto.CSub(cryptoParams, YtM[i], tmpM[i])
				bEBlocks[b][i] = crypto.CSub(cryptoParams, YtE[i], tmpE[i])
			}

			log.LLvl1(time.Now().Format(time.RFC3339), "Tractor: block", b+1, "/", numBlocks, "computed bA, bM, bE")

			filtOut[b] = make([]bool, numCtx*slots)
			for i := range filtOut[b] {
				filtOut[b][i] = i < nsnpBlock
			}
		}

		s11 = crypto.ConcatCipherMatrix(s11Blocks)[0]
		s22 = crypto.ConcatCipherMatrix(s22Blocks)[0]
		s33 = crypto.ConcatCipherMatrix(s33Blocks)[0]
		s12 = crypto.ConcatCipherMatrix(s12Blocks)[0]
		s13 = crypto.ConcatCipherMatrix(s13Blocks)[0]
		s23 = crypto.ConcatCipherMatrix(s23Blocks)[0]
		sumA = crypto.ConcatCipherMatrix(sumABlocks)[0]
		sumM = crypto.ConcatCipherMatrix(sumMBlocks)[0]
		sumE = crypto.ConcatCipherMatrix(sumEBlocks)[0]

		bA = crypto.ConcatCipherMatrix(bABlocks)
		bM = crypto.ConcatCipherMatrix(bMBlocks)
		bE = crypto.ConcatCipherMatrix(bEBlocks)

		totLen := 0
		for i := range filtOut {
			totLen += len(filtOut[i])
		}
		outFilter = make([]bool, totLen)
		shift := 0
		for i := range filtOut {
			copy(outFilter[shift:], filtOut[i])
			shift += len(filtOut[i])
		}

		numCtx = len(s11)
		nsnps = SumBool(outFilter)

		if pid == mpcObj.GetHubPid() {
			mpcObj.Network.SendInt(numCtx, 0)
			mpcObj.Network.SendInt(nsnps, 0)
		}
	} else {
		numCtx = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())
		nsnps = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())

		s11 = crypto.CZeros(cryptoParams, numCtx)
		s22 = crypto.CZeros(cryptoParams, numCtx)
		s33 = crypto.CZeros(cryptoParams, numCtx)
		s12 = crypto.CZeros(cryptoParams, numCtx)
		s13 = crypto.CZeros(cryptoParams, numCtx)
		s23 = crypto.CZeros(cryptoParams, numCtx)
		sumA = crypto.CZeros(cryptoParams, numCtx)
		sumM = crypto.CZeros(cryptoParams, numCtx)
		sumE = crypto.CZeros(cryptoParams, numCtx)

		bA = make(crypto.CipherMatrix, npheno)
		bM = make(crypto.CipherMatrix, npheno)
		bE = make(crypto.CipherMatrix, npheno)
		for i := 0; i < npheno; i++ {
			bA[i] = crypto.CZeros(cryptoParams, numCtx)
			bM[i] = crypto.CZeros(cryptoParams, numCtx)
			bE[i] = crypto.CZeros(cryptoParams, numCtx)
		}
	}

	mpcObj.AssertSync()

	/* sy: genotype-independent, computed once */

	sy := make(crypto.CipherMatrix, npheno)
	if pid > 0 {
		buffer := make([]float64, slots)
		for i := 0; i < npheno; i++ {
			var ysq float64
			for _, v := range Yt.RawRowView(i) {
				ysq += v * v
			}
			for j := range buffer {
				buffer[j] = ysq
			}
			YtYloc, _ := crypto.EncryptFloatVector(cryptoParams, buffer)
			YtY := mpcObj.Network.AggregateCVec(cryptoParams, YtYloc)
			ct := crypto.InnerProd(cryptoParams, YtQ[i], YtQ[i])
			sy[i] = crypto.CSub(cryptoParams, YtY, crypto.CipherVector{ct})
		}
	} else {
		for i := 0; i < npheno; i++ {
			sy[i] = crypto.CZeros(cryptoParams, 1)
		}
	}

	/* Cross to the secret-shared domain */

	s11ss := mpcObj.CVecToSS(cryptoParams, rtype, s11, -1, len(s11), slots*len(s11))
	s22ss := mpcObj.CVecToSS(cryptoParams, rtype, s22, -1, len(s22), slots*len(s22))
	s33ss := mpcObj.CVecToSS(cryptoParams, rtype, s33, -1, len(s33), slots*len(s33))
	s12ss := mpcObj.CVecToSS(cryptoParams, rtype, s12, -1, len(s12), slots*len(s12))
	s13ss := mpcObj.CVecToSS(cryptoParams, rtype, s13, -1, len(s13), slots*len(s13))
	s23ss := mpcObj.CVecToSS(cryptoParams, rtype, s23, -1, len(s23), slots*len(s23))

	bAss := make([]mpc_core.RVec, npheno)
	bMss := make([]mpc_core.RVec, npheno)
	bEss := make([]mpc_core.RVec, npheno)
	syss := make([]mpc_core.RVec, npheno)
	for i := 0; i < npheno; i++ {
		bAss[i] = mpcObj.CVecToSS(cryptoParams, rtype, bA[i], -1, len(bA[i]), slots*len(bA[i]))
		bMss[i] = mpcObj.CVecToSS(cryptoParams, rtype, bM[i], -1, len(bM[i]), slots*len(bM[i]))
		bEss[i] = mpcObj.CVecToSS(cryptoParams, rtype, bE[i], -1, len(bE[i]), slots*len(bE[i]))
		syss[i] = mpcObj.CiphertextToSS(cryptoParams, rtype, sy[i][0], -1, 1)
	}

	/* Cofactors, determinant, 1/det -- local RVec ops + SSMultElemVec + one Divide,
	   mirroring qualcontrol.go's HWE chi-square pattern (gwas/qualcontrol.go:440-580) */

	dataBits := mpcObj.GetDataBits()

	// s11..s23/bA/bM/bE are fracBits-scaled fixed-point reals (unlike qualcontrol.go's
	// HWE test, which multiplies raw integer genotype counts and so never needs this): a
	// product of two fracBits-scaled values is scaled by fracBits*2, so every
	// SSMultElemVec product here must be truncated back down to fracBits, exactly as
	// qrfact.go and mpc.go's own Divide/SqrtAndSqrtInverse do after each of their
	// SSMultElemVec calls (e.g. mpc/mpc.go:2130-2131, gwas/qrfact.go:136-137). Skipping
	// this is what produced ~1e67-magnitude garbage on the first live run.
	sq := func(v mpc_core.RVec) mpc_core.RVec {
		return mpcObj.TruncVec(mpcPar.SSMultElemVec(v, v), dataBits, fracBits)
	}
	mul := func(a, b mpc_core.RVec) mpc_core.RVec {
		return mpcObj.TruncVec(mpcPar.SSMultElemVec(a, b), dataBits, fracBits)
	}
	subv := func(a, b mpc_core.RVec) mpc_core.RVec {
		out := a.Copy()
		out.Sub(b)
		return out
	}
	addv := func(a, b mpc_core.RVec) mpc_core.RVec {
		out := a.Copy()
		out.Add(b)
		return out
	}

	c11 := subv(mul(s22ss, s33ss), sq(s23ss))
	c22 := subv(mul(s11ss, s33ss), sq(s13ss))
	c33 := subv(mul(s11ss, s22ss), sq(s12ss))
	c12 := subv(mul(s13ss, s23ss), mul(s12ss, s33ss))
	c13 := subv(mul(s12ss, s23ss), mul(s13ss, s22ss))
	c23 := subv(mul(s12ss, s13ss), mul(s11ss, s23ss))

	det := addv(addv(mul(s11ss, c11), mul(s12ss, c12)), mul(s13ss, c13))

	// A valid n-party additive share of the public constant 1.0, at the same fracBits
	// scale as det (rtype.One() is the unscaled ring identity -- literally the integer 1,
	// not 2^fracBits -- so it would represent 2^-fracBits here, not 1.0; FromFloat64 is
	// the scale-aware constructor, matching Divide's own internal polynomial constants,
	// e.g. mpc/mpc.go:2143-2145 `scaledEst.AddScalar(rtype.FromFloat64(5.9430, nBitsF))`).
	// Exactly one party (pid==1) embeds it, everyone else contributes 0 -- the same idiom
	// used there. InitRVec(FromFloat64(1,...), n) on every party would be wrong too: it
	// would sum to NumMainParties, not 1.
	ones := mpc_core.InitRVec(rtype.Zero(), len(det))
	if pid == 1 {
		ones.AddScalar(rtype.FromFloat64(1.0, fracBits))
	}
	invDet := mpcPar.Divide(ones, det, useBoolean)

	inv11 := mul(c11, invDet)
	inv22 := mul(c22, invDet)
	inv33 := mul(c33, invDet)

	betaA := make([]mpc_core.RVec, npheno)
	betaM := make([]mpc_core.RVec, npheno)
	betaE := make([]mpc_core.RVec, npheno)
	sigma2 := make([]mpc_core.RVec, npheno)

	df := nrowsTotal - ncov - 3
	for k := 0; k < npheno; k++ {
		numA := addv(addv(mul(c11, bAss[k]), mul(c12, bMss[k])), mul(c13, bEss[k]))
		numM := addv(addv(mul(c12, bAss[k]), mul(c22, bMss[k])), mul(c23, bEss[k]))
		numE := addv(addv(mul(c13, bAss[k]), mul(c23, bMss[k])), mul(c33, bEss[k]))

		betaA[k] = mul(numA, invDet)
		betaM[k] = mul(numM, invDet)
		betaE[k] = mul(numE, invDet)

		// Replicate the (already-valid, for every party including pid 0) share of the
		// scalar sy[k] across all nsnp positions. Unlike `ones` above this is not a fresh
		// public constant -- it's copying whatever share each party already legitimately
		// holds from CiphertextToSS, so -- unlike `ones` -- every party (including pid 0)
		// must copy its own share, not just pid 1.
		syBroadcast := make(mpc_core.RVec, len(det))
		for i := range syBroadcast {
			syBroadcast[i] = syss[k][0].Copy()
		}
		rss := subv(subv(subv(syBroadcast, mul(betaA[k], bAss[k])), mul(betaM[k], bMss[k])), mul(betaE[k], bEss[k]))

		sigma2[k] = rss.Copy()
		sigma2[k].MulScalar(rtype.FromFloat64(1.0/float64(df), fracBits))
		sigma2[k] = mpcObj.TruncVec(sigma2[k], dataBits, fracBits)
	}

	/* Reveal */

	detR := mpcPar.RevealSymVec(det).ToFloat(fracBits)[:nsnps]
	inv11R := mpcPar.RevealSymVec(inv11).ToFloat(fracBits)[:nsnps]
	inv22R := mpcPar.RevealSymVec(inv22).ToFloat(fracBits)[:nsnps]
	inv33R := mpcPar.RevealSymVec(inv33).ToFloat(fracBits)[:nsnps]

	betaAR := make([][]float64, npheno)
	betaMR := make([][]float64, npheno)
	betaER := make([][]float64, npheno)
	sigma2R := make([][]float64, npheno)
	for k := 0; k < npheno; k++ {
		betaAR[k] = mpcPar.RevealSymVec(betaA[k]).ToFloat(fracBits)[:nsnps]
		betaMR[k] = mpcPar.RevealSymVec(betaM[k]).ToFloat(fracBits)[:nsnps]
		betaER[k] = mpcPar.RevealSymVec(betaE[k]).ToFloat(fracBits)[:nsnps]
		sigma2R[k] = mpcPar.RevealSymVec(sigma2[k]).ToFloat(fracBits)[:nsnps]
	}

	var sumAR, sumMR, sumER []float64
	if pid > 0 {
		sumADec := mpcObj.Network.CollectiveDecryptVec(cryptoParams, sumA, -1)
		sumMDec := mpcObj.Network.CollectiveDecryptVec(cryptoParams, sumM, -1)
		sumEDec := mpcObj.Network.CollectiveDecryptVec(cryptoParams, sumE, -1)
		sumAR = crypto.DecodeFloatVector(cryptoParams, sumADec)[:nsnps]
		sumMR = crypto.DecodeFloatVector(cryptoParams, sumMDec)[:nsnps]
		sumER = crypto.DecodeFloatVector(cryptoParams, sumEDec)[:nsnps]
	}

	return &TractorRevealed{
		NTot:   nrowsTotal,
		DF:     df,
		Det:    detR,
		Inv11:  inv11R,
		Inv22:  inv22R,
		Inv33:  inv33R,
		BetaA:  betaAR,
		BetaAMR: betaMR,
		BetaEUR: betaER,
		Sigma2: sigma2R,
		SumA:   sumAR,
		SumAMR: sumMR,
		SumEUR: sumER,
	}
}
