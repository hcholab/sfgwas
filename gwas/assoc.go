package gwas

import (
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	mpc_core "github.com/hhcho/mpc-core"
	"github.com/ldsec/lattigo/v2/ckks"
	"go.dedis.ch/onet/v3/log"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/hcholab/sfgwas/mpc"

	"gonum.org/v1/gonum/floats"
	"gonum.org/v1/gonum/mat"
)

type AssocTest struct {
	general *ProtocolInfo

	pheno    crypto.PlainMatrix
	inputCov crypto.PlainMatrix
	Qpc      crypto.CipherMatrix
}

type AssocTestPlainMult struct {
	general *ProtocolInfo

	pheno *mat.Dense
	covPc *mat.Dense
}

func (g *ProtocolInfo) InitAssociationTests(Qpc crypto.CipherMatrix) *AssocTest {

	pid := g.mpcObj[0].GetPid()
	gwasParams := g.gwasParams
	cps := g.cps

	var phenoEnc crypto.PlainMatrix
	var covEnc crypto.PlainMatrix

	if pid > 0 {
		phenoEnc = crypto.EncodeDense(cps, mat.DenseCopyOf(g.pheno))
		covEnc = crypto.EncodeDense(cps, mat.DenseCopyOf(g.cov))
		_, npheno := g.pheno.Dims()
		r, c := g.cov.Dims()
		log.LLvl1(time.Now().Format(time.RFC3339), "Pheno cols:", npheno)
		log.LLvl1(time.Now().Format(time.RFC3339), "Cov dims:", r, c)
	} else {
		phenoEnc = make(crypto.PlainMatrix, 0) // multiPhenoSize communicated at runtime
		covEnc = make(crypto.PlainMatrix, gwasParams.NumCov())
		log.LLvl1(time.Now().Format(time.RFC3339), "Cov dims:", 0, gwasParams.NumCov())
	}

	return &AssocTest{
		general:  g,
		pheno:    phenoEnc,
		inputCov: covEnc,
		Qpc:      Qpc,
	}
}

func (g *ProtocolInfo) InitAssociationTestsPlainMult(QpcPlain *mat.Dense) *AssocTestPlainMult {

	mpcObj := g.mpcObj[0]
	pid := mpcObj.GetPid()
	gwasParams := g.gwasParams
	npc := gwasParams.numPCs
	ncov := gwasParams.numCovs

	// The phenotype count is derived from the input file rather than the config, so that
	// no new config key is required. Party 0 holds no data, so the hub tells it the count;
	// every party needs it before the first secret-shared multiplication.
	var npheno int
	if pid > 0 {
		_, npheno = g.pheno.Dims() // g.pheno is nsample-by-npheno as loaded
		if g.config.NumPheno > 0 && g.config.NumPheno != npheno {
			log.Fatalf("num_pheno=%d in config, but %s has %d phenotypes", g.config.NumPheno, g.config.PhenoFile, npheno)
		}
		if pid == mpcObj.GetHubPid() {
			mpcObj.Network.SendInt(npheno, 0)
		}
	} else {
		npheno = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())
	}
	gwasParams.SetNumPheno(npheno)

	if pid > 0 && QpcPlain == nil {
		log.Fatal("Plaintext Qpca has not been provided")
	}

	var phenoPlain *mat.Dense
	var covPcPlain *mat.Dense

	if pid > 0 {
		// Row-major representation: rows correspond to phenotypes/covariates, columns correspond to individuals
		// These matrices will never be encoded as plain/ciphertexts in this version
		phenoPlain = mat.DenseCopyOf(g.pheno.T()) // Rows correspond to phenotypes
		covPlain := mat.DenseCopyOf(g.cov.T())    // Rows correspond to covariates

		nsample := gwasParams.numFiltInds[pid]

		_, phenoCols := phenoPlain.Dims()
		covRows, covCols := covPlain.Dims()
		qpcRows, qpcCols := QpcPlain.Dims()

		if covRows != ncov {
			log.Fatalf("covPlain has %d rows; expected ncov=%d", covRows, ncov)
		}

		if qpcRows != npc {
			log.Fatalf("QpcPlain has %d rows; expected npc=%d", qpcRows, npc)
		}

		if qpcCols != nsample || covCols != nsample || phenoCols != nsample {
			log.Fatalf("Inconsistent local sample count (expected %d; Qpc %d, cov %d, pheno %d)", nsample, qpcCols, covCols, phenoCols)
		}

		covPcPlain = mat.NewDense(ncov+npc, nsample, nil)
		covPcPlain.Stack(covPlain, QpcPlain)

	} else {
		phenoPlain = mat.NewDense(npheno, 1, nil)
		covPcPlain = mat.NewDense(ncov+npc, 1, nil)
	}

	return &AssocTestPlainMult{
		general: g,
		pheno:   phenoPlain,
		covPc:   covPcPlain,
	}
}

// Orthogonal basis of covariates and PCs combined; joint QR
func (ast *AssocTest) computeCombinedQV2(C crypto.PlainMatrix, Qpc crypto.CipherMatrix) crypto.CipherMatrix {
	cryptoParams := ast.general.cps
	mpcPar := ast.general.mpcObj
	mpcObj := mpcPar[0]
	pid := mpcPar[0].GetPid()
	slots := cryptoParams.GetSlots()

	gwasParams := ast.general.gwasParams
	nrowsAll := gwasParams.FiltNumInds()
	nrowsTotal := 0
	for i := 1; i < len(nrowsAll); i++ {
		nrowsTotal += nrowsAll[i]
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Starting QR Factorization")
	log.LLvl1(time.Now().Format(time.RFC3339), "Starting QR: C numCols", len(C))

	CEnc := crypto.EncryptPlaintextMatrix(cryptoParams, C)

	comb := make(crypto.CipherMatrix, len(C)+len(Qpc))
	copy(comb, CEnc)
	for i := range Qpc {
		comb[len(CEnc)+i] = Qpc[i]
	}

	start := time.Now()

	Qcomb := NetDQRenc(cryptoParams, mpcObj, comb, nrowsAll)

	log.LLvl1(time.Now().Format(time.RFC3339), "Covariate joint QR time: ", time.Since(start))
	log.LLvl1(time.Now().Format(time.RFC3339), "Qcomb dimensions: r,c :", len(Qcomb[0]), len(Qcomb))

	Qcomb = mpcObj.Network.BootstrapMatAll(cryptoParams, Qcomb)

	log.LLvl1(time.Now().Format(time.RFC3339), "Qcomb replacing first vector with an all-ones vector (normalized)")
	if pid > 0 {
		ct := crypto.CZeros(cryptoParams, 1)[0]
		ct = crypto.AddConst(cryptoParams, ct, 1.0)

		QFirst := make(crypto.CipherVector, ((nrowsAll[pid]-1)/slots)+1)
		for i := range QFirst {
			nElem := slots
			if i == len(QFirst)-1 {
				nElem = nrowsAll[pid] - (len(QFirst)-1)*slots
			}
			QFirst[i] = crypto.MaskTrunc(cryptoParams, ct, nElem)
		}

		Qcomb[0] = QFirst
		Qcomb, _ = crypto.FlattenLevels(cryptoParams, Qcomb)
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "AssertSync")
	mpcObj.AssertSync()

	return Qcomb
}

func (ast *AssocTestPlainMult) GenoBlockMultPlain(b int, mat *mat.Dense) (matOut [][]float64, dosageSum, dosageSqSum []float64, filtOut []bool) {

	pid := ast.general.mpcObj[0].GetPid()
	isPgen := ast.general.IsPgen()
	pgenBatchSize := ast.general.config.PgenBatchSize

	XBlock := ast.general.genoBlocks[b]
	numBlocks := ast.general.config.GenoNumBlocks

	gwasParams := ast.general.gwasParams
	snpFilt := gwasParams.snpFilt

	blockSize := ast.general.genoBlockSizes[b]

	shift := uint64(0)
	for i := 0; i < b; i++ {
		shift += uint64(ast.general.genoBlockSizes[i])
	}

	var nsnps int
	if isPgen {
		if snpFilt == nil { // no QC
			nsnps = blockSize
		} else {
			nsnps = SumBool(snpFilt[shift : shift+uint64(blockSize)])
		}
	} else {
		nsnps = int(XBlock.NumColsToKeep())
	}

	if nsnps == 0 { // empty block
		log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "skipped (empty)")
		return
	}

	// Distinct from the assoc_cache_* files written by GenoBlockMult: the contents
	// (plaintext floats vs. serialized ciphertexts) and the vector lengths (nsnps vs.
	// numCtx*slots) differ, so the two paths must not share a cache.
	multFile := ast.general.CachePath(fmt.Sprintf("assoc_cache_plain_mult.%d.txt", b))
	dosFile := ast.general.CachePath(fmt.Sprintf("assoc_cache_plain_dos_sum.%d.txt", b))
	dos2File := ast.general.CachePath(fmt.Sprintf("assoc_cache_plain_dos_sqsum.%d.txt", b))
	filtFile := ast.general.CachePath(fmt.Sprintf("assoc_cache_plain_filt.%d.txt", b))

	if fileExists(multFile) && fileExists(dosFile) && fileExists(dos2File) && fileExists(filtFile) {

		log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "cache found")

		matOut = LoadMatrixFromFileFloat(multFile, ',')
		dosageSum = LoadFloatVectorFromFile(dosFile, nsnps)
		dosageSqSum = LoadFloatVectorFromFile(dos2File, nsnps)
		filtOut = readFilterFromFile(filtFile, nsnps, true)

		nrowsExp, _ := mat.Dims()
		if len(matOut) != nrowsExp || len(matOut[0]) != nsnps {
			ncolsGot := 0
			if len(matOut) > 0 {
				ncolsGot = len(matOut[0])
			}
			log.Fatalf("stale cache %s: got %d-by-%d, expected %d-by-%d",
				multFile, len(matOut), ncolsGot, nrowsExp, nsnps)
		}

		log.LLvl1("Dosage Sum:", dosageSum[:Min(5, nsnps)])
		log.LLvl1("Dosage SqSum:", dosageSqSum[:Min(5, nsnps)])

	} else {

		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: MatMult: block", b+1, "/", numBlocks, "starting")

		filtOut = make([]bool, nsnps)
		for i := range filtOut {
			filtOut[i] = true
		}

		start := time.Now()
		if isPgen {

			numInd := gwasParams.numFiltInds[pid]
			snpFilt := gwasParams.snpFilt[shift : shift+uint64(blockSize)]

			pgenFile := fmt.Sprintf(ast.general.config.GenoFilePrefix, b+1) // Geno file for chromosome b+1

			startIndex := 0
			counter := 0
			outShift := 0
			batchIndex := 0

			dimsOut, _ := mat.Dims()

			nbatch := 1 + (nsnps-1)/pgenBatchSize

			matOut = make([][]float64, dimsOut)
			for i := range matOut {
				matOut[i] = make([]float64, nsnps)
			}
			dosageSum = make([]float64, nsnps)
			dosageSqSum = make([]float64, nsnps)

			nblocksParallel := ast.general.config.LocalAssocNumBlocksParallel
			nprocsPerBlock := Max(1, runtime.GOMAXPROCS(0)/nblocksParallel)

			// Dispatcher
			threadPool := make(chan int, nblocksParallel)
			for i := 0; i < nblocksParallel; i++ {
				threadPool <- i
			}

			var wg sync.WaitGroup

			for idx := 0; idx < blockSize; idx++ {
				if snpFilt[idx] {
					counter++
				}

				if counter == pgenBatchSize || (idx == blockSize-1 && counter > 0) {
					// Fetch an available thread
					threadId := <-threadPool
					wg.Add(1)

					go func(threadId, batchIndex, startIndex, idx, counter, shift, outShift int) {
						defer wg.Done()

						start := time.Now()
						log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("MatMult: block %d/%d, batch %d/%d, thread %d started", b+1, numBlocks, batchIndex+1, nbatch, threadId))

						batchFilt := snpFilt[startIndex : idx+1]
						gfsTempFile := ast.general.CachePath(fmt.Sprintf("pgen_gfs.%d.tmp", threadId))

						FilterMatrixFilePgen(pgenFile, numInd, counter, ast.general.config.SampleKeepFile, ast.general.config.SnpIdsFile, shift+startIndex, batchFilt, gfsTempFile, nprocsPerBlock)

						X := NewGenoFileStream(gfsTempFile, uint64(numInd), uint64(counter), true)

						mult, sum, sqSum := MatMult4StreamPlain(mat, X, true, nprocsPerBlock)

						for r := 0; r < len(matOut); r++ {
							copy(matOut[r][outShift:outShift+counter], mult[r])
						}
						copy(dosageSum[outShift:outShift+counter], sum)
						copy(dosageSqSum[outShift:outShift+counter], sqSum)

						log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("MatMult: block %d/%d, batch %d/%d, thread %d finished,", b+1, numBlocks, batchIndex+1, nbatch, threadId), "elapsed time", time.Since(start))

						// Return thread to pool
						threadPool <- threadId
					}(threadId, batchIndex, startIndex, idx, counter, int(shift), outShift)

					outShift += counter
					startIndex = idx + 1
					batchIndex++
					counter = 0
				}
			}

			wg.Wait() // Wait until all batches are finished
			close(threadPool)

		} else {
			matOut, dosageSum, dosageSqSum = MatMult4StreamPlain(mat, XBlock, true, 0)
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "elapsed time", time.Since(start))

		// Save cache
		SaveFloatMatrixToFileRowMajor(multFile, matOut)
		SaveFloatVectorToFile(dosFile, dosageSum)
		SaveFloatVectorToFile(dos2File, dosageSqSum)
		writeFilterToFile(filtFile, filtOut, true)
	}

	return
}

func (ast *AssocTest) GenoBlockMult(b int, mat crypto.CipherMatrix) (matOut crypto.CipherMatrix, dosageSum, dosageSqSum []float64, filtOut []bool) {
	cryptoParams := ast.general.cps

	pid := ast.general.mpcObj[0].GetPid()

	slots := cryptoParams.GetSlots()
	isPgen := ast.general.IsPgen()
	pgenBatchSize := ast.general.config.PgenBatchSize

	XBlock := ast.general.genoBlocks[b]
	numBlocks := ast.general.config.GenoNumBlocks

	gwasParams := ast.general.gwasParams
	snpFilt := gwasParams.snpFilt

	blockSize := ast.general.genoBlockSizes[b]

	shift := uint64(0)
	for i := 0; i < b; i++ {
		shift += uint64(ast.general.genoBlockSizes[i])
	}

	var nsnps int
	if isPgen {
		if snpFilt == nil { // no QC
			nsnps = blockSize
		} else {
			nsnps = SumBool(snpFilt[shift : shift+uint64(blockSize)])
		}
	} else {
		nsnps = int(XBlock.NumColsToKeep())
	}

	if nsnps == 0 { // empty block
		log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "skipped (empty)")
		return
	}

	numCtx := 0
	if isPgen {
		for nleft := nsnps; nleft > 0; {
			bsize := Min(nleft, pgenBatchSize)
			numCtx += 1 + (bsize-1)/slots
			nleft -= bsize
		}
	} else {
		numCtx = 1 + (nsnps-1)/slots
	}

	multFile := ast.general.CachePath(fmt.Sprintf("assoc_cache_mult.%d.bin", b))
	dosFile := ast.general.CachePath(fmt.Sprintf("assoc_cache_dos_sum.%d.txt", b))
	dos2File := ast.general.CachePath(fmt.Sprintf("assoc_cache_dos_sqsum.%d.txt", b))
	filtFile := ast.general.CachePath(fmt.Sprintf("assoc_cache_filt.%d.txt", b))

	if fileExists(multFile) && fileExists(dosFile) && fileExists(dos2File) && fileExists(filtFile) {

		log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "cache found")

		matOut = crypto.LoadCipherMatrixFromFile(cryptoParams, multFile)
		dosageSum = LoadFloatVectorFromFile(dosFile, numCtx*slots)
		dosageSqSum = LoadFloatVectorFromFile(dos2File, numCtx*slots)
		filtOut = readFilterFromFile(filtFile, numCtx*slots, true)

		log.LLvl1("Dosage Sum:", dosageSum[:5])
		log.LLvl1("Dosage SqSum:", dosageSqSum[:5])

	} else {

		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: MatMult: block", b+1, "/", numBlocks, "starting")

		filtOut = make([]bool, numCtx*slots)

		start := time.Now()
		if isPgen {

			numInd := gwasParams.numFiltInds[pid]
			snpFilt := gwasParams.snpFilt[shift : shift+uint64(blockSize)]

			pgenFile := fmt.Sprintf(ast.general.config.GenoFilePrefix, b+1) // Geno file for chromosome b+1

			startIndex := 0
			counter := 0
			outShift := 0
			batchIndex := 0

			nbatch := 1 + (nsnps-1)/pgenBatchSize
			outMult := make([]crypto.CipherMatrix, nbatch)

			dosageSum = make([]float64, numCtx*slots)
			dosageSqSum = make([]float64, numCtx*slots)

			nblocksParallel := ast.general.config.LocalAssocNumBlocksParallel
			nprocsPerBlock := Max(1, runtime.GOMAXPROCS(0)/nblocksParallel)

			// Dispatcher
			threadPool := make(chan int, nblocksParallel)
			for i := 0; i < nblocksParallel; i++ {
				threadPool <- i
			}

			var wg sync.WaitGroup

			for idx := 0; idx < blockSize; idx++ {
				if snpFilt[idx] {
					counter++
				}

				if counter == pgenBatchSize || (idx == blockSize-1 && counter > 0) {
					// Fetch an available thread
					threadId := <-threadPool
					wg.Add(1)

					go func(threadId, batchIndex, startIndex, idx, counter, shift, outShift int) {
						defer wg.Done()

						start := time.Now()
						log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("MatMult: block %d/%d, batch %d/%d, thread %d started", b+1, numBlocks, batchIndex+1, nbatch, threadId))

						batchFilt := snpFilt[startIndex : idx+1]
						gfsTempFile := ast.general.CachePath(fmt.Sprintf("pgen_gfs.%d.tmp", threadId))

						FilterMatrixFilePgen(pgenFile, numInd, counter, ast.general.config.SampleKeepFile, ast.general.config.SnpIdsFile, shift+startIndex, batchFilt, gfsTempFile, nprocsPerBlock)

						X := NewGenoFileStream(gfsTempFile, uint64(numInd), uint64(counter), true)

						mult, sum, sqSum := MatMult4Stream(cryptoParams, mat, X, 5, true, nprocsPerBlock)

						outMult[batchIndex] = mult
						copy(dosageSum[outShift:outShift+len(sum)], sum)
						copy(dosageSqSum[outShift:outShift+len(sqSum)], sqSum)
						for c := 0; c < counter; c++ {
							filtOut[outShift+c] = true
						}

						log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("MatMult: block %d/%d, batch %d/%d, thread %d finished,", b+1, numBlocks, batchIndex+1, nbatch, threadId), "elapsed time", time.Since(start))

						// Return thread to pool
						threadPool <- threadId
					}(threadId, batchIndex, startIndex, idx, counter, int(shift), outShift)

					nctx := 1 + (counter-1)/slots
					outShift += nctx * slots
					startIndex = idx + 1
					batchIndex++
					counter = 0
				}
			}

			wg.Wait() // Wait until all batches are finished
			close(threadPool)

			matOut = crypto.ConcatCipherMatrix(outMult)

		} else {
			matOut, dosageSum, dosageSqSum = MatMult4Stream(cryptoParams, mat, XBlock, 5, true, 0)

			for c := 0; c < nsnps; c++ {
				filtOut[c] = true
			}
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "elapsed time", time.Since(start))

		// Save cache
		crypto.SaveCipherMatrixToFile(cryptoParams, matOut, multFile)
		SaveFloatVectorToFile(dosFile, dosageSum)
		SaveFloatVectorToFile(dos2File, dosageSqSum)
		writeFilterToFile(filtFile, filtOut, true)
	}

	return
}

func (ast *AssocTest) GetAssociationStats() (crypto.CipherMatrix, []bool) {
	debug := ast.general.config.Debug

	covAllOnes := ast.general.config.CovAllOnes // Flag indicating whether cov includes an all-ones covariate

	cryptoParams := ast.general.cps
	mpcPar := ast.general.mpcObj
	mpcObj := mpcPar[0]
	pid := mpcPar[0].GetPid()
	gwasParams := ast.general.gwasParams
	slots := cryptoParams.GetSlots()

	numBlocks := ast.general.config.GenoNumBlocks

	/* Sample counts */
	nrowsAll := gwasParams.FiltNumInds()
	nrowsTotal := 0
	for i := 1; i < len(nrowsAll); i++ {
		nrowsTotal += nrowsAll[i]
	}
	nrowsTotalInv := 1.0 / float64(nrowsTotal)

	/* Phenotypes and PCs */
	Qpc := ast.Qpc

	/* Setup covariates */
	C := ast.inputCov
	ncov := gwasParams.NumCov()
	if !covAllOnes {
		log.LLvl1("Adding an all-ones covariate")

		arr := make([]float64, nrowsAll[pid])
		for i := range arr {
			arr[i] = 1.0
		}
		pv, _ := crypto.EncodeFloatVector(cryptoParams, arr)

		C = append([]crypto.PlainVector{pv}, C...)
		ncov += 1

		covAllOnes = true
	} else {
		log.LLvl1("Warning: assumes the first covariate is all ones (if not reorder)")
	}

	if debug && pid > 0 {
		yDebug := make([][]float64, len(ast.pheno))
		for i := range ast.pheno {
			yDebug[i] = crypto.DecodeFloatVector(cryptoParams, ast.pheno[i])[:nrowsAll[pid]]
		}
		SaveFloatMatrixToFile(ast.general.CachePath("y.txt"), yDebug)

		Cf := make([][]float64, len(C))
		for i := range C {
			Cf[i] = crypto.DecodeFloatVector(cryptoParams, C[i])[:nrowsAll[pid]]
		}
		SaveFloatMatrixToFile(ast.general.CachePath("C.txt"), Cf)
	}

	cacheFileQ := ast.general.CachePath("Qcomb.bin")
	var Q crypto.CipherMatrix
	if ast.general.config.UseCachedCombinedQ {
		if pid > 0 {
			Q = crypto.LoadCipherMatrixFromFile(cryptoParams, cacheFileQ)
			log.LLvl1(time.Now().Format(time.RFC3339), "Qcomb loaded from", cacheFileQ)
		}
	} else {
		Q = ast.computeCombinedQV2(C, Qpc) // nil for pid = 0
		if pid > 0 {
			crypto.SaveCipherMatrixToFile(cryptoParams, Q, cacheFileQ)
			log.LLvl1(time.Now().Format(time.RFC3339), "Qcomb saved to", cacheFileQ)
		}
	}

	if debug && pid > 0 {
		for party := 1; party <= ast.general.config.NumMainParties; party++ {
			SaveMatrixToFile(cryptoParams, mpcObj, Q, nrowsAll[party], party, ast.general.CachePath("Qcomb.txt"))
		}
	}

	var multiPhenoSize int

	var varx, sx, sxx crypto.CipherVector
	var vary, sy, sxy crypto.CipherMatrix
	var nsnps, numCtx int
	var outFilter []bool

	if pid == 0 {
		multiPhenoSize = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())
		numCtx = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())
		nsnps = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())

		varx = crypto.CZeros(cryptoParams, numCtx)
		sxx = crypto.CZeros(cryptoParams, numCtx)
		vary = make(crypto.CipherMatrix, multiPhenoSize)
		for i := range vary {
			vary[i] = crypto.CZeros(cryptoParams, 1)
		}

	} else { // pid > 0
		multiPhenoSize = len(ast.pheno)

		// Project covariates out of y: ynew = (I - Q*Q')*ymat
		ymat := ast.pheno

		mmplainfn := func(cp *crypto.CryptoParams, a crypto.CipherVector,
			B crypto.PlainMatrix, j int) crypto.CipherVector {
			return crypto.CPMult(cp, a, B[j])
		}

		ynew := DCMatMulAAtBPlain(cryptoParams, mpcObj, Q, ymat, nrowsAll, multiPhenoSize, mmplainfn) // Level -2

		for i := 0; i < multiPhenoSize; i++ {
			ynew[i] = crypto.CMultConstRescale(cryptoParams, ynew[i], nrowsTotalInv, true)
		}

		if debug {
			for party := 1; party <= ast.general.config.NumMainParties; party++ {
				SaveMatrixToFile(cryptoParams, mpcObj, ynew, nrowsAll[party], party, ast.general.CachePath("QQy.txt"))
			}
		}

		for i := 0; i < multiPhenoSize; i++ {
			ynew[i] = mpcObj.Network.BootstrapVecAll(cryptoParams, ynew[i])
			ynew[i] = crypto.CMultConst(cryptoParams, ynew[i], -1.0, true)
			ynew[i] = crypto.CPAdd(cryptoParams, ynew[i], ymat[i])
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "ynew computed")

		if debug {
			for party := 1; party <= ast.general.config.NumMainParties; party++ {
				SaveMatrixToFile(cryptoParams, mpcObj, ynew, nrowsAll[party], party, ast.general.CachePath("ynew.txt"))
			}
		}

		// Compute u (=Q*Q'*1)
		dummyMat := make(crypto.PlainMatrix, 1)
		mm1fn := func(cp *crypto.CryptoParams, a crypto.CipherVector,
			B crypto.PlainMatrix, j int) crypto.CipherVector {
			return crypto.CopyEncryptedVector(a)
		}

		u := DCMatMulAAtBPlain(cryptoParams, mpcObj, Q, dummyMat, nrowsAll, 1, mm1fn) // Level -2
		u[0] = crypto.CMultConstRescale(cryptoParams, u[0], nrowsTotalInv, true)
		log.LLvl1(time.Now().Format(time.RFC3339), "u computed")

		if debug {
			for party := 1; party <= ast.general.config.NumMainParties; party++ {
				SaveMatrixToFile(cryptoParams, mpcObj, u, nrowsAll[party], party, ast.general.CachePath("u.txt"))
			}
		}

		omu := crypto.CZeros(cryptoParams, len(u[0]))
		if !covAllOnes {
			omu = crypto.CSub(cryptoParams, omu, u[0])
			omu = crypto.CAddConst(cryptoParams, omu, 1.0)

			log.LLvl1(time.Now().Format(time.RFC3339), "omu computed")
		} else {
			log.LLvl1(time.Now().Format(time.RFC3339), "omu set to zero")
		}

		if debug {
			for party := 1; party <= ast.general.config.NumMainParties; party++ {
				SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{omu}, nrowsAll[party], party, ast.general.CachePath("omu.txt"))
			}
		}

		// Compute sx, sxx, sxy, sy, syy
		// sx = 1'*X - u'*X = omu'*X
		// sxx = diag(X'X) - diag(B'B)
		// sxy = ynew'*X

		// In parallel:
		// (1) Compute B (=Q'*X, row-based encoding)
		// (2) Compute sx (=omu'*X)
		// (3) Compute sxy (=ynew'*X)
		// Note: if covAllOnes = true, then sx = sy = 0. Skip all calculations involving sx and sy.

		concat := make(crypto.CipherMatrix, len(Q)+1+multiPhenoSize) // remove all ones
		copy(concat, Q)
		concat[len(Q)] = omu

		for i := 0; i < multiPhenoSize; i++ {
			concat[len(Q)+1+i] = ynew[i]
		}

		filtOut := make([][]bool, numBlocks)

		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Starting Multiplication with Genotype Matrix")

		sxBlocks := make([]crypto.CipherMatrix, numBlocks)
		sxxBlocks := make([]crypto.CipherMatrix, numBlocks)
		sxyBlocks := make([]crypto.CipherMatrix, numBlocks)

		for b := 0; b < numBlocks; b++ {
			if !ast.general.IsBlockForAssocTest(b) {
				log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "skipped")
			} else {
				concatOut, dosageSum, dosageSqSum, filt := ast.GenoBlockMult(b, concat)
				if concatOut == nil {
					continue
				}

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "aggregating")
				concatOut = mpcObj.Network.AggregateCMat(cryptoParams, concatOut)
				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "bootstrapping")
				concatOut = mpcObj.Network.CollectiveBootstrapMat(cryptoParams, concatOut, -1)

				B := make(crypto.CipherMatrix, len(Q)-1) // Skip the one correponding to all ones
				for i := range B {
					B[i] = crypto.CMultConstRescale(cryptoParams, concatOut[i+1], math.Sqrt(nrowsTotalInv), true)
				}

				if covAllOnes {
					sxBlocks[b] = crypto.CipherMatrix{crypto.CZeros(cryptoParams, len(concatOut[len(Q)]))}
					log.LLvl1(time.Now().Format(time.RFC3339), "sx set to zero")
				} else {
					sxBlocks[b] = crypto.CipherMatrix{concatOut[len(Q)]}
				}

				sxyBlocks[b] = make(crypto.CipherMatrix, multiPhenoSize)
				for i := 0; i < multiPhenoSize; i++ {
					sxyBlocks[b][i] = concatOut[len(Q)+1+i]
				}

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "computed B, sx, sxy")

				var sx2 crypto.CipherVector
				if dosageSqSum != nil {
					sxxBlocks[b] = make(crypto.CipherMatrix, 1)
					sxxBlocks[b][0], _ = crypto.EncryptFloatVector(cryptoParams, dosageSqSum)
					sx2, _ = crypto.EncryptFloatVector(cryptoParams, dosageSum)
				}

				sx2 = mpcObj.Network.AggregateCVec(cryptoParams, sx2)
				sx2 = crypto.CMultConstRescale(cryptoParams, sx2, math.Sqrt(nrowsTotalInv), true)

				if pid == mpcObj.GetHubPid() {
					cryptoParams.WithEvaluator(func(evaluator ckks.Evaluator) error {
						for c := range B {
							for j := range sxxBlocks[b][0] {
								tmp := evaluator.MulRelinNew(B[c][j], B[c][j])
								evaluator.Sub(sxxBlocks[b][0][j], tmp, sxxBlocks[b][0][j])
							}
						}
						for j := range sxxBlocks[b][0] {
							tmp := evaluator.MulRelinNew(sx2[j], sx2[j])
							evaluator.Sub(sxxBlocks[b][0][j], tmp, sxxBlocks[b][0][j])
						}
						return nil
					})
				}

				sxxBlocks[b][0] = mpcObj.Network.AggregateCVec(cryptoParams, sxxBlocks[b][0])

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "computed sxx")

				filtOut[b] = filt
			}
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "All blocks processed")

		sx = crypto.ConcatCipherMatrix(sxBlocks)[0]
		sxy = crypto.ConcatCipherMatrix(sxyBlocks)
		sxx = crypto.ConcatCipherMatrix(sxxBlocks)[0]
		sxBlocks, sxxBlocks, sxyBlocks = nil, nil, nil

		totLen := 0
		for i := range filtOut {
			totLen += len(filtOut[i])
		}

		outFilter = make([]bool, totLen)
		outShift := 0
		for i := range filtOut {
			copy(outFilter[outShift:], filtOut[i])
			outShift += len(filtOut[i])
		}
		filtOut = nil

		numCtx = len(sx)
		nsnps = SumBool(outFilter)

		if pid == mpcObj.GetHubPid() {
			mpcObj.Network.SendInt(multiPhenoSize, 0)
			mpcObj.Network.SendInt(numCtx, 0)
			mpcObj.Network.SendInt(nsnps, 0)
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "numCtx", numCtx, "numSnps", nsnps)

		// Compute sy and syy
		syy := make(crypto.CipherMatrix, multiPhenoSize)
		if covAllOnes {
			sy = make(crypto.CipherMatrix, multiPhenoSize)
			for i := 0; i < multiPhenoSize; i++ {
				sy[i] = crypto.CZeros(cryptoParams, 1)
			}
			log.LLvl1(time.Now().Format(time.RFC3339), "sy set to zero")
		} else {
			sy = make(crypto.CipherMatrix, multiPhenoSize)
			for i := 0; i < multiPhenoSize; i++ {
				sy[i] = crypto.CipherVector{mpcObj.Network.AggregateCText(
					cryptoParams, crypto.InnerSumAll(cryptoParams, ynew[i]))}
				sy[i] = mpcObj.Network.CollectiveBootstrapVec(cryptoParams, sy[i], -1)
			}
		}

		for i := 0; i < multiPhenoSize; i++ {
			ynewsq := crypto.CMult(cryptoParams, ynew[i], ynew[i])
			syyloc := crypto.InnerSumAll(cryptoParams, ynewsq)
			syy[i] = crypto.CipherVector{mpcObj.Network.AggregateCText(cryptoParams, syyloc)}
			syy[i] = mpcObj.Network.CollectiveBootstrapVec(cryptoParams, syy[i], -1)
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Computed sy/syy")

		totalInds := 0
		for _, v := range nrowsAll {
			totalInds += v
		}

		sqrtinvn := 1.0 / math.Sqrt(float64(totalInds))
		if !covAllOnes {
			sx = crypto.CMultConst(cryptoParams, sx, sqrtinvn, true) // sx / sqrt(n)

			varx = crypto.CMult(cryptoParams, sx, sx)   // sx * sx / n
			varx = crypto.CSub(cryptoParams, sxx, varx) // varx = sxx - (sx * sx / n)

			vary = make(crypto.CipherMatrix, multiPhenoSize)
			for i := 0; i < multiPhenoSize; i++ {
				sy[i] = crypto.CMultConst(cryptoParams, sy[i], sqrtinvn, true) // sy[i] / sqrt(n)
				vary[i] = crypto.CMult(cryptoParams, sy[i], sy[i])             // sy[i] * sy[i] / n
				vary[i] = crypto.CSub(cryptoParams, syy[i], vary[i])           // vary[i] = syy[i] - (sy[i]*sy[i]/n)
			}
		} else {
			varx = sxx
			vary = syy
		}

		if debug {
			writeFilterToFile(ast.general.CachePath("xfilt.bin"), outFilter, true)
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{sx}, len(sx)*slots, -1, ast.general.CachePath("sx.txt"))       // sx / sqrt(n)
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{sxx}, len(sxx)*slots, -1, ast.general.CachePath("sxx.txt"))    // sxx
			SaveMatrixToFile(cryptoParams, mpcObj, sy, 1, -1, ast.general.CachePath("sy.txt"))                                        // sy / sqrt(n)
			SaveMatrixToFile(cryptoParams, mpcObj, syy, 1, -1, ast.general.CachePath("syy.txt"))                                      // syy
			SaveMatrixToFile(cryptoParams, mpcObj, sxy, len(sxy[0])*slots, -1, ast.general.CachePath("sxy.txt"))                      // sxy
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{varx}, len(varx)*slots, -1, ast.general.CachePath("varx.txt")) // sxx - (sx*sx/n)
			SaveMatrixToFile(cryptoParams, mpcObj, vary, 1, -1, ast.general.CachePath("vary.txt"))                                    // syy - (sy*sy/n)
		}
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "AssertSync")
	mpcObj.AssertSync()

	stdinvx, stdinvy := ComputeStdInv(cryptoParams, mpcPar, varx, vary, nsnps, outFilter, debug)
	log.LLvl1(time.Now().Format(time.RFC3339), "Computed stdev")

	if debug && pid > 0 {
		SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{stdinvx}, nsnps, -1, ast.general.CachePath("stdinvx.txt")) // 1 / sqrt(sxx - (sx*sx/n))
		SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{stdinvy}, 1, -1, ast.general.CachePath("stdinvy.txt"))     // 1 / sqrt(syy - (sy*sy/n))
	}

	if pid > 0 {
		stats := make(crypto.CipherMatrix, multiPhenoSize)
		for i := 0; i < multiPhenoSize; i++ {
			var s crypto.CipherVector
			if !covAllOnes {
				s = crypto.CMultScalar(cryptoParams, sx, sy[i][0]) // sx * sy[i] / n
				s = crypto.CSub(cryptoParams, sxy[i], s)           // sxy[i] - (sx * sy[i] / n)
			} else {
				s = sxy[i]
			}
			s = crypto.CMult(cryptoParams, s, stdinvx)          // stdinvx * (sxy[i] - ...)
			s = crypto.CMultScalar(cryptoParams, s, stdinvy[i]) // stdinvx * stdinvy[i] * ...
			stats[i] = s
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "All done!")

		return stats, outFilter
	}

	return nil, nil // party 0
}

// covOrthoFactor applies S (see computeCovOrthoFactor) to a target matrix, in either
// secret-shared or ciphertext form, using whichever sequence of multiply+truncate steps is
// correct for how S itself is constructed. Deliberately NOT just a plain mpc_core.RMat:
// Cholesky's S genuinely is one matrix (L^{-1}), so applying it is one multiply+truncate,
// but eigendecomposition's S is a product of two matrices -- diag(1/sqrt(λ)) and Vᵀ -- that
// Hoon's original code always applied as two SEPARATE truncated steps directly to the
// target data, never combined into a standalone ncov-by-ncov matrix first. An earlier
// version of this fused those two steps into one (mathematically valid in exact arithmetic,
// since matrix multiplication is associative) and it produced ~1e44-1e46 garbage on the
// real dataset: associativity holds exactly, but NOT under fixed-point truncation, where
// where you truncate changes the result. This type exists so each construction can apply
// itself using its own correct sequencing, without the call sites needing to know which.
type covOrthoFactor struct {
	applySS func(mpc_core.RMat) mpc_core.RMat
	applyCT func(crypto.CipherMatrix) crypto.CipherMatrix
}

// covOrthoHighPrec optionally carries a higher-fracBits representation of ZtZss/scaling,
// used only by computeCovOrthoFactor's Cholesky branch. ZtZ's condition number is the
// square of Z's own (unlike legacy's computeCombinedQV2, which runs an actual QR directly
// on Z via NetDQRenc), so for SNPs collinear with the covariate/PC space, the standard
// fracBits can lose enough precision in S that downstream sxx = diag(XᵀX) - diag(BᵀB)
// catastrophically cancels. Extra fracBits on just this ncov-by-ncov step recovers digits
// without touching the much more expensive genome-wide path -- ZtZ is formed once, cheaply,
// regardless of precision. nil disables this (standard-precision path, unchanged).
type covOrthoHighPrec struct {
	ZtZss    mpc_core.RMat
	scaling  mpc_core.RElem
	dataBits int
	fracBits int
}

// computeCovOrthoFactor returns S (ncov-by-ncov) such that SᵀS = scaling²·(ZtZss)^{-1}, so
// that Q = Zᵀ·Sᵀ is an orthonormal basis for the covariate/PC column space (see the comment
// at this function's call site for why any such S gives identical association statistics).
// Two interchangeable constructions:
//
//   - Cholesky (default): S = scaling * L^{-1}, where ZtZss = L Lᵀ. Direct, non-iterative,
//     no eigenvalues computed at all — see CholeskyInvSqrt's doc comment.
//   - Eigendecomposition (config.UseEigenCovOrtho = true): S = diag(1/sqrt(λ)) * Vᵀ, where
//     ZtZss = VΛVᵀ. This was the original construction; kept available since its smallest
//     eigenvalue can carry several percent of run-dependent error from the iterative
//     shifted-QR algorithm on an ill-conditioned covariate matrix (see EigenDecomp's doc
//     comment) — useful for comparing against Cholesky on suspect input.
func (ast *AssocTestPlainMult) computeCovOrthoFactor(cryptoParams *crypto.CryptoParams, ZtZss mpc_core.RMat, scaling mpc_core.RElem, hiPrec *covOrthoHighPrec, numThreads int) covOrthoFactor {
	mpcObj := ast.general.mpcObj[0]
	dataBits := mpcObj.GetDataBits()
	fracBits := mpcObj.GetFracBits()
	debug := ast.general.config.Debug
	pid := mpcObj.GetPid()

	if !ast.general.config.UseEigenCovOrtho {
		var Sss, Lss, LinvSs mpc_core.RMat
		var revealFracBits int
		if hiPrec == nil {
			Sss, Lss, LinvSs = mpcObj.CholeskyInvSqrt(ZtZss, scaling)
			revealFracBits = fracBits
		} else {
			// Temporarily run CholeskyInvSqrt (and everything it calls -- SqrtAndSqrtInverse,
			// TruncVec/TruncMat) at higher precision, then rescale the result back down to
			// the standard fracBits before it's used by the rest of this (standard-precision)
			// pipeline. Scoped to mpcObj[0] only, synchronously, before the per-block parallel
			// loop starts -- no concurrent goroutine touches this MPC object's precision
			// fields during the window between save and restore.
			revealFracBits = hiPrec.fracBits
			Sss, Lss, LinvSs = func() (mpc_core.RMat, mpc_core.RMat, mpc_core.RMat) {
				oldDataBits, oldFracBits := mpcObj.GetDataBits(), mpcObj.GetFracBits()
				defer func() {
					mpcObj.SetDataBits(oldDataBits)
					mpcObj.SetFracBits(oldFracBits)
				}()
				mpcObj.SetDataBits(hiPrec.dataBits)
				mpcObj.SetFracBits(hiPrec.fracBits)
				SssHi, LssHi, LinvSsHi := mpcObj.CholeskyInvSqrt(hiPrec.ZtZss, hiPrec.scaling)
				return mpcObj.TruncMat(SssHi, hiPrec.dataBits, hiPrec.fracBits-fracBits), LssHi, LinvSsHi
			}()
		}

		// L and Linv are the un-scaled Cholesky factor of ZtZss and its inverse -- dumped
		// so they can be diffed directly against testutil.Cholesky's plaintext L/Linv on
		// the same input, isolating whether a precision issue is fixed-point truncation
		// here or ZtZ's own conditioning (see CholeskyInvSqrt's doc comment).
		if debug && pid > 0 {
			Lr := mpcObj.RevealSymMat(Lss).ToFloat(revealFracBits)
			LinvR := mpcObj.RevealSymMat(LinvSs).ToFloat(revealFracBits)
			SaveFloatMatrixToFileRowMajor(ast.general.CachePath("cholesky_L.txt"), Lr)
			SaveFloatMatrixToFileRowMajor(ast.general.CachePath("cholesky_Linv.txt"), LinvR)
		}

		Sct := mpcObj.SSToCMat(cryptoParams, Sss)
		return covOrthoFactor{
			applySS: func(A mpc_core.RMat) mpc_core.RMat {
				R := mpcObj.SSMultMat(Sss, A)
				return mpcObj.TruncMat(R, dataBits, fracBits)
			},
			applyCT: func(A crypto.CipherMatrix) crypto.CipherMatrix {
				return CMultMatRowTimesRow(cryptoParams, Sct, A, numThreads)
			},
		}
	}

	rtype := mpcObj.GetRType()
	useBoolean := mpcObj.GetBooleanShareFlag()
	ncov := len(ZtZss)

	Vtss, Lss := mpcObj.EigenDecomp(ZtZss)
	_, LsqrtInvss := mpcObj.SqrtAndSqrtInverse(Lss, useBoolean)

	LsqrtInvss.MulScalar(scaling)
	LsqrtInvss = mpcObj.TruncVec(LsqrtInvss, dataBits, fracBits)

	LsqrtInvDiagss := mpc_core.InitRMat(rtype.Zero(), ncov, ncov)
	for i := 0; i < ncov; i++ {
		LsqrtInvDiagss[i][i] = LsqrtInvss[i].Copy()
	}

	// Ciphertext counterparts for applyCT, mirroring the secret-shared ones above.
	Vt := mpcObj.SSToCMat(cryptoParams, Vtss)
	LsqrtInv := crypto.CZeros(cryptoParams, len(LsqrtInvss)) // one ciphertext per eigenvalue
	for i := range LsqrtInv {
		LsqrtInv[i] = mpcObj.SStoCiphertext(cryptoParams, mpc_core.RVec{LsqrtInvss[i]})
		if mpcObj.GetPid() > 0 { // no share on party 0; SStoCiphertext left it nil
			LsqrtInv[i] = crypto.InnerSumAll(cryptoParams, crypto.CipherVector{LsqrtInv[i]})
		}
	}

	return covOrthoFactor{
		applySS: func(A mpc_core.RMat) mpc_core.RMat {
			R := mpcObj.SSMultMat(Vtss, A)
			R = mpcObj.TruncMat(R, dataBits, fracBits)
			R = mpcObj.SSMultMat(LsqrtInvDiagss, R)
			return mpcObj.TruncMat(R, dataBits, fracBits)
		},
		applyCT: func(A crypto.CipherMatrix) crypto.CipherMatrix {
			B := CMultMatRowTimesRow(cryptoParams, Vt, A, numThreads)
			for i := range B {
				B[i] = crypto.CMultScalar(cryptoParams, B[i], LsqrtInv[i])
			}
			return B
		},
	}
}

// Optimized version that assumes PCs are provided in plaintext.
// Performs multiplications on local plaintext matrices to avoid expensive cipher-plain operations
// on the large genotype matrix. Corrects for covariates post-multiplication using the inverse covariance matrix
func (ast *AssocTestPlainMult) GetAssociationStatsPlainMult() (crypto.CipherMatrix, []bool) {
	debug := ast.general.config.Debug

	numThreads := ast.general.config.LocalNumThreads

	cryptoParams := ast.general.cps
	slots := cryptoParams.GetSlots()

	mpcPar := ast.general.mpcObj
	mpcObj := mpcPar[0]
	fracBits := mpcObj.GetFracBits()
	rtype := mpcObj.GetRType()

	gwasParams := ast.general.gwasParams
	numBlocks := ast.general.config.GenoNumBlocks

	covAllOnes := ast.general.config.CovAllOnes // Flag indicating whether cov includes an all-ones covariate

	pid := mpcObj.GetPid()

	/* Sample counts */
	nrowsAll := gwasParams.FiltNumInds()
	nrowsTotal := 0
	for i := 1; i < len(nrowsAll); i++ {
		nrowsTotal += nrowsAll[i]
	}
	nrowsTotalInv := 1.0 / float64(nrowsTotal)
	nrowsTotalInvSqrt := math.Sqrt(nrowsTotalInv)

	/* Covariate (includes PCs) and pheno counts */
	/* Data dimensions already verifed in protocol setup */
	ncov := gwasParams.NumCov() + gwasParams.NumPC()
	npheno := gwasParams.NumPheno()

	Zt := ast.covPc
	Yt := ast.pheno

	if !covAllOnes {
		log.LLvl1("Adding an all-ones covariate")

		_, cols := Zt.Dims()

		ones := mat.NewDense(1, cols, nil)
		if pid > 0 {
			// Party 0 holds no share of the data; its Zt is a dummy placeholder and must
			// stay all-zero so that it contributes nothing to the shared Zt*Z below.
			for i := 0; i < cols; i++ {
				ones.Set(0, i, 1)
			}
		}

		covWithIntercept := mat.NewDense(ncov+1, cols, nil)
		covWithIntercept.Stack(ones, Zt)

		Zt = covWithIntercept
		ncov += 1
		covAllOnes = true
	} else {
		log.LLvl1("Warning: assumes the first covariate is all ones (if not, reorder input)")
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "Phenotype count:", npheno)
	log.LLvl1(time.Now().Format(time.RFC3339), "Covariate count (including PCs and intercept):", ncov)
	log.LLvl1(time.Now().Format(time.RFC3339), "Local individual count:", nrowsAll)
	log.LLvl1(time.Now().Format(time.RFC3339), "Total individual count:", nrowsTotal)

	/* Compute S of (Zt*Z)^{-1} = St*S (dims: ncov-by-ncov) */

	var tmp mat.SymDense
	tmp.SymOuterK(nrowsTotalInvSqrt, Zt) // Scale Zt*Z by 1/sqrt(n)
	ZtZss := mpc.DenseToRMat(rtype, &tmp, fracBits)

	// Also capture ZtZ at higher fracBits from the same plaintext tmp, before it's
	// discarded -- see covOrthoHighPrec's doc comment. Only meaningful for the Cholesky
	// branch (eigen already has its own, separate precision story via EigenDecomp).
	var hiPrec *covOrthoHighPrec
	if ast.general.config.UseHighPrecCovOrtho && !ast.general.config.UseEigenCovOrtho {
		hiDataBits, hiFracBits := mpcObj.GetDataBits()*2, fracBits*2
		hiPrec = &covOrthoHighPrec{
			ZtZss:    mpc.DenseToRMat(rtype, &tmp, hiFracBits),
			scaling:  rtype.FromFloat64(math.Sqrt(math.Sqrt(float64(nrowsTotal))), hiFracBits),
			dataBits: hiDataBits,
			fracBits: hiFracBits,
		}
	}
	tmp.Reset()

	log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Starting calculation of covariate correction factor")

	log.LLvl1(time.Now().Format(time.RFC3339), "Calculating inverse of covariate covariance matrix: started")

	// S combines downstream as (S·A)ᵀ(S·B) for various A, B (sxx via ΣB[c]², sxy via
	// YtQ·B, ...), so any S with SᵀS = sqrt(n)·(ZtZss)^{-1} is interchangeable — see
	// computeCovOrthoFactor for the two constructions available (config.UseEigenCovOrtho).
	scaling := rtype.FromFloat64(math.Sqrt(math.Sqrt(float64(nrowsTotal))), fracBits)
	covOrtho := ast.computeCovOrthoFactor(cryptoParams, ZtZss, scaling, hiPrec, numThreads)

	ZtZss = nil

	log.LLvl1(time.Now().Format(time.RFC3339), "Calculating inverse of covariate covariance matrix: finished")

	var varx, sx, sxx crypto.CipherVector
	var vary, sy, sxy crypto.CipherMatrix
	var nsnps, numCtx int
	var outFilter []bool

	var ZtY1ss mpc_core.RMat
	if pid > 0 {
		// Build [Yt; 1]
		Yt1 := mat.NewDense(npheno+1, nrowsAll[pid], nil)

		_, cols := Yt.Dims()

		ones := mat.NewDense(1, cols, nil)
		for i := 0; i < cols; i++ {
			ones.Set(0, i, 1)
		}

		Yt1.Stack(Yt, ones)

		var ZtY1 mat.Dense
		ZtY1.Mul(Zt, Yt1.T())
		ZtY1.Scale(nrowsTotalInvSqrt, &ZtY1) // scaling by 1/sqrt(n)
		ZtY1ss = mpc.DenseToRMat(rtype, &ZtY1, fracBits)
	} else {
		ZtY1ss = mpc_core.InitRMat(rtype.Zero(), ncov, npheno+1)
	}

	QtY1ss := covOrtho.applySS(ZtY1ss)

	// Split into QtY and Qt1
	YtQss := mpc_core.InitRMat(rtype.Zero(), npheno, ncov)
	OnetQss := mpc_core.InitRVec(rtype.Zero(), ncov)
	if pid > 0 {
		for i := 0; i < ncov; i++ {
			for j := 0; j < npheno; j++ {
				YtQss[j][i] = QtY1ss[i][j].Copy()
			}
			OnetQss[i] = QtY1ss[i][npheno].Copy()
		}
	}
	QtY1ss = nil

	OnetQ := mpcObj.SSToCVec(cryptoParams, OnetQss)
	YtQ := mpcObj.SSToCMat(cryptoParams, YtQss)
	OnetQss, YtQss = nil, nil

	if pid == 0 { // TODO: Check consistency with pid > 0 branch
		numCtx = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())
		nsnps = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())

		varx = crypto.CZeros(cryptoParams, numCtx)
		sxx = crypto.CZeros(cryptoParams, numCtx)
		vary = make(crypto.CipherMatrix, npheno)
		for i := range vary {
			vary[i] = crypto.CZeros(cryptoParams, 1)
		}

	} else { // pid > 0

		// Compute sx, sxx, sxy, sy, syy
		// sx = 1ᵀ(I - QQᵀ)X = 1ᵀX - (1ᵀQ)(QᵀX)
		// sxx = diag(XᵀX) - diag((XᵀQ)(QᵀX))
		// sxy = Yᵀ(I-QQᵀ)X = YᵀX - (YᵀQ)(QᵀX)

		// In parallel:
		// (1) Compute ZᵀX (then later compute B = QᵀX = S * (ZᵀX)/sqrt(n))
		// (2) Compute YᵀX (for sxy = Yᵀ*X - (YᵀQ)B
		// (3) Compute 1ᵀX (for sx = 1ᵀX - (1ᵀQ)B) --> Computed separately as dosageSum
		// (4) Compute diag(XᵀX) (for sxx = diag(XᵀX) - diag(BᵀB)) --> Computed separately as dosageSqSum
		// Note: if covAllOnes = true, then sx = sy = 0. Skip all calculations involving sx and sy.

		matIn := mat.NewDense(ncov+npheno, nrowsAll[pid], nil)
		matIn.Stack(Zt, Yt)

		filtOut := make([][]bool, numBlocks)

		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Starting Multiplication with Genotype Matrix")

		sxBlocks := make([]crypto.CipherMatrix, numBlocks)
		sxxBlocks := make([]crypto.CipherMatrix, numBlocks)
		sxyBlocks := make([]crypto.CipherMatrix, numBlocks)

		for b := 0; b < numBlocks; b++ {
			if !ast.general.IsBlockForAssocTest(b) {
				log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "skipped")
			} else {
				matOut, dosageSum, dosageSqSum, filt := ast.GenoBlockMultPlain(b, matIn)
				if matOut == nil {
					continue
				}

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "computed genotype matrix mult")

				// Scale ZtX by 1/sqrt(n) to account for scaling in covariate correction
				for i := 0; i < ncov; i++ {
					for j := range matOut[i] {
						matOut[i][j] *= nrowsTotalInvSqrt
					}
				}

				matOutEnc, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, matOut)
				matOutEnc = mpcObj.Network.AggregateCMat(cryptoParams, matOutEnc)

				numCtx = len(matOutEnc[0])

				ZtXscaled := matOutEnc[:ncov]
				YtX := matOutEnc[ncov:]

				OnetX, _ := crypto.EncryptFloatVector(cryptoParams, dosageSum)
				OnetX = mpcObj.Network.AggregateCVec(cryptoParams, OnetX)

				OnetXsq, _ := crypto.EncryptFloatVector(cryptoParams, dosageSqSum)
				OnetXsq = mpcObj.Network.AggregateCVec(cryptoParams, OnetXsq)

				// Compute B = QᵀX = S * (ZᵀX)/sqrt(n)
				B := covOrtho.applyCT(ZtXscaled)

				// Compute sx = 1ᵀ(I - QQᵀ)X
				if covAllOnes {
					sxBlocks[b] = crypto.CipherMatrix{crypto.CZeros(cryptoParams, numCtx)}
					log.LLvl1(time.Now().Format(time.RFC3339), "sx set to zero")
				} else {
					tmp := CMultMatRowTimesRow(cryptoParams, crypto.CipherMatrix{OnetQ}, B, numThreads)
					sxBlocks[b] = crypto.CipherMatrix{crypto.CSub(cryptoParams, OnetX, tmp[0])}
				}

				// Compute sxy = Yᵀ(I - QQᵀ)X
				sxyBlocks[b] = make(crypto.CipherMatrix, npheno)
				tmp := CMultMatRowTimesRow(cryptoParams, YtQ, B, numThreads)
				for i := range sxyBlocks[b] {
					sxyBlocks[b][i] = crypto.CSub(cryptoParams, YtX[i], tmp[i])
				}

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "computed B, sx, sxy")

				// Compute sxx = diag(XᵀX) - diag(BᵀB)
				sxxBlocks[b] = crypto.CipherMatrix{OnetXsq}
				if err := cryptoParams.WithEvaluator(func(evaluator ckks.Evaluator) error {
					for c := range B {
						for j := range B[c] {
							tmp := evaluator.MulRelinNew(B[c][j], B[c][j])
							// Not required for correctness: Lattigo's Sub auto-aligns mismatched
							// scales (it upscales the lower-scale operand before subtracting), so
							// omitting this would still decode correctly. Rescaling here instead
							// keeps sxxBlocks at the codebase's canonical scale — matching every
							// other ct*ct product (see CMultScalar, CMultConstRescale) — rather
							// than leaving it elevated to Δ² for the rest of the pipeline.
							if err := evaluator.Rescale(tmp, cryptoParams.Params.Scale(), tmp); err != nil {
								return err
							}
							evaluator.Sub(sxxBlocks[b][0][j], tmp, sxxBlocks[b][0][j])
						}
					}
					return nil
				}); err != nil {
					log.Fatalf("block %d: rescaling B^2 before sxx subtraction: %v", b+1, err)
				}

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "computed sxx")

				filtOut[b] = make([]bool, numCtx*slots)
				copy(filtOut[b], filt)
			}
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "All blocks processed")

		sx = crypto.ConcatCipherMatrix(sxBlocks)[0]
		sxy = crypto.ConcatCipherMatrix(sxyBlocks)
		sxx = crypto.ConcatCipherMatrix(sxxBlocks)[0]
		sxBlocks, sxxBlocks, sxyBlocks = nil, nil, nil

		totLen := 0
		for i := range filtOut {
			totLen += len(filtOut[i])
		}

		outFilter = make([]bool, totLen)
		outShift := 0
		for i := range filtOut {
			copy(outFilter[outShift:], filtOut[i])
			outShift += len(filtOut[i])
		}
		filtOut = nil

		numCtx = len(sx)
		nsnps = SumBool(outFilter)

		if pid == mpcObj.GetHubPid() {
			mpcObj.Network.SendInt(numCtx, 0)
			mpcObj.Network.SendInt(nsnps, 0)
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "numCtx", numCtx, "numSnps", nsnps)

		// Compute sy = 1ᵀY - (1ᵀQ)(QᵀY)
		if covAllOnes {
			sy = make(crypto.CipherMatrix, npheno)
			for i := 0; i < npheno; i++ {
				sy[i] = crypto.CZeros(cryptoParams, 1)
			}
			log.LLvl1(time.Now().Format(time.RFC3339), "sy set to zero")
		} else {
			sy = make(crypto.CipherMatrix, npheno)
			buffer := make([]float64, slots)
			for i := 0; i < npheno; i++ {
				Ysum := floats.Sum(Yt.RawRowView(i))
				for i := range buffer {
					buffer[i] = Ysum
				}
				OnetYloc, _ := crypto.EncryptFloatVector(cryptoParams, buffer)
				OnetY := mpcObj.Network.AggregateCVec(cryptoParams, OnetYloc)
				ct := crypto.InnerProd(cryptoParams, OnetQ, YtQ[i])
				sy[i] = crypto.CSub(cryptoParams, OnetY, crypto.CipherVector{ct})
			}
		}

		// Compute syy = diag(YᵀY) - diag((YᵀQ)(QᵀY))
		syy := make(crypto.CipherMatrix, npheno)
		buffer := make([]float64, slots)
		for i := 0; i < npheno; i++ {
			YsqSum := floats.Norm(Yt.RawRowView(i), 2)
			YsqSum *= YsqSum
			for j := range buffer {
				buffer[j] = YsqSum
			}
			YtYloc, _ := crypto.EncryptFloatVector(cryptoParams, buffer)
			YtY := mpcObj.Network.AggregateCVec(cryptoParams, YtYloc)
			ct := crypto.InnerProd(cryptoParams, YtQ[i], YtQ[i]) // Check if masking is needed before InnerProd
			syy[i] = crypto.CSub(cryptoParams, YtY, crypto.CipherVector{ct})
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Computed sy and syy")

		if !covAllOnes {
			sx = crypto.CMultConst(cryptoParams, sx, nrowsTotalInvSqrt, true) // sx / sqrt(n)

			varx = crypto.CMult(cryptoParams, sx, sx)   // sx * sx / n
			varx = crypto.CSub(cryptoParams, sxx, varx) // varx = sxx - (sx * sx / n)

			vary = make(crypto.CipherMatrix, npheno)
			for i := 0; i < npheno; i++ {
				sy[i] = crypto.CMultConst(cryptoParams, sy[i], nrowsTotalInvSqrt, true) // sy[i] / sqrt(n)
				vary[i] = crypto.CMult(cryptoParams, sy[i], sy[i])                      // sy[i] * sy[i] / n
				vary[i] = crypto.CSub(cryptoParams, syy[i], vary[i])                    // vary[i] = syy[i] - (sy[i]*sy[i]/n)
			}
		} else {
			varx = sxx
			vary = syy
		}

		if debug {
			writeFilterToFile(ast.general.CachePath("xfilt.bin"), outFilter, true)
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{sx}, len(sx)*slots, -1, ast.general.CachePath("sx.txt"))       // sx / sqrt(n)
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{sxx}, len(sxx)*slots, -1, ast.general.CachePath("sxx.txt"))    // sxx
			SaveMatrixToFile(cryptoParams, mpcObj, sy, 1, -1, ast.general.CachePath("sy.txt"))                                        // sy / sqrt(n)
			SaveMatrixToFile(cryptoParams, mpcObj, syy, 1, -1, ast.general.CachePath("syy.txt"))                                      // syy
			SaveMatrixToFile(cryptoParams, mpcObj, sxy, len(sxy[0])*slots, -1, ast.general.CachePath("sxy.txt"))                      // sxy
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{varx}, len(varx)*slots, -1, ast.general.CachePath("varx.txt")) // sxx - (sx*sx/n)
			SaveMatrixToFile(cryptoParams, mpcObj, vary, 1, -1, ast.general.CachePath("vary.txt"))                                    // syy - (sy*sy/n)
		}
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "AssertSync")
	mpcObj.AssertSync()

	stdinvx, stdinvy := ComputeStdInv(cryptoParams, mpcPar, varx, vary, nsnps, outFilter, debug)
	log.LLvl1(time.Now().Format(time.RFC3339), "Computed stdev")

	if debug && pid > 0 {
		SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{stdinvx}, nsnps, -1, ast.general.CachePath("stdinvx.txt")) // 1 / sqrt(sxx - (sx*sx/n))
		SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{stdinvy}, 1, -1, ast.general.CachePath("stdinvy.txt"))     // 1 / sqrt(syy - (sy*sy/n))
	}

	if pid > 0 {
		stats := make(crypto.CipherMatrix, npheno)
		for i := 0; i < npheno; i++ {
			var s crypto.CipherVector
			if !covAllOnes {
				s = crypto.CMultScalar(cryptoParams, sx, sy[i][0]) // sx * sy[i] / n
				s = crypto.CSub(cryptoParams, sxy[i], s)           // sxy[i] - (sx * sy[i] / n)
			} else {
				s = sxy[i]
			}
			s = crypto.CMult(cryptoParams, s, stdinvx)          // stdinvx * (sxy[i] - ...)
			s = crypto.CMultScalar(cryptoParams, s, stdinvy[i]) // stdinvx * stdinvy[i] * ...
			stats[i] = s
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "All done!")

		return stats, outFilter
	}

	return nil, nil // party 0
}

// Returns stdinvx (per-SNP) and stdinvy (one per phenotype)
func ComputeStdInv(cryptoParams *crypto.CryptoParams, mpcPar mpc.ParallelMPC, varx crypto.CipherVector, vary crypto.CipherMatrix, nsnps int, filter []bool, debug bool) (crypto.CipherVector, crypto.CipherVector) {
	mpcObj := mpcPar[0]
	pid := mpcPar[0].GetPid()
	rtype := mpcPar[0].GetRType()
	slots := cryptoParams.GetSlots()
	useBoolean := mpcPar[0].GetBooleanShareFlag()

	npheno := len(vary)

	// Convert to SS
	varxSS := mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), varx, -1, len(varx), slots*len(varx))

	varySS := make([]mpc_core.RVec, npheno)
	for i := 0; i < npheno; i++ {
		varySS[i] = mpcObj.CiphertextToSS(cryptoParams, mpcObj.GetRType(), vary[i][0], -1, 1)
	}

	if debug && pid > 0 {
		log.LLvl1(time.Now().Format(time.RFC3339), "varxSS", mpcObj.RevealSymVec(varxSS[:5]).ToFloat(mpcObj.GetFracBits()))
		log.LLvl1(time.Now().Format(time.RFC3339), "varySS[0]", mpcObj.RevealSymVec(varySS[0]).ToFloat(mpcObj.GetFracBits()))
	}

	// Concatenate: nsnps varx values followed by npheno vary values
	varSS := mpc_core.InitRVec(rtype.Zero(), nsnps+npheno)
	if pid > 0 {
		dst := 0
		for src := range varxSS {
			if filter[src] {
				varSS[dst] = varxSS[src]
				dst++
			}
		}
	}
	for i := 0; i < npheno; i++ {
		varSS[nsnps+i] = varySS[i][0]
	}

	// Compute Sqrt Inverse
	stdinvSS := mpcPar.SqrtInv(varSS, useBoolean)

	if debug && pid > 0 {
		log.LLvl1(time.Now().Format(time.RFC3339), "varxSS", mpcObj.RevealSymVec(varxSS[:5]).ToFloat(mpcObj.GetFracBits()))
		log.LLvl1(time.Now().Format(time.RFC3339), "varSS", mpcObj.RevealSymVec(varSS[:5]).ToFloat(mpcObj.GetFracBits()))
		log.LLvl1(time.Now().Format(time.RFC3339), "stdinvxSS", mpcObj.RevealSymVec(stdinvSS[:5]).ToFloat(mpcObj.GetFracBits()))
		log.LLvl1(time.Now().Format(time.RFC3339), "stdinvySS", mpcObj.RevealSymVec(stdinvSS[nsnps:]).ToFloat(mpcObj.GetFracBits()))
	}

	// Convert stdinvx back to HE
	stdinvxSS := mpc_core.InitRVec(rtype.Zero(), len(varxSS))
	if pid > 0 {
		src := 0
		for dst := range filter {
			if filter[dst] {
				stdinvxSS[dst] = stdinvSS[src]
				src++
			}
		}
	}

	stdinvx := mpcObj.SSToCVec(cryptoParams, stdinvxSS)

	// Convert stdinvy back to HE — one ciphertext per phenotype
	stdinvy := make(crypto.CipherVector, npheno)
	for i := 0; i < npheno; i++ {
		stdinvy[i] = mpcObj.SStoCiphertext(cryptoParams, mpc_core.RVec{stdinvSS[nsnps+i]})
		if pid > 0 { // no share on party 0; SStoCiphertext left it nil
			stdinvy[i] = crypto.InnerSumAll(cryptoParams, crypto.CipherVector{stdinvy[i]})
		}
	}

	return stdinvx, stdinvy
}
