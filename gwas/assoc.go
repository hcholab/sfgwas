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
			var snpFilt []bool
			if gwasParams.snpFilt == nil {
				snpFilt = make([]bool, blockSize)
				for i := range snpFilt {
					snpFilt[i] = true
				}
			} else {
				snpFilt = gwasParams.snpFilt[shift : shift+uint64(blockSize)]
			}

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

	// applyCTAdditive is applyCT's counterpart for callers that hold their own
	// additive share of the target matrix in plaintext (e.g. GenoBlockMultPlain's
	// per-party local product) instead of an already-aggregated ciphertext, so it
	// encrypts internally rather than taking a CipherMatrix.
	applyCTAdditive func([][]float64) crypto.CipherMatrix
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
	ncov := len(ZtZss)

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

			// Sss is always rescaled back to the standard fracBits before being returned
			// above (both branches), regardless of revealFracBits/hiPrec -- unlike Lss/LinvSs,
			// which stay at whatever precision they were computed at.
			Sr := mpcObj.RevealSymMat(Sss).ToFloat(fracBits)
			SaveFloatMatrixToFileRowMajor(ast.general.CachePath("cholesky_S.txt"), Sr)
		}

		// ###### DEBUG ######
		// log.LLvl1("## DEBUG Replacing Sss with plaintext matrices for testing ##")
		// rtype := mpcObj.GetRType()
		// Sss = mpc_core.InitRMat(rtype.Zero(), len(ZtZss), len(ZtZss))
		// var Sfloat [][]float64
		// if pid > 0 {
		// 	Sfloat = LoadMatrixFromFileFloat(ast.general.CachePath("cholesky_S_truth.txt"), ',')
		// 	log.LLvl1("## DEBUG", len(Sfloat), "rows, ", len(Sfloat[0]), "cols")

		// 	for i := range Sss {
		// 		for j := range Sss[i] {
		// 			if pid == 1 {
		// 				Sss[i][j] = rtype.FromFloat64(Sfloat[i][j], fracBits)
		// 			} else {
		// 				Sss[i][j] = rtype.Zero().Copy()
		// 			}
		// 		}
		// 		log.LLvl1("## DEBUG Sfloat", Sfloat[i][:5])
		// 	}
		// }
		// ###################

		Sct := mpcObj.SSToCMat(cryptoParams, Sss)

		// Sct is the ciphertext conversion of Sss actually used by applyCT (unlike
		// cholesky_S.txt, which reveals Sss directly via the SS-domain RevealSymMat path
		// that applySS uses instead). If SSToCMat introduces an error that RevealSymMat
		// doesn't, this diverges from cholesky_S.txt even though both claim to be S.
		if debug && pid > 0 {
			SaveMatrixToFile(cryptoParams, mpcObj, Sct, len(Sss), -1, ast.general.CachePath("cholesky_Sct.txt"))
		}

		return covOrthoFactor{
			applySS: func(A mpc_core.RMat) mpc_core.RMat {
				R := mpcObj.SSMultMat(Sss, A)
				return mpcObj.TruncMat(R, dataBits, fracBits)
			},
			applyCT: func(A crypto.CipherMatrix) crypto.CipherMatrix {
				if pid == 0 {
					return A
				}

				Adec := mpcObj.Network.CollectiveDecryptMat(cryptoParams, A, 1)
				Sdec := mpcObj.Network.CollectiveDecryptMat(cryptoParams, Sct, 1)

				Sfloat := make([][]float64, len(Sdec))
				for i := range Sdec {
					row := make([]float64, 0, len(Sdec[i])*cryptoParams.GetSlots())
					for j := range Sdec[i] {
						row = append(row, crypto.DecodeFloatVector(cryptoParams, crypto.PlainVector{Sdec[i][j]})...)
					}
					Sfloat[i] = row[:ncov]
				}

				Afloat := make([][]float64, len(Adec))
				for i := range Adec {
					row := make([]float64, 0, len(Adec[i])*cryptoParams.GetSlots())
					for j := range Adec[i] {
						row = append(row, crypto.DecodeFloatVector(cryptoParams, crypto.PlainVector{Adec[i][j]})...)
					}
					Afloat[i] = row
				}

				Smat := mat.NewDense(len(Sfloat), len(Sfloat[0]), nil)
				for i := range Sfloat {
					// Smat.SetRow(i, Sfloat[i])
					for j := 0; j <= i; j++ {
						Smat.Set(i, j, Sfloat[i][j])
					}
				}

				Aflat := mat.NewDense(len(Afloat), len(Afloat[0]), nil)
				for i := range Afloat {
					Aflat.SetRow(i, Afloat[i])
				}

				out := mat.NewDense(len(Sfloat), len(Afloat[0]), nil)
				out.Mul(Smat, Aflat)

				outFloat := make([][]float64, len(Sfloat))
				for i := range outFloat {
					outFloat[i] = append([]float64(nil), out.RawRowView(i)...)
				}

				Aenc, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, outFloat)
				Aenc = mpcObj.Network.BroadcastCMat(cryptoParams, Aenc, 1, len(Aenc), len(Aenc[0]))
				return Aenc
			},
			applyCTAdditive: func(APlain [][]float64) crypto.CipherMatrix {
				// S (Sct) is ncov-by-ncov lower-triangular (S = scaling * L^{-1}, and the
				// inverse of a lower-triangular L is lower-triangular), so row i of S*A only
				// depends on rows 0..i of A. Encrypt A's covariate rows once, then for each
				// output row i, restrict both operands to the nonzero prefix: a 1-row slice
				// of S and A's first i+1 encrypted rows. This is CMultMatRowTimesRow's usual
				// contract (N i-by-k, M k-by-m) with N and M's shared/k dimension cut down
				// from ncov to i+1, which is exactly where that function's cost comes from
				// (masking+replicating one element of N per row of M).

				// Aenc, _, _, err := crypto.EncryptFloatMatrixRow(cryptoParams, APlain[:ncov])
				Aenc, _, _, err := crypto.EncodeFloatMatrixRow(cryptoParams, APlain[:ncov])
				if err != nil {
					panic(err)
				}

				result := make(crypto.CipherMatrix, ncov)
				for i := 0; i < ncov; i++ {
					Si := crypto.CipherMatrix{Sct[i]}
					// out := CMultMatRowTimesRow(cryptoParams, Si, Aenc[:i+1], numThreads)
					out := CPMultMatRowTimesRow(cryptoParams, Si, Aenc[:i+1], numThreads)
					result[i] = out[0]
				}

				// APlain is this party's own additive share of the target matrix, not the
				// value itself, so S*APlain is only this party's share of S*A. S*(Ξ£β‚šAβ‚š) =
				// Ξ£β‚š(S*Aβ‚š) by linearity, so summing every party's local S*APlain across the
				// network reconstructs the same S*A that applyCT computes from an
				// already-aggregated input -- just with the aggregation moved after the
				// (now cheaper, triangular) multiply instead of before it.
				return mpcObj.Network.AggregateCMat(cryptoParams, result)
			},
		}
	}

	rtype := mpcObj.GetRType()
	useBoolean := mpcObj.GetBooleanShareFlag()

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
		applyCTAdditive: func(APlain [][]float64) crypto.CipherMatrix {
			// Unlike Cholesky's S, V isn't triangular, so there's no nonzero-prefix
			// shortcut here -- just encrypt and reuse applyCT's full product.
			Aenc, _, _, err := crypto.EncryptFloatMatrixRow(cryptoParams, APlain[:ncov])
			if err != nil {
				panic(err)
			}
			B := CMultMatRowTimesRow(cryptoParams, Vt, Aenc, numThreads)
			for i := range B {
				B[i] = crypto.CMultScalar(cryptoParams, B[i], LsqrtInv[i])
			}
			// APlain is this party's local additive share; sum every party's local B
			// across the network to reconstruct the true S*A (see the Cholesky branch's
			// applyCTAdditive for why this is valid).
			return mpcObj.Network.AggregateCMat(cryptoParams, B)
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
	dataBits := mpcObj.GetDataBits()

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

	// Standardize Zt (covariates)
	if !covAllOnes {
		z1Local := mat.NewDense(1, ncov, nil)
		zz1Local := mat.NewDense(1, ncov, nil)
		if pid > 0 {
			for i := 0; i < ncov; i++ {
				row := Zt.RawRowView(i)

				z1Local.Set(0, i, floats.Sum(row)/float64(nrowsTotal))
				zz1Local.Set(0, i, floats.Dot(row, row)/float64(nrowsTotal))
			}
		}
		z1ss := mpc.DenseToRMat(rtype, z1Local, fracBits)[0]
		zz1ss := mpc.DenseToRMat(rtype, zz1Local, fracBits)[0]
		z1 := mpcObj.RevealSymVec(z1ss).ToFloat(fracBits)
		zz1 := mpcObj.RevealSymVec(zz1ss).ToFloat(fracBits)
		for i := 0; i < ncov; i++ {
			zz1[i] = math.Sqrt(zz1[i] - z1[i]*z1[i])
		}
		for i := 0; i < ncov; i++ {
			floats.AddConst(-z1[i], Zt.RawRowView(i))
			floats.Scale(10.0/zz1[i], Zt.RawRowView(i))
		}
	}

	// Secret-shared mean of covariates (ncov-by-1), used for lazy mean-centering when no
	// explicit all-ones covariate is present. Each party's local column sum, already divided
	// by the (public) total sample count before fixed-point encoding, is directly a valid
	// additive share of the true global mean -- no MPC truncation required, since the division
	// happens in plaintext, unlike a post-hoc SS multiply by a fractional constant.
	var mu mpc_core.RMat
	if !covAllOnes {
		log.LLvl1("Computing covariate means for lazy mean-centering (no explicit all-ones covariate added)")

		z1Local := mat.NewDense(ncov, 1, nil)
		if pid > 0 {
			for i := 0; i < ncov; i++ {
				z1Local.Set(i, 0, floats.Sum(Zt.RawRowView(i))*nrowsTotalInv)
			}
		}
		mu = mpc.DenseToRMat(rtype, z1Local, fracBits)

		if debug && pid > 0 {
			SaveFloatMatrixToFileRowMajor(ast.general.CachePath("mu.txt"), mpcObj.RevealSymMat(mu).ToFloat(fracBits))
		}

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

	// ZtZ is the earliest checkpoint in the covariate-orthogonalization chain -- dumped
	// before it's decomposed at all, so a divergence here isolates to how ZtZ itself was
	// formed (data/QC/individual-count mismatch) rather than to Cholesky or anything
	// downstream of it. Compare against oracle_ZtZ.txt.
	if debug && pid > 0 {
		ZtZr := mpcObj.RevealSymMat(ZtZss).ToFloat(fracBits)
		SaveFloatMatrixToFileRowMajor(ast.general.CachePath("ZtZ.txt"), ZtZr)
	}

	// Mean-center ZtZ: Z0tZ0 = ZtZ - n*mu*muT (see derivation notes). ZtZss already carries the
	// 1/sqrt(n) scaling from the SymOuterK call above, so the correction term needs the matching
	// sqrt(n) factor (n/sqrt(n)) rather than a bare n.
	ZtZcss := ZtZss.Copy()
	if !covAllOnes {
		muScaled := mu.Copy()
		muScaled.MulScalar(rtype.FromFloat64(math.Sqrt(float64(nrowsTotal)), fracBits))
		muScaled = mpcObj.TruncMat(muScaled, dataBits, fracBits)

		muOuter := mpcObj.SSMultMat(muScaled, mu.Transpose())
		muOuter = mpcObj.TruncMat(muOuter, dataBits, fracBits)

		ZtZcss.Sub(muOuter)
	}
	covOrtho := ast.computeCovOrthoFactor(cryptoParams, ZtZcss, scaling, hiPrec, numThreads)

	ZtZss = nil

	// Smu = S*mu, computed once here (for all parties, including party 0) so the per-block
	// mean-centering of B below never has to touch the interactive SSMultMat/TruncMat
	// protocol -- party 0 never enters that per-block loop (see the pid==0 branch below),
	// so any Beaver-style secret-shared multiply placed inside it would deadlock: party 0
	// would never show up to distribute its side of the masking/randomness those protocols
	// require (see TruncMat's and BeaverReconstructMat's own pid==0 branches), while parties
	// 1/2 block forever waiting for it. One ciphertext per covariate, each holding its scalar
	// replicated across all slots, mirrors how computeCovOrthoFactor turns LsqrtInv into
	// per-block-safe ciphertexts for the same reason.
	var SmuCT crypto.CipherVector
	if !covAllOnes {
		Smu := covOrtho.applySS(mu)

		if debug && pid > 0 {
			Smur := mpcObj.RevealSymMat(Smu).ToFloat(fracBits)
			SaveFloatMatrixToFileRowMajor(ast.general.CachePath("Smu.txt"), Smur)
		}

		SmuCT = crypto.CZeros(cryptoParams, ncov)
		for i := range SmuCT {
			rv := mpc_core.InitRVec(Smu[i][0], slots)
			SmuCT[i] = mpcObj.SStoCiphertext(cryptoParams, rv)
		}
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "Calculating inverse of covariate covariance matrix: finished")

	var varx, sx, sxx, xtxdiag crypto.CipherVector
	var vary, sy, sxy, ztx, qtx crypto.CipherMatrix
	var nsnps, numCtx int
	var outFilter []bool

	// ZtY is scaled by 1/sqrt(n) to match ZtZss's pre-existing scaling (required for
	// QtY = S*ZtY/sqrt(n) to be a properly normalized projection, QᵀQ = I -- see comment above
	// computeCovOrthoFactor's "scaling" factor). When !covAllOnes, Ysum gets the same 1/sqrt(n)
	// factor, since it feeds the muYsum centering term below.
	var ZtYss mpc_core.RMat
	var YsumMatss mpc_core.RMat // 1-by-npheno; unused when covAllOnes
	if pid > 0 {
		var ZtY mat.Dense
		ZtY.Mul(Zt, Yt.T())
		ZtY.Scale(nrowsTotalInvSqrt, &ZtY)
		ZtYss = mpc.DenseToRMat(rtype, &ZtY, fracBits)

		if !covAllOnes {
			Ysum := mat.NewDense(1, npheno, nil)
			for i := 0; i < npheno; i++ {
				Ysum.Set(0, i, floats.Sum(Yt.RawRowView(i))*nrowsTotalInvSqrt)
			}
			YsumMatss = mpc.DenseToRMat(rtype, Ysum, fracBits)
		}
	} else {
		ZtYss = mpc_core.InitRMat(rtype.Zero(), ncov, npheno)
		if !covAllOnes {
			YsumMatss = mpc_core.InitRMat(rtype.Zero(), 1, npheno)
		}
	}

	QtYss := covOrtho.applySS(ZtYss)
	if !covAllOnes {
		// Lazy mean centering: QtY is the projection against the uncentered covariates;
		// subtract S*mu*Ysum/sqrt(n) to land on the centered ones. QtY stays ncov-by-npheno
		// throughout -- unlike the covAllOnes path, there is no extra row for the intercept,
		// since Q here is built purely from centered covariates and never spans it (see the
		// sx/sy comments below for why that's fine).
		muYsumss := mpcObj.SSMultMat(mu, YsumMatss)
		muYsumss = mpcObj.TruncMat(muYsumss, dataBits, fracBits)
		centering := covOrtho.applySS(muYsumss)
		QtYss.Sub(centering)
	}

	// QtY = QᵀY is the covariate projection applied to phenotypes -- the same S-application
	// step as the per-block QtX (qtx.txt) below, but computed once, so it's cheap to dump and
	// a useful earlier checkpoint:
	// if this already diverges, the bug is in S/applySS itself, not in anything specific to
	// genotype blocks.
	if debug && pid > 0 {
		QtYr := mpcObj.RevealSymMat(QtYss).ToFloat(fracBits)
		SaveFloatMatrixToFileRowMajor(ast.general.CachePath("QtY.txt"), QtYr)
	}

	YtQss := QtYss.Transpose()
	YtQ := mpcObj.SSToCMat(cryptoParams, YtQss)

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

		// Debug-only checkpoints bracketing the S-application step: ztxBlocks is B's
		// input (ZtXscaled, before applyCT), qtxBlocks is B itself (after applyCT), and
		// xtxBlocks is diag(XtX) before the BtB subtraction that turns it into sxx. Diffed
		// against the oracle's own ztx/qtx/xtxdiag dumps, these isolate a divergence to
		// before S is applied, to the S-multiply itself, or to the final BtB subtraction.
		var ztxBlocks, qtxBlocks, xtxBlocks []crypto.CipherMatrix
		if debug {
			ztxBlocks = make([]crypto.CipherMatrix, numBlocks)
			qtxBlocks = make([]crypto.CipherMatrix, numBlocks)
			xtxBlocks = make([]crypto.CipherMatrix, numBlocks)
		}

		for b := 0; b < numBlocks; b++ {
			if !ast.general.IsBlockForAssocTest(b) {
				log.LLvl1(time.Now().Format(time.RFC3339), "MatMult: block", b+1, "/", numBlocks, "skipped")
			} else {
				matOut, dosageSum, dosageSqSum, filt := ast.GenoBlockMultPlain(b, matIn)
				if matOut == nil {
					continue
				}

				log.LLvl1(time.Now().Format(time.RFC3339), "block", b+1, "/", numBlocks, "computed genotype matrix mult")

				matOutEnc, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, matOut)
				matOutEnc = mpcObj.Network.AggregateCMat(cryptoParams, matOutEnc)

				numCtx = len(matOutEnc[0])

				ZtXscaled := matOutEnc[:ncov]
				YtX := matOutEnc[ncov:]

				OnetX, _ := crypto.EncryptFloatVector(cryptoParams, dosageSum)
				OnetX = mpcObj.Network.AggregateCVec(cryptoParams, OnetX)

				OnetXsq, _ := crypto.EncryptFloatVector(cryptoParams, dosageSqSum)
				OnetXsq = mpcObj.Network.AggregateCVec(cryptoParams, OnetXsq)

				if debug {
					// Snapshot before the BtB-subtraction loop below mutates OnetXsq in
					// place (evaluator.Sub writes into sxxBlocks[b][0], which IS OnetXsq).
					xtxBlocks[b] = crypto.CipherMatrix{crypto.CopyEncryptedVector(OnetXsq)}
				}

				// Compute B = QᵀX = S * (ZᵀX - mu*Xsum) / sqrt(n)
				B := covOrtho.applyCTAdditive(matOut)

				if !covAllOnes {
					// Lazy mean centering: subtract Smu*(1ᵀX) from B. Pure ciphertext ops --
					// no Beaver protocol here, see SmuCT's construction above for why.
					for i := range B {
						B[i] = crypto.CSub(cryptoParams, B[i], crypto.CMultScalar(cryptoParams, OnetX, SmuCT[i]))
					}
				}

				// Scale by 1/sqrt(n) to match ZtZss's pre-existing scaling (see QtY above).
				// Applied once here (rather than pre-scaling matOut/dosageSum) since it
				// distributes the same way over the subtraction above.
				B = crypto.CMultConstMat(cryptoParams, B, nrowsTotalInvSqrt, true)

				if debug {
					ztxBlocks[b] = ZtXscaled
					qtxBlocks[b] = B
				}

				// Compute sx = 1ᵀ(I - QQᵀ)X = 1ᵀX - (1ᵀQ)(QᵀX)
				if covAllOnes {
					// The supplied covariates already include an explicit all-ones row, so 1
					// lies entirely within Q's span and (I - QQᵀ) annihilates it.
					sxBlocks[b] = crypto.CipherMatrix{crypto.CZeros(cryptoParams, numCtx)}
					log.LLvl1(time.Now().Format(time.RFC3339), "sx set to zero")
				} else {
					// Q here is built purely from mean-centered covariates (1ᵀZ0 = 0 exactly),
					// so 1ᵀQ = 0 identically -- the (1ᵀQ)(QᵀX) term is always exactly zero, and
					// sx is just the raw dosage sum.
					sxBlocks[b] = crypto.CipherMatrix{OnetX}
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

		if debug {
			ztx = crypto.ConcatCipherMatrix(ztxBlocks)
			qtx = crypto.ConcatCipherMatrix(qtxBlocks)
			xtxdiag = crypto.ConcatCipherMatrix(xtxBlocks)[0]
			ztxBlocks, qtxBlocks, xtxBlocks = nil, nil, nil
		}

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
			// See the matching sx branch above: 1 is already in Q's span, so this is
			// exactly zero.
			sy = make(crypto.CipherMatrix, npheno)
			for i := 0; i < npheno; i++ {
				sy[i] = crypto.CZeros(cryptoParams, 1)
			}
			log.LLvl1(time.Now().Format(time.RFC3339), "sy set to zero")
		} else {
			// 1ᵀQ = 0 identically (see the sx comment above), so sy is just the raw
			// phenotype sum -- no (1ᵀQ)(QᵀY) term to compute or subtract.
			sy = make(crypto.CipherMatrix, npheno)
			buffer := make([]float64, slots)
			for i := 0; i < npheno; i++ {
				Ysum := floats.Sum(Yt.RawRowView(i))
				for j := range buffer {
					buffer[j] = Ysum
				}
				OnetYloc, _ := crypto.EncryptFloatVector(cryptoParams, buffer)
				sy[i] = mpcObj.Network.AggregateCVec(cryptoParams, OnetYloc)
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

			// ztx/qtx bracket the S-application step (see the ztxBlocks/qtxBlocks comment
			// above); xtxdiag is diag(XtX) before the BtB subtraction that produces sxx.
			// Same numCtx*slots padding as sxx.txt -- use xfilt.bin to drop it. ztx/qtx
			// have ncov rows (one SaveMatrixToFile call each, like sxy's npheno rows).
			SaveMatrixToFile(cryptoParams, mpcObj, ztx, len(ztx[0])*slots, -1, ast.general.CachePath("ztx.txt"))                               // (ZtX)/sqrt(n), pre-S
			SaveMatrixToFile(cryptoParams, mpcObj, qtx, len(qtx[0])*slots, -1, ast.general.CachePath("qtx.txt"))                               // B = QtX, post-S
			SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{xtxdiag}, len(xtxdiag)*slots, -1, ast.general.CachePath("xtxdiag.txt")) // diag(XtX), pre-BtB
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
