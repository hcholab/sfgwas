package pca

import (
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/simonjmendelsohn/sfgwas/crypto"
	"github.com/simonjmendelsohn/sfgwas/general"
	"go.dedis.ch/onet/v3/log"
)

func MatMult4StreamPreprocess(cryptoParams *crypto.CryptoParams, fs *FileStream, maxLevel int, cacheFilePrefix string) {
	fs.Reset() // Reset to beginning of file just in case

	slots := cryptoParams.GetSlots()
	d := int(math.Ceil(math.Sqrt(float64(slots))))

	m_ct := ((fs.NumCols() - 1) / uint64(slots)) + 1
	numBlockRows := ((fs.NumRows() - 1) / uint64(slots)) + 1
	nproc := runtime.GOMAXPROCS(0)

	log.LLvl1(time.Now().Format(time.RFC3339), "MatMult4StreamPreprocess:", "input", fs.NumRows(), fs.NumCols(), "numBlockRows", numBlockRows, "numBlockCols", m_ct)

	for bi := 0; bi < int(numBlockRows); bi++ {

		dcs, flag := general.NewDiagCacheStream(cryptoParams, cacheFilePrefix, bi, true)
		if flag {
			continue
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "gathering submatrix")

		BSlice := make([]general.BlockI8, m_ct)
		nr := general.Min((bi+1)*slots, int(fs.NumRows())) - bi*slots
		for ri := 0; ri < nr; ri++ {

			// Read one row from file
			row := fs.NextRow()

			// Add slice to each block matrix
			for bj := range BSlice {
				j1 := bj * slots
				j2 := general.Min((bj+1)*slots, int(fs.NumCols()))
				nc := j2 - j1
				if ri == 0 {
					BSlice[bj] = general.NewBlockI8(nr, nc)
				}
				BSlice[bj].Data[ri] = row[j1:j2]
			}
		}

		blockVec := make(general.BlockVector, m_ct)
		for bj := range blockVec {
			blockVec[bj] = general.Block(BSlice[bj])
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "finding active diagonals")

		// Pre-collect active baby/giant indices
		babyTable := make([]bool, d)
		giantTable := make([]bool, d)
		shiftTable := make([]bool, slots)
		for shift := 0; shift < slots; shift++ {
			if general.EncodeDiagBool(blockVec, -shift, slots) {
				baby, giant := shift%d, shift/d
				babyTable[baby] = true
				giantTable[giant] = true
				shiftTable[shift] = true
			}
		}

		dcs.SetIndexTables(babyTable, giantTable)

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "extracting and caching diagonals")

		type dataItem struct {
			plainVec crypto.PlainVector
			shift    int
		}

		jobChannels := make([]chan int, nproc)
		for i := range jobChannels {
			jobChannels[i] = make(chan int, 32)
		}

		diagChannel := make(chan dataItem, 16)

		// Job feeder
		go func() {
			for shift, flag := range shiftTable {
				if flag {
					jobChannels[shift%nproc] <- shift
				}
			}
			for _, c := range jobChannels {
				close(c)
			}
		}()

		// Data writer
		var writer sync.WaitGroup
		writer.Add(1)
		go func() {
			defer writer.Done()
			for item := range diagChannel {
				dcs.WriteDiag(item.plainVec, uint32(item.shift))
			}
		}()

		// Data encoders
		var encoderGroup sync.WaitGroup
		for thread := 0; thread < nproc; thread++ {
			encoderGroup.Add(1)
			go func(thread int) {
				defer encoderGroup.Done()

				enc := ckks.NewEncoderBig(cryptoParams.Params, cryptoParams.GetPrec())

				for shift := range jobChannels[thread] {
					_, giant := shift%d, shift/d

					plainVec, _ := general.EncodeDiagWithEncoder(cryptoParams, blockVec, -shift, d*giant, maxLevel, enc)

					general.ToMontgomeryForm(cryptoParams, plainVec)

					diagChannel <- dataItem{plainVec, shift}
				}
			}(thread)
		}

		encoderGroup.Wait()
		close(diagChannel)

		writer.Wait()
		dcs.Close()
	}
}

func MatMult4Stream(cryptoParams *crypto.CryptoParams, A crypto.CipherMatrix, fs *FileStream, maxLevel int, computeSquaredSum bool, nproc int) (crypto.CipherMatrix, []float64, []float64) {
	fs.Reset() // Reset to beginning of file just in case

	nrow, ncol := fs.NumRows(), fs.NumCols()
	if nproc <= 0 { // If nproc is non-positive, use all cores
		nproc = runtime.GOMAXPROCS(0)
	}

	s := len(A)
	outScale := A[0][0].Scale() * cryptoParams.Params.Scale()
	slots := cryptoParams.GetSlots()
	d := int(math.Ceil(math.Sqrt(float64(slots))))

	//blockB := ToBlockMatrix(B, slots)
	//fmt.Println("blockB dims:", len(blockB), len(blockB[0]))
	m_ct := ((ncol - 1) / uint64(slots)) + 1
	numBlockRows := ((nrow - 1) / uint64(slots)) + 1

	if A[0][0].Level() > maxLevel {
		fmt.Println("Dropping level. Input:", A[0][0].Level())
		A = crypto.DropLevel(cryptoParams, A, maxLevel)
	}
	fmt.Println("A level:", A[0][0].Level())

	accCache := make([][]general.CipherVectorAccV2, s)
	accCacheMux := make([][]sync.Mutex, s)
	for i := range accCache {
		accCache[i] = make([]general.CipherVectorAccV2, d) // Cache each of the sqrt(slots) groups, initialize later on-the-fly
		accCacheMux[i] = make([]sync.Mutex, d)
	}

	rotCache := make(crypto.CipherMatrix, s)
	for i := range rotCache {
		rotCache[i] = make(crypto.CipherVector, d)
	}

	var sqSum, sum []float64
	if computeSquaredSum {
		sqSum = make([]float64, ncol)
		sum = make([]float64, ncol)
	}

	for bi := 0; bi < int(numBlockRows); bi++ {

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "gathering submatrix")

		BSlice := make([]general.BlockI8, m_ct)
		nr := general.Min((bi+1)*slots, int(nrow)) - bi*slots
		for ri := 0; ri < nr; ri++ {

			// Read one row from file
			row := fs.NextRow()

			// Replace missing with zeros
			for rj := range row {
				if row[rj] < 0 {
					row[rj] = 0
				}

				if computeSquaredSum {
					sqSum[rj] += float64(row[rj] * row[rj])
					sum[rj] += float64(row[rj])
				}
			}

			// Add slice to each block matrix
			for bj := range BSlice {
				j1 := bj * slots
				j2 := general.Min((bj+1)*slots, int(ncol))
				nc := j2 - j1
				if ri == 0 {
					BSlice[bj] = general.NewBlockI8(nr, nc)
				}
				BSlice[bj].Data[ri] = row[j1:j2]
			}
		}

		blockVec := make(general.BlockVector, m_ct)
		for bj := range blockVec {
			blockVec[bj] = general.Block(BSlice[bj])
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "finding active diagonals")

		// Pre-collect active baby/giant indices
		babyTable := make([]bool, d)
		giantTable := make([]bool, d)
		shiftTable := make([]bool, slots)
		for shift := 0; shift < slots; shift++ {
			if general.EncodeDiagBool(blockVec, -shift, slots) {
				baby, giant := shift%d, shift/d
				babyTable[baby] = true
				giantTable[giant] = true
				shiftTable[shift] = true
			}
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "generating rotation cache")

		log.LLvl1(time.Now().Format(time.RFC3339), "Num procs", nproc)

		// Dispatcher
		jobChannels := make([]chan int, nproc)
		for i := range jobChannels {
			jobChannels[i] = make(chan int, 64)
		}
		go func() {
			index := 0
			for baby, flag := range babyTable {
				if flag {
					jobChannels[index%nproc] <- baby
					index++
				}
			}
			for _, c := range jobChannels {
				close(c)
			}
		}()

		// Workers
		var workerGroup sync.WaitGroup
		Aslice := make(crypto.CipherVector, len(A))
		for i := range A {
			Aslice[i] = A[i][bi]
		}
		for thread := 0; thread < nproc; thread++ {
			workerGroup.Add(1)
			go func(thread int) {
				defer workerGroup.Done()

				eva := ckks.NewEvaluator(cryptoParams.Params, ckks.EvaluationKey{Rlk: cryptoParams.Rlk, Rtks: cryptoParams.RotKs})

				for baby := range jobChannels[thread] {
					for i := range A {
						rotCache[i][baby] = crypto.RotateRightWithEvaluator(cryptoParams, Aslice[i], -baby, eva)
					}
				}
			}(thread)
		}
		workerGroup.Wait()

		for giant, flag := range giantTable {
			if flag {
				for i := range A {
					if accCache[i][giant].Val == nil {
						accCache[i][giant] = general.NewCipherVectorAccV2(cryptoParams, int(m_ct), maxLevel)
					}
				}
			}
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Block row", bi+1, "/", numBlockRows, "extracting and multiplying diagonals")

		// Extract and encode diagonal vectors
		shiftChannels := make([]chan int, nproc)
		for i := range shiftChannels {
			shiftChannels[i] = make(chan int, 128)
		}

		go func() {
			index := 0
			for shift, flag := range shiftTable {
				if flag {
					if (index+1)%1000 == 0 {
						log.LLvl1(index + 1)
					}
					shiftChannels[index%nproc] <- shift
					index++
				}
			}
			for _, c := range shiftChannels {
				close(c)
			}
		}()

		for thread := 0; thread < nproc; thread++ {
			workerGroup.Add(1)
			go func(thread int) {
				defer workerGroup.Done()

				enc := ckks.NewEncoderBig(cryptoParams.Params, cryptoParams.GetPrec())

				for shift := range shiftChannels[thread] {
					baby, giant := shift%d, shift/d

					plainVec, _ := general.EncodeDiagWithEncoder(cryptoParams, blockVec, -shift, d*giant, maxLevel, enc)

					general.ToMontgomeryForm(cryptoParams, plainVec)

					for i := range A {
						accCacheMux[i][giant].Lock()
						general.CPMultAccWithoutMRedV2(crypto.CipherVector{rotCache[i][baby]}, plainVec, accCache[i][giant])
						accCacheMux[i][giant].Unlock()
					}
				}
			}(thread)
		}
		workerGroup.Wait()
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "Postprocessing accumulators")

	out := crypto.CZeroMat(cryptoParams, int(m_ct), s)
	for i := range out {
		jobChannels := make([]chan int, nproc)
		for j := range jobChannels {
			jobChannels[j] = make(chan int, 32)
		}

		go func() {
			for l := range accCache[i] {
				if accCache[i][l].Val != nil {
					jobChannels[l%nproc] <- l
				}
			}
			for _, c := range jobChannels {
				close(c)
			}
		}()

		aggChannel := make(chan crypto.CipherVector, 8)

		var wg sync.WaitGroup
		for thread := 0; thread < nproc; thread++ {
			wg.Add(1)
			go func(thread int) {
				defer wg.Done()

				eva := ckks.NewEvaluator(cryptoParams.Params, ckks.EvaluationKey{Rlk: cryptoParams.Rlk, Rtks: cryptoParams.RotKs})

				for l := range jobChannels[thread] {
					cv := general.ModularReduceV2(cryptoParams, accCache[i][l], outScale)

					if l > 0 { // Giant step alignment
						for j := range cv {
							cv[j] = crypto.RotateRightWithEvaluator(cryptoParams, cv[j], -l*d, eva)
						}
					}

					aggChannel <- cv
				}
			}(thread)
		}

		var aggGroup sync.WaitGroup
		aggGroup.Add(1)
		go func() {
			defer aggGroup.Done()

			eva := ckks.NewEvaluator(cryptoParams.Params, ckks.EvaluationKey{Rlk: cryptoParams.Rlk, Rtks: cryptoParams.RotKs})

			for cv := range aggChannel {
				for j := range cv {
					eva.Add(out[i][j], cv[j], out[i][j])
				}
			}
		}()

		wg.Wait()
		close(aggChannel)
		aggGroup.Wait()
	}

	return out, sum, sqSum
}
