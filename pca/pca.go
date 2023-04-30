package pca

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/hcholab/sfgwas/general"
	"github.com/hcholab/sfgwas/mpc"
	mpc_core "github.com/hhcho/mpc-core"
	"github.com/ldsec/lattigo/v2/ckks"
	"go.dedis.ch/onet/v3/log"
)

type ProtocolInfo struct {
	mpcObj mpc.ParallelMPC
	cps    *crypto.CryptoParams
	config *Config
}

type Config struct {
	NumMainParties int `toml:"num_main_parties"`
	HubPartyId     int `toml:"hub_party_id"`

	CkksParams string `toml:"ckks_params"`

	DivSqrtMaxLen int `toml:"div_sqrt_max_len"`

	NumRows    []int `toml:"num_rows"`
	NumColumns int   `toml:"num_columns"`

	ItersPerEval  int `toml:"iter_per_eigenval"`
	NumPCs        int `toml:"num_pcs_to_remove"`
	NumOversample int `toml:"num_oversampling"`
	NumPowerIters int `toml:"num_power_iters"`

	BindingIP string `toml:"binding_ipaddr"`
	Servers   map[string]mpc.Server

	SharedKeysPath string `toml:"shared_keys_path"`

	InputFile string `toml:"input_file"` // for pca

	OutDir   string `toml:"output_dir"`
	CacheDir string `toml:"cache_dir"`

	MpcFieldSize     int    `toml:"mpc_field_size"`
	MpcDataBits      int    `toml:"mpc_data_bits"`
	MpcFracBits      int    `toml:"mpc_frac_bits"`
	MpcNumThreads    int    `toml:"mpc_num_threads"`
	MpcBooleanShares bool   `toml:"mpc_boolean_shares"`
	LocalNumThreads  int    `toml:"local_num_threads"`
	MemoryLimit      uint64 `toml:"memory_limit"`

	Debug bool `toml:"debug"`
}

func (prot *ProtocolInfo) GetConfig() *Config {
	return prot.config
}

func (g *ProtocolInfo) CachePath(filename string) string {
	return filepath.Join(g.config.CacheDir, filename)
}

func InitializePCAProtocol(config *Config, pid int, mpcOnly bool) (pcaProt *ProtocolInfo) {
	var chosen int
	if !mpcOnly {
		switch config.CkksParams {
		case "PN12QP109":
			chosen = ckks.PN12QP109
		case "PN13QP218":
			chosen = ckks.PN13QP218
		case "PN14QP438":
			chosen = ckks.PN14QP438
		case "PN15QP880":
			chosen = ckks.PN15QP880
		case "PN16QP1761":
			chosen = ckks.PN16QP1761
		default:
			panic("Undefined value of CKKS params in config")
		}
	}

	prec := uint(config.MpcFieldSize)
	networks := mpc.ParallelNetworks(mpc.InitCommunication(config.BindingIP, config.Servers, pid, config.NumMainParties+1, config.MpcNumThreads, config.SharedKeysPath))

	var params *ckks.Parameters
	if !mpcOnly {
		params = ckks.DefaultParams[chosen]
		for thread := range networks {
			networks[thread].SetMHEParams(params)
		}
	}

	var rtype mpc_core.RElem
	switch config.MpcFieldSize {
	case 256:
		rtype = mpc_core.LElem256Zero
	case 128:
		rtype = mpc_core.LElem128Zero
	default:
		panic("Unsupported value of MPC field size")
	}

	log.LLvl1(fmt.Sprintf("MPC parameters: bit length %d, data bits %d, frac bits %d",
		config.MpcFieldSize, config.MpcDataBits, config.MpcFracBits))
	mpcEnv := mpc.InitParallelMPCEnv(networks, rtype, config.MpcDataBits, config.MpcFracBits)
	for thread := range mpcEnv {
		mpcEnv[thread].SetHubPid(config.HubPartyId)
		mpcEnv[thread].SetBooleanShareFlag(config.MpcBooleanShares)
		mpcEnv[thread].SetDivSqrtMaxLen(config.DivSqrtMaxLen)
	}

	var cps *crypto.CryptoParams
	if !mpcOnly {
		cps = networks.CollectiveInit(params, prec)
	}

	return &ProtocolInfo{
		mpcObj: mpcEnv,
		cps:    cps,
		config: config,
	}
}

func (prot *ProtocolInfo) PCA() {
	log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: Starting Principal Component Analysis")

	mpc := prot.mpcObj[0]
	pid := mpc.GetPid()
	numRowsPCA := prot.GetConfig().NumRows[pid]
	numColumnsPCA := prot.GetConfig().NumColumns
	var dataReduced, dataReducedT *FileStream
	dataPCA := prot.CachePath("data_pca.bin")
	dataPCATranspose := prot.CachePath("data_pca_transpose.bin")

	if pid > 0 {
		if pid == mpc.GetHubPid() {
			mpc.Network.SendInt(numColumnsPCA, 0)
		}

		cmd := exec.Command("/bin/sh", "scripts/convertToBinary.sh", prot.config.InputFile, strconv.Itoa(numRowsPCA), strconv.Itoa(numColumnsPCA), dataPCA)
		cout, e := cmd.CombinedOutput()
		fmt.Print(string(cout))
		if e != nil {
			panic(e)
		}

		if _, err := os.Stat(dataPCATranspose); os.IsNotExist(err) {
			general.TransposeMatrixFile(dataPCA, numRowsPCA, numColumnsPCA, dataPCATranspose, "float64")
		} else {
			log.LLvl1("Cache file found:", dataPCATranspose)
		}

		dataReduced = NewFileStream(dataPCA, uint64(numRowsPCA), uint64(numColumnsPCA))
		dataReducedT = NewFileStream(dataPCATranspose, uint64(numColumnsPCA), uint64(numRowsPCA))

	} else { // Party 0
		numColumnsPCA = mpc.Network.ReceiveInt(mpc.GetHubPid())

		log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("Number of SNPs selected for PCA: %d", numColumnsPCA))
	}

	start := time.Now()

	log.LLvl1(time.Now().Format(time.RFC3339), "AssertSync")
	prot.mpcObj[0].AssertSync()

	Q := prot.DistributedPCA(dataReduced, dataReducedT, dataPCA, dataPCATranspose)

	log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("Finished distributed PCA, %s", time.Since(start)))
	log.LLvl1(time.Now().Format(time.RFC3339), fmt.Sprintf("PCA complete: calculated %d PCs", len(Q)))

	pcaCacheFile := prot.CachePath("Qpc.txt")
	for p := 1; p <= prot.config.NumMainParties; p++ {
		general.SaveMatrixToFile(prot.cps, prot.mpcObj[0], Q, prot.GetConfig().NumRows[p], p, pcaCacheFile)
	}
}

func (prot *ProtocolInfo) DistributedPCA(X, XT *FileStream, Xcache, XTcache string) (Q crypto.CipherMatrix) {
	debug := prot.config.Debug
	cryptoParams := prot.cps
	mpcPar := prot.mpcObj
	mpcObj := mpcPar[0]
	pid := mpcObj.GetPid()
	nrow := prot.GetConfig().NumRows[pid]
	ncol := prot.GetConfig().NumColumns

	log.LLvl1(time.Now().Format(time.RFC3339), "Distributed PCA called: numRows: ", nrow, " numColumns: ", ncol)

	rtype := mpcObj.GetRType().Zero()
	fracBits := mpcObj.GetFracBits()
	dataBits := mpcObj.GetDataBits()
	slots := cryptoParams.GetSlots()
	nRowsAll := prot.GetConfig().NumRows
	totRows := 0
	for i := range nRowsAll {
		totRows += nRowsAll[i]
	}

	npc := prot.GetConfig().NumPCs
	kp := npc + prot.GetConfig().NumOversample
	nPowerIter := prot.GetConfig().NumPowerIters

	numColSqrtInv := 1.0 / math.Sqrt(float64(ncol))
	numTotRowsSqrtInv := 1.0 / math.Sqrt(float64(totRows))

	// Mean, stdev calculation
	xsum := make([]float64, ncol)
	x2sum := make([]float64, ncol)
	bucketCount := make([]uint64, kp)
	posCount := make([]uint64, kp)

	// Sketching (ncol x nrow --> ncol x kp)
	localSketch := make([][]float64, kp)
	for i := range localSketch {
		localSketch[i] = make([]float64, ncol)
	}

	Zmat := mpc_core.InitRMat(rtype, kp, kp)
	var Qloc crypto.CipherMatrix
	var XMean, XVar, XStdInv crypto.CipherVector

	// Preprocess X
	if pid > 0 {
		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Preprocessing X")
		MatMult4StreamPreprocess(cryptoParams, X, 5, Xcache)
		MatMult4StreamPreprocess(cryptoParams, XT, 5, XTcache)
	}

	sx := mpc_core.InitRVec(rtype, ncol)
	sx2 := mpc_core.InitRVec(rtype, ncol)

	log.LLvl1(time.Now().Format(time.RFC3339), "Before sketch")
	mpcObj.AssertSync()

	if pid > 0 {
		log.LLvl1(time.Now().Format(time.RFC3339), "Sketching")

		randIndex := make([]int, nrow)
		sgn := make([]float64, nrow)

		for i := range randIndex {

			randIndex[i] = mpcObj.Network.Rand.CurPRG().Intn(kp)
			sgn[i] = float64(mpcObj.Network.Rand.CurPRG().Intn(2)*2 - 1)

			bucketCount[randIndex[i]]++
			if sgn[i] > 0 {
				posCount[randIndex[i]]++
			}
		}

		if debug {
			sgnInt := make([]int, nrow)
			for i := range sgnInt {
				if sgn[i] > 0 {
					sgnInt[i] = 1
				} else {
					sgnInt[i] = -1
				}
			}
			general.SaveIntVectorToFile(prot.CachePath("SketchSign.txt"), sgnInt)
			general.SaveIntVectorToFile(prot.CachePath("SketchBucketId.txt"), randIndex)
		}

		X.Reset()
		for i := 0; i < nrow; i++ {
			row := X.NextRow()

			for j := range row {
				localSketch[randIndex[i]][j] += sgn[i] * float64(row[j])

				xsum[j] += float64(row[j])
				x2sum[j] += float64(row[j] * row[j])
			}
		}

		Qloc, _, _, _ = crypto.EncryptFloatMatrixRow(cryptoParams, localSketch)
		Q = mpcObj.Network.AggregateCMat(cryptoParams, Qloc)

		if debug && pid > 0 {
			pv := mpcObj.Network.CollectiveDecryptVec(cryptoParams, Q[0], 1)
			log.LLvl1("Sketch:", crypto.DecodeFloatVector(cryptoParams, pv)[:5])
			general.SaveMatrixToFile(cryptoParams, mpcObj, Q, ncol, -1, prot.CachePath("Sketch.txt"))
		}

		log.LLvl1(time.Now().Format(time.RFC3339), "Local bucket counts:", bucketCount)
		bucketCount = mpcObj.Network.AggregateIntVec(bucketCount)
		posCount = mpcObj.Network.AggregateIntVec(posCount)
		log.LLvl1(time.Now().Format(time.RFC3339), "Global bucket counts:", bucketCount)

		for i := range sx {
			sx[i] = rtype.FromFloat64(xsum[i], fracBits) // fracBits or 2 * fracBits?
			sx2[i] = rtype.FromFloat64(x2sum[i], fracBits)
		}

		invN := 1.0 / float64(totRows)

		// consider making similar change as gwas/pca if using more than 30 fracbits
		sx.MulScalar(rtype.FromFloat64(invN, fracBits)) // 2*fracBits or fracBits?
		sx2.MulScalar(rtype.FromFloat64(invN, fracBits))
	}

	XMeanSS := mpcObj.TruncVec(sx, dataBits, fracBits)
	XMeanSq := mpcPar.SSSquareElemVec(XMeanSS) // E[X]^2
	sx2.Sub(XMeanSq)                           // E[X^2] - E[X]^2
	XVarSS := mpcObj.TruncVec(sx2, dataBits, fracBits)

	log.LLvl1(time.Now().Format(time.RFC3339), "Computing stdev ... m =", len(XVarSS))
	XStdInvSS := mpcPar.SqrtInv(XVarSS, prot.config.MpcBooleanShares)
	log.LLvl1(time.Now().Format(time.RFC3339), "Computing stdev finished")

	if pid > 0 {
		inRmat := mpc_core.InitRMat(rtype.Zero(), 3, slots*(1+((ncol-1)/slots)))

		copy(inRmat[0], XStdInvSS)
		copy(inRmat[1], XMeanSS)
		copy(inRmat[2], XVarSS)

		outCm := mpcObj.SSToCMat(cryptoParams, inRmat)

		XStdInv = outCm[0]
		XMean = outCm[1]
		XVar = outCm[2]
	}

	if debug {
		general.SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{XMean}, slots*len(XMean), -1, prot.CachePath("XMean.txt"))
		general.SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{XVar}, slots*len(XVar), -1, prot.CachePath("XVar.txt"))
		general.SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{XStdInv}, slots*len(XStdInv), -1, prot.CachePath("XStdInv.txt"))
	}

	if pid > 0 {
		// Normalize to reduce value range of Q
		for b := range localSketch {
			countSqrtInv := 1.0 / math.Sqrt(float64(bucketCount[b]))
			buf := make([]float64, slots)
			for i := range buf {
				buf[i] = countSqrtInv
			}
			pt, _ := crypto.EncodeFloatVector(cryptoParams, buf)

			// Cumulative weight on the mean shift (need to correct sum by meanWeight * XMean)
			meanWeight := 2*int(posCount[b]) - int(bucketCount[b])

			// Compute (Q * (1/bucketCount) - XMean) * XStdInv
			cryptoParams.WithEvaluator(func(eval ckks.Evaluator) error {
				for i := range Q[b] {
					eval.MultByConstAndAdd(XMean[i], -meanWeight, Q[b][i])
					eval.MulRelin(Q[b][i], pt[0], Q[b][i])
					eval.Rescale(Q[b][i], cryptoParams.Params.Scale(), Q[b][i])
					eval.MulRelin(Q[b][i], XStdInv[i], Q[b][i])
					eval.Rescale(Q[b][i], cryptoParams.Params.Scale(), Q[b][i])
				}
				return nil
			})
		}
	} else {
		Q = make(crypto.CipherMatrix, kp)
		Qloc = make(crypto.CipherMatrix, kp)
	}

	if debug && pid > 0 {
		pv := mpcObj.Network.CollectiveDecryptVec(cryptoParams, Q[0], 1)
		log.LLvl1(time.Now().Format(time.RFC3339), "Scaling", crypto.DecodeFloatVector(cryptoParams, pv)[:5])
		general.SaveMatrixToFile(cryptoParams, mpcObj, Q, ncol, -1, prot.CachePath("Qinit.txt"))
	}

	Q = mpcObj.Network.CollectiveBootstrapMat(cryptoParams, Q, -1)

	log.LLvl1(time.Now().Format(time.RFC3339), "Initial distributed QR, local input ", len(Q), "by", len(Q[0]), "ciphertexts")
	if pid > 0 {
		Qloc = general.QXLazyNormStream(cryptoParams, mpcObj, Q, XTcache, XMean, XStdInv, nRowsAll[pid])
		Qloc = mpcObj.Network.BootstrapMatAll(cryptoParams, Qloc)
		Qloc = crypto.CMultConstMat(cryptoParams, Qloc, numColSqrtInv, true) // scale by 1/sqrt(m)
	}

	if debug && pid > 0 {
		pv := mpcObj.Network.CollectiveDecryptVec(cryptoParams, Qloc[0], 1)
		log.LLvl1(time.Now().Format(time.RFC3339), "Before DQR", crypto.DecodeFloatVector(cryptoParams, pv)[:5])
		for outp := 1; outp < mpcObj.GetNParty(); outp++ {
			general.SaveMatrixToFile(cryptoParams, mpcObj, Qloc, nRowsAll[outp], outp, prot.CachePath("QinitX.txt"))
		}
	}

	Q = general.NetDQRenc(cryptoParams, mpcObj, Qloc, nRowsAll) // kp by nind

	if debug && pid > 0 {
		pv := mpcObj.Network.CollectiveDecryptVec(cryptoParams, Q[0], 1)
		log.LLvl1(time.Now().Format(time.RFC3339), "After DQR", crypto.DecodeFloatVector(cryptoParams, pv)[:5])
		for outp := 1; outp < mpcObj.GetNParty(); outp++ {
			general.SaveMatrixToFile(cryptoParams, mpcObj, Q, nRowsAll[outp], outp, prot.CachePath("QinitXOrth.txt"))
		}
	}

	itStart := 0

	// Power iteration
	for it := itStart; it < nPowerIter; it++ {
		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Power iteration iter ", it+1, "/", nPowerIter)

		// Compute Q*X', row-based encoding
		if pid > 0 {
			Qloc := general.QXtLazyNormStream(cryptoParams, mpcObj, Q, Xcache, XMean, XStdInv)

			Qloc = crypto.CMultConstMat(cryptoParams, Qloc, numTotRowsSqrtInv, true) // scale by 1/sqrt(n)
			Q = mpcObj.Network.AggregateCMat(cryptoParams, Qloc)
			Q = mpcObj.Network.CollectiveBootstrapMat(cryptoParams, Q, -1)
		}

		if pid > 0 {
			Qloc = general.QXLazyNormStream(cryptoParams, mpcObj, Q, XTcache, XMean, XStdInv, nRowsAll[pid])
			Qloc = mpcObj.Network.BootstrapMatAll(cryptoParams, Qloc)
			Qloc = crypto.CMultConstMat(cryptoParams, Qloc, numColSqrtInv, true) // scale by 1/sqrt(m)
		}

		if debug && pid > 0 {
			pv := mpcObj.Network.CollectiveDecryptVec(cryptoParams, Qloc[0], 1)
			log.LLvl1(time.Now().Format(time.RFC3339), "Power iter", it+1, crypto.DecodeFloatVector(cryptoParams, pv)[:5])
			for outp := 1; outp < mpcObj.GetNParty(); outp++ {
				general.SaveMatrixToFile(cryptoParams, mpcObj, Qloc, nRowsAll[outp], outp, prot.CachePath(fmt.Sprintf("QmulB_%d.txt", it)))
			}
		}

		// Skip QR in the last iteration
		if it == nPowerIter-1 {
			Q = Qloc
		} else {
			Q = general.NetDQRenc(cryptoParams, mpcObj, Qloc, nRowsAll)
		}
	}
	log.LLvl1(time.Now().Format(time.RFC3339), "Power iteration complete")

	if debug && pid > 0 {
		pv := mpcObj.Network.CollectiveDecryptVec(cryptoParams, Q[0], 1)
		log.LLvl1(time.Now().Format(time.RFC3339), "After power iter", crypto.DecodeFloatVector(cryptoParams, pv)[:5])
		for outp := 1; outp < mpcObj.GetNParty(); outp++ {
			general.SaveMatrixToFile(cryptoParams, mpcObj, Q, nRowsAll[outp], outp, prot.CachePath("Q_final.txt"))
		}
	}

	// Q contains Q*X' (kp by numRows) for each party
	// Compute local Gram matrix Q * Q'
	// TODO: be careful of the increasing data range
	if pid > 0 {

		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Computing covariance matrix")

		nct := ((kp*kp)-1)/slots + 1
		Zloc := crypto.CZeros(cryptoParams, nct)
		for i := 0; i < kp; i++ {
			for j := i; j < kp; j++ {
				inds := [2]int{i*kp + j, j*kp + i}

				iprod := crypto.InnerProd(cryptoParams, Q[i], Q[j])

				for k := range inds {
					ctid, slotid := inds[k]/slots, inds[k]%slots

					ct := crypto.Mask(cryptoParams, iprod, slotid, false)

					cryptoParams.WithEvaluator(func(eval ckks.Evaluator) error {
						eval.Add(ct, Zloc[ctid], Zloc[ctid])
						return nil
					})

					if i == j {
						break
					}
				}
			}
		}

		Z := mpcObj.Network.AggregateCVec(cryptoParams, Zloc)

		// Normalize by 1/N
		Z = crypto.CMultConst(cryptoParams, Z, 1.0/float64(totRows*1000), true) // TODO: investigate scaling

		if debug {
			general.SaveMatrixToFile(cryptoParams, mpcObj, crypto.CipherMatrix{Z}, kp*kp, -1, prot.CachePath("Zgram.txt"))
		}

		Zss := mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), Z, -1, len(Z), kp*kp)

		for i := range Zmat {
			Zmat[i] = Zss[(i * kp):((i + 1) * kp)]
		}
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Eigen decomposition")

	// Eigen decomposition
	Vss, L := mpcObj.EigenDecomp(Zmat)
	Vss, L = mpcObj.SortRowsDescend(Vss, L)
	Vss = Vss[:npc]

	if debug && pid > 0 {
		Vr := mpcObj.RevealSymMat(Vss)
		Lr := mpcObj.RevealSymVec(L)
		Vf := Vr.ToFloat(fracBits)
		for i := range Vf {
			log.LLvl1(time.Now().Format(time.RFC3339), "V[i]", i, Vf[i])
		}
		log.LLvl1(time.Now().Format(time.RFC3339), "L", Lr.ToFloat(fracBits))
	}

	V := mpcObj.SSToCMat(cryptoParams, Vss)

	if debug && pid > 0 {
		general.SaveMatrixToFile(cryptoParams, mpcObj, V, kp, -1, prot.CachePath("V.txt"))
	}

	Qpc := crypto.CZeroMat(cryptoParams, len(Q[0]), npc)
	if pid > 0 {
		log.LLvl1(time.Now().Format(time.RFC3339), "sfkit: sub-task: Extract PC subspace")

		// Extract local PC subspace by computing V*Q (npc by numInd)
		for r := range V {
			for c := range Q {
				ctid, slotid := c/slots, c%slots

				elem := crypto.Mask(cryptoParams, V[r][ctid], slotid, false)
				elem = crypto.InnerSumAll(cryptoParams, crypto.CipherVector{elem})

				cv := crypto.CMultScalar(cryptoParams, Q[c], elem)

				cryptoParams.WithEvaluator(func(eval ckks.Evaluator) error {
					for i := range cv {
						eval.Add(cv[i], Qpc[r][i], Qpc[r][i])
					}
					return nil
				})
			}
		}
	}

	log.LLvl1(time.Now().Format(time.RFC3339), "AssertSync")
	mpcObj.AssertSync()

	return Qpc
}

func (g *ProtocolInfo) SyncAndTerminate(closeChannelFlag bool) {
	mainMPCObj := g.mpcObj[0]
	pid := mainMPCObj.GetPid()

	var dummy mpc_core.RElem = mainMPCObj.GetRType().Zero()
	if pid == 0 {
		for p := 1; p < mainMPCObj.GetNParty(); p++ {
			dummy = mainMPCObj.Network.ReceiveRElem(dummy, p)
			mainMPCObj.Network.SendRData(dummy, p)
		}
	} else {
		mainMPCObj.Network.SendRData(dummy, 0)
		_ = mainMPCObj.Network.ReceiveRElem(dummy, 0)
	}

	if closeChannelFlag {
		// Close all threads
		for t := range g.mpcObj {
			g.mpcObj[t].Network.CloseAll()
		}
	}

}
