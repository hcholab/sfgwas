package test

import (
	"fmt"
	"time"

	"github.com/hcholab/sfgwas/crypto"
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

	BindingIP string `toml:"binding_ipaddr"`
	Servers   map[string]mpc.Server

	SharedKeysPath string `toml:"shared_keys_path"`

	OutDir   string `toml:"output_dir"`
	CacheDir string `toml:"cache_dir"`

	MpcFieldSize     int    `toml:"mpc_field_size"`
	MpcDataBits      int    `toml:"mpc_data_bits"`
	MpcFracBits      int    `toml:"mpc_frac_bits"`
	MpcNumThreads    int    `toml:"mpc_num_threads"`
	MpcBooleanShares bool   `toml:"mpc_boolean_shares"`
	LocalNumThreads  int    `toml:"local_num_threads"`
	MemoryLimit      uint64 `toml:"memory_limit"`
}

func InitializeTestProtocol(config *Config, pid int, mpcOnly bool) (testProtocol *ProtocolInfo) {
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

	prec := uint(config.MpcFieldSize) // precision of the MPC field
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

func (prot *ProtocolInfo) GetConfig() *Config {
	return prot.config
}

func (prot *ProtocolInfo) Test() {
	log.LLvl1(time.Now().Format(time.RFC3339), "AssertSync")
	prot.mpcObj[0].AssertSync()

	fmt.Print("\n\nTesting basic MHE and MPC functionality:\n\n")
	pid := prot.mpcObj[0].GetPid()
	cryptoParams := prot.cps

	if pid != 0 {
		// MHE test
		fmt.Println("MHE test")

		testMat := make([][]float64, 2)
		for i := range testMat {
			testMat[i] = make([]float64, 2)
		}
		testMat[0][0] = float64(pid)
		testMat[0][1] = float64(pid)
		testMat[1][0] = float64(pid)
		testMat[1][1] = float64(pid)
		log.LLvl1("Original matrix: ", testMat[0], testMat[1])

		encryptedMat, _, _, _ := crypto.EncryptFloatMatrixRow(cryptoParams, testMat)
		log.LLvl1("Encrypted matrix: ", encryptedMat[0], encryptedMat[1])

		aggregatedMat := prot.mpcObj[0].Network.AggregateCMat(cryptoParams, encryptedMat)
		log.LLvl1("Aggregated matrix: ", aggregatedMat[0], aggregatedMat[1])

		decryptedMat := prot.mpcObj[0].Network.CollectiveDecryptMat(cryptoParams, aggregatedMat, 1)
		log.LLvl1("Decrypted matrix: ", decryptedMat[0], decryptedMat[1])

		vec1 := crypto.DecodeFloatVector(cryptoParams, decryptedMat[0])
		vec2 := crypto.DecodeFloatVector(cryptoParams, decryptedMat[1])
		log.LLvl1("Decoded matrix: ", vec1[:2], vec2[:2])

		// MPC test
		fmt.Println("MPC test")

		mpcMat := mpc_core.InitRMat(prot.mpcObj[0].GetRType(), 2, 2)
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				mpcMat[i][j] = prot.mpcObj[0].GetRType().FromInt(pid)
			}
		}
		log.LLvl1("Original matrix: ", mpcMat[0], mpcMat[1])

		revealedMat := prot.mpcObj[0].RevealSymMat(mpcMat)
		log.LLvl1("Revealed matrix: ", revealedMat[0], revealedMat[1])

	}
	fmt.Print("\n\nFinished tests\n\n")
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
