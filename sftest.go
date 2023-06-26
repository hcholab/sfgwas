package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/hcholab/sfgwas/test"
	"github.com/raulk/go-watchdog"
)

var PID, PID_ERR = strconv.Atoi(os.Getenv("PID"))
var CONFIG_PATH = "config/test"

func main() {
	RunTest()
}

func InitTestProtocol(configPath string) *test.ProtocolInfo {
	config := new(test.Config)

	if _, err := toml.DecodeFile(filepath.Join(configPath, "configGlobal.toml"), config); err != nil {
		fmt.Println(err)
		return nil
	}
	if _, err := toml.DecodeFile(filepath.Join(configPath, fmt.Sprintf("configLocal.Party%d.toml", PID)), config); err != nil {
		fmt.Println(err)
		return nil
	}

	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(config.OutDir, 0755); err != nil {
		panic(err)
	}

	runtime.GOMAXPROCS(config.LocalNumThreads)

	return test.InitializeTestProtocol(config, PID, false)
}

func RunTest() {
	if PID_ERR != nil {
		panic(PID_ERR)
	}

	// Initialize protocol
	prot := InitTestProtocol(CONFIG_PATH)

	// Invoke memory manager
	err, stopFn := watchdog.HeapDriven(prot.GetConfig().MemoryLimit, 40, watchdog.NewAdaptivePolicy(0.5))
	if err != nil {
		panic(err)
	}
	defer stopFn()

	// Run protocol
	prot.Test()

	prot.SyncAndTerminate(true)
}
