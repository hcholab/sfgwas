package unittests

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/ldsec/lattigo/v2/ckks"
)

// Benchmarks for the row-times-row matmul variants at production CKKS parameters.
// They only run under -bench, since key generation alone takes tens of seconds.
//
//	go test ./tests/unit_tests/ -run '^$' -bench BenchmarkCMultMatRowTimesRow -benchtime 1x -timeout 3h
//
// Dimensions and parameters are read from the environment so a run can be sized to
// the machine without editing code:
//
//	SFGWAS_BENCH_PARAMS   CKKS parameter set     (default PN14QP438, matching config/gwas)
//	SFGWAS_BENCH_NCOV     rows and shared dim    (default 20, matching num_covs + num_pcs)
//	SFGWAS_BENCH_NUMCTX   ciphertexts per row    (default 8; ~56 models a 10M-SNP block)
//	SFGWAS_BENCH_THREADS  numThreads argument    (default GOMAXPROCS)
//
// Peak heap is reported per variant as a custom metric, but the Go heap does not
// shrink promptly, so cross-variant comparison within one process is only
// indicative. For trustworthy memory numbers run each variant in its own process:
//
//	for v in V1 V2 V3; do
//	  go test ./tests/unit_tests/ -run '^$' -bench "BenchmarkCMultMatRowTimesRow/$v" -benchtime 1x -timeout 3h
//	done

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

var benchParamSets = map[string]int{
	"PN12QP109":  ckks.PN12QP109,
	"PN13QP218":  ckks.PN13QP218,
	"PN14QP438":  ckks.PN14QP438,
	"PN15QP880":  ckks.PN15QP880,
	"PN16QP1761": ckks.PN16QP1761,
}

var (
	benchOnce sync.Once
	benchCPS  *crypto.CryptoParams
)

// benchCryptoParams builds the benchmark context once per process. Key generation
// (especially the rotation keys) dominates setup, so it is shared across variants.
func benchCryptoParams(b *testing.B) *crypto.CryptoParams {
	b.Helper()

	benchOnce.Do(func() {
		name := os.Getenv("SFGWAS_BENCH_PARAMS")
		if name == "" {
			name = "PN14QP438"
		}
		idx, ok := benchParamSets[name]
		if !ok {
			b.Fatalf("unknown SFGWAS_BENCH_PARAMS %q", name)
		}

		start := time.Now()
		benchCPS = crypto.NewCryptoParamsForNetwork(ckks.DefaultParams[idx], 1, 30)[0]
		benchCPS.SetRotKeys(crypto.GenerateRotKeys(benchCPS.GetSlots(), 0, false))
		b.Logf("%s: slots=%d maxLevel=%d, keygen %v",
			name, benchCPS.GetSlots(), benchCPS.Params.MaxLevel(), time.Since(start))
	})
	return benchCPS
}

// peakHeapSampler polls the heap in the background and reports the high-water mark
// above the baseline captured when it started.
type peakHeapSampler struct {
	stop chan struct{}
	done chan struct{}
	peak uint64
}

func startPeakHeapSampler() *peakHeapSampler {
	runtime.GC()

	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	s := &peakHeapSampler{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if d := m.HeapInuse - base.HeapInuse; m.HeapInuse > base.HeapInuse && d > s.peak {
					s.peak = d
				}
			}
		}
	}()
	return s
}

// stopMiB halts sampling and returns the peak heap growth in MiB.
func (s *peakHeapSampler) stopMiB() float64 {
	close(s.stop)
	<-s.done
	return float64(s.peak) / (1 << 20)
}

func BenchmarkCMultMatRowTimesRow(b *testing.B) {
	cps := benchCryptoParams(b)
	slots := cps.GetSlots()

	ncov := envInt("SFGWAS_BENCH_NCOV", 20)
	numCtx := envInt("SFGWAS_BENCH_NUMCTX", 8)
	threads := envInt("SFGWAS_BENCH_THREADS", runtime.GOMAXPROCS(0))
	m := numCtx * slots

	b.Logf("shape %dx%d * %dx%d (%d ciphertexts per row), threads=%d",
		ncov, ncov, ncov, m, numCtx, threads)

	// Vt x ZtXscaled, the dominant call site: n = k = ncov.
	A := make([][]float64, ncov)
	for i := range A {
		A[i] = make([]float64, ncov)
		for j := range A[i] {
			A[i][j] = float64((i+1)*(j+2)) / 97.0
		}
	}
	M := make([][]float64, ncov)
	for i := range M {
		M[i] = make([]float64, m)
		for j := range M[i] {
			M[i][j] = float64((i+j)%11) / 23.0
		}
	}

	Aenc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, A)
	Menc, _, _, _ := crypto.EncryptFloatMatrixRow(cps, M)

	for _, impl := range rowTimesRowImpls {
		b.Run(impl.name, func(b *testing.B) {
			sampler := startPeakHeapSampler()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := impl.fn(cps, Aenc, Menc, threads)
				if len(out) != ncov {
					b.Fatalf("result has %d rows, want %d", len(out), ncov)
				}
			}
			b.StopTimer()

			b.ReportMetric(sampler.stopMiB(), "peakMiB")
		})
	}
}
