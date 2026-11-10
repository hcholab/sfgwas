package unittests

import (
	"math"
	"testing"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/ldsec/lattigo/v2/ckks"
)

// TestCKKSScaleAlignment reproduces the "raw sum - rescaled projection" pattern of the
// association statistics (sxx, sxy, syy) with the production parameters PN14QP438,
// whose 34-bit primes differ from the default scale 2^34 by up to ~8e-5.
//
// raw is ~10^6 (like YᵀY for a phenotype with mean ~10 at n = 10^4) and the projection
// is a rescaled ciphertext product close to it, so the difference is ~10^3. Subtracting
// the projection from a fresh ciphertext with Lattigo's Sub silently reads the
// projection at the fresh ciphertext's scale (scale ratio in (1, 2), multiplier
// uint64(ratio) = 1), which shifts the result by ~ratio·10^6. Encrypting raw at the
// projection's exact scale and level (crypto.EncryptFloatVectorAtScale) and subtracting
// with crypto.CSubSameScale must match plaintext to the CKKS noise floor.
func TestCKKSScaleAlignment(t *testing.T) {
	params := ckks.DefaultParams[ckks.PN14QP438]
	cps := crypto.NewCryptoParamsForNetwork(params, 1, 256)[0]

	const m = 16
	x := make([]float64, m)
	y := make([]float64, m)
	raw := make([]float64, m)
	want := make([]float64, m)
	for j := range x {
		x[j] = 1000 + 3*float64(j) // projection term x·y ~ 10^6
		y[j] = 999.25 - float64(j)
		raw[j] = x[j]*y[j] + 1000 + 10*float64(j)
		want[j] = raw[j] - x[j]*y[j]
	}

	xe, _ := crypto.EncryptFloatVector(cps, x)
	ye, _ := crypto.EncryptFloatVector(cps, y)
	var proj crypto.CipherVector
	if err := cps.WithEvaluator(func(eval ckks.Evaluator) error {
		p := eval.MulRelinNew(xe[0], ye[0])
		if err := eval.Rescale(p, params.Scale(), p); err != nil {
			return err
		}
		proj = crypto.CipherVector{p}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ratio := proj[0].Scale() / params.Scale()
	t.Logf("projection scale / Δ = 1 %+.3e (level %d)", ratio-1, proj[0].Level())
	if math.Abs(ratio-1) < 1e-7 {
		t.Fatalf("test needs a rescaled ciphertext whose scale is off Δ; got ratio %v", ratio)
	}

	maxErr := func(cv crypto.CipherVector) float64 {
		got := crypto.DecryptFloatVector(cps, cv, m)
		e := 0.0
		for j := range want {
			e = math.Max(e, math.Abs(got[j]-want[j]))
		}
		return e
	}

	// Old pattern: raw at the default scale, plain Sub.
	rawFresh, _ := crypto.EncryptFloatVector(cps, raw)
	if err := crypto.CheckSameScale("old pattern", rawFresh[0], proj[0]); err == nil {
		t.Fatal("CheckSameScale did not flag the near-1 scale mismatch")
	}
	errOld := maxErr(crypto.CSub(cps, rawFresh, proj))

	// Fixed pattern.
	rawAligned := crypto.EncryptFloatVectorAtScale(cps, raw, proj[0].Scale(), proj[0].Level())
	errNew := maxErr(crypto.CSubSameScale(cps, "aligned", rawAligned, proj))

	// The noise floor: the projection's own decryption error (two fresh ciphertexts of
	// magnitude ~1e3, each with ~1e-5 absolute noise, multiplied).
	projDec := crypto.DecryptFloatVector(cps, proj, m)
	floor := 0.0
	for j := range x {
		floor = math.Max(floor, math.Abs(projDec[j]-x[j]*y[j]))
	}

	t.Logf("max |error| of raw - projection: plain Sub %.3g, scale-aligned %.3g; projection's own CKKS error %.3g (values ~1e3, operands ~1e6)",
		errOld, errNew, floor)
	if errNew > 1.5*floor+1e-6 {
		t.Errorf("scale-aligned subtraction off by %.3g, more than the projection's own CKKS error %.3g", errNew, floor)
	}
	if errOld < 100*errNew {
		t.Errorf("plain Sub error %.3g not clearly above the aligned error %.3g; the test no longer exercises the mismatch", errOld, errNew)
	}
}
