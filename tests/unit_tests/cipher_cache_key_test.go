package unittests

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/ldsec/lattigo/v2/ckks"
)

// TestCipherCacheKeyFingerprint checks that ciphertext caches record the key they were
// written under and that a cache written under another key (or without a fingerprint,
// as older builds wrote them) is refused instead of silently decrypting to garbage.
func TestCipherCacheKeyFingerprint(t *testing.T) {
	params := ckks.DefaultParams[ckks.PN12QP109]
	cps := crypto.NewCryptoParamsForNetwork(params, 1, 30)[0]
	cps.KeyFingerprint = "aaaa" + "0000000000000000000000000000000000000000000000000000000000"

	vals := []float64{1.5, -2.25, 3}
	cm, _, _, err := crypto.EncryptFloatMatrixRow(cps, [][]float64{vals})
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "cache.bin")
	crypto.SaveCipherMatrixToFile(cps, cm, file)

	if err := crypto.CheckCipherCacheKey(cps, file); err != nil {
		t.Fatalf("matching key refused: %v", err)
	}
	got := crypto.DecryptFloatVector(cps, crypto.LoadCipherMatrixFromFile(cps, file)[0], len(vals))
	for i := range vals {
		if math.Abs(got[i]-vals[i]) > 1e-3 {
			t.Fatalf("round trip: got %v want %v", got, vals)
		}
	}

	other := *cps
	other.KeyFingerprint = "bbbb" + cps.KeyFingerprint[4:]
	if err := crypto.CheckCipherCacheKey(&other, file); err == nil {
		t.Fatal("cache written under another key was accepted")
	} else {
		t.Log(err)
	}

	if err := os.Remove(file + ".keyfp"); err != nil {
		t.Fatal(err)
	}
	if err := crypto.CheckCipherCacheKey(cps, file); err == nil {
		t.Fatal("cache without a key fingerprint was accepted")
	}

	// Without CollectiveInit (no joint fingerprint) the local secret key is used.
	local := *cps
	local.KeyFingerprint = ""
	crypto.SaveCipherMatrixToFile(&local, cm, file)
	if err := crypto.CheckCipherCacheKey(&local, file); err != nil {
		t.Fatalf("local-key fingerprint refused: %v", err)
	}
	if err := crypto.CheckCipherCacheKey(cps, file); err == nil {
		t.Fatal("local-key cache accepted under a joint fingerprint")
	}
}
