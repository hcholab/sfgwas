package mpc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/dckks"
)

func TestSkSeedPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ckks_sk_seed.bin")
	opts := KeyOptions{SeedFile: path}

	seed1, status, err := loadOrCreateSkSeed(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(status)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("seed file mode %04o, want 0600", perm)
	}

	seed2, _, err := loadOrCreateSkSeed(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed1, seed2) {
		t.Fatal("second run did not reuse the persisted seed")
	}

	seed3, _, err := loadOrCreateSkSeed(KeyOptions{SeedFile: path, FreshKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(seed1, seed3) {
		t.Fatal("ckks_fresh_keys did not produce a new seed")
	}
	seed4, _, err := loadOrCreateSkSeed(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed3, seed4) {
		t.Fatal("fresh seed was not persisted")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateSkSeed(opts); err == nil {
		t.Fatal("world-readable seed file was accepted")
	}

	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateSkSeed(opts); err == nil {
		t.Fatal("truncated seed file was accepted")
	}

	e1, _, err := loadOrCreateSkSeed(KeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e2, _, _ := loadOrCreateSkSeed(KeyOptions{})
	if bytes.Equal(e1, e2) {
		t.Fatal("ephemeral seeds repeated")
	}
}

func TestSkShardDerivation(t *testing.T) {
	params := ckks.DefaultParams[ckks.PN12QP109]
	ctx := dckks.NewContext(params)

	seedA := bytes.Repeat([]byte{1}, skSeedLen)
	seedB := bytes.Repeat([]byte{2}, skSeedLen)

	a1 := deriveSkShard(params, ctx, seedA)
	a2 := deriveSkShard(params, ctx, seedA)
	b := deriveSkShard(params, ctx, seedB)

	if !ctx.RingQP.Equal(a1.Value, a2.Value) {
		t.Fatal("same seed gave different shards")
	}
	if ctx.RingQP.Equal(a1.Value, b.Value) {
		t.Fatal("different seeds gave the same shard")
	}
	if shardFingerprint(a1) != shardFingerprint(a2) || shardFingerprint(a1) == shardFingerprint(b) {
		t.Fatal("shard fingerprints do not track the shard")
	}

	// The old fixed seed {42, pid} must no longer be what a party ends up with.
	legacy := deriveSkShard(params, ctx, []byte{42, 1})
	if ctx.RingQP.Equal(a1.Value, legacy.Value) {
		t.Fatal("unexpected collision with the legacy fixed seed")
	}

	if !bytes.Equal(crpSeed(seedA, seedB, 32), crpSeed(seedA, seedB, 32)) ||
		bytes.Equal(crpSeed(seedA, seedA, 32), crpSeed(seedA, seedB, 32)) {
		t.Fatal("CRP seed does not depend (only) on its inputs")
	}
}
