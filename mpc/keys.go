package mpc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/dckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"go.dedis.ch/onet/v3/log"
)

// KeyOptions controls how a data party obtains its CKKS secret-key shard.
//
// The shard is derived deterministically from a 32-byte seed drawn from crypto/rand.
// The seed is the only secret: it never leaves the party, and it is persisted (mode
// 0600) so that ciphertexts cached by one run stay decryptable by the next. Party 0
// holds no key material and ignores these options.
type KeyOptions struct {
	// SeedFile is the path of this party's persisted seed. It is created on first use.
	// An empty path means ephemeral keys: a fresh random shard every run, nothing written.
	SeedFile string

	// FreshKeys replaces the persisted seed with a new random one. Every ciphertext
	// cache written under the old key is then rejected by its key fingerprint.
	FreshKeys bool
}

// NewKeyOptions resolves the ckks_sk_seed_file / ckks_fresh_keys config keys: an
// explicit seedFile wins, otherwise the seed lives at <cacheDir>/ckks_sk_seed.bin.
func NewKeyOptions(seedFile, cacheDir string, fresh bool) KeyOptions {
	if seedFile == "" {
		seedFile = filepath.Join(cacheDir, "ckks_sk_seed.bin")
	}
	return KeyOptions{SeedFile: seedFile, FreshKeys: fresh}
}

const (
	skSeedLen = 32

	// Domain-separation prefixes; every hash/PRF input in this file starts with one.
	domainSkPRF      = "sfgwas/ckks-sk/v1"
	domainShardFP    = "sfgwas/ckks-sk-shard-fp/v1"
	domainJointFP    = "sfgwas/ckks-joint-key-fp/v1"
	domainRunNonce   = "sfgwas/ckks-run-nonce/v1"
	domainCRPSeed    = "sfgwas/ckks-crp-seed/v1"
	runNonceWords    = 4 // 32 bytes as uint64 words
	fingerprintWords = 4
)

// loadOrCreateSkSeed returns this party's secret seed, creating (or, with FreshKeys,
// replacing) the persisted copy as needed. The second return value says what happened,
// for the log.
func loadOrCreateSkSeed(opts KeyOptions) ([]byte, string, error) {
	if opts.SeedFile == "" {
		seed, err := randomBytes(skSeedLen)
		return seed, "ephemeral (not persisted)", err
	}

	if !opts.FreshKeys {
		info, err := os.Stat(opts.SeedFile)
		if err == nil {
			if !info.Mode().IsRegular() {
				return nil, "", fmt.Errorf("CKKS key seed %s is not a regular file", opts.SeedFile)
			}
			if perm := info.Mode().Perm(); perm&0o077 != 0 {
				return nil, "", fmt.Errorf("CKKS key seed %s is accessible by other users (mode %04o); "+
					"run `chmod 600 %s` (or set ckks_fresh_keys = true to replace it)", opts.SeedFile, perm, opts.SeedFile)
			}
			seed, err := os.ReadFile(opts.SeedFile)
			if err != nil {
				return nil, "", err
			}
			if len(seed) != skSeedLen {
				return nil, "", fmt.Errorf("CKKS key seed %s has %d bytes, expected %d", opts.SeedFile, len(seed), skSeedLen)
			}
			return seed, "loaded from " + opts.SeedFile, nil
		}
		if !os.IsNotExist(err) {
			return nil, "", err
		}
	}

	seed, err := randomBytes(skSeedLen)
	if err != nil {
		return nil, "", err
	}
	if err := writeFileAtomic0600(opts.SeedFile, seed); err != nil {
		return nil, "", err
	}
	if opts.FreshKeys {
		return seed, "fresh seed written to " + opts.SeedFile + " (ckks_fresh_keys)", nil
	}
	return seed, "new seed written to " + opts.SeedFile, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

// writeFileAtomic0600 writes data to path through a 0600 temp file in the same
// directory followed by a rename, so readers never see a partial seed and the file is
// never briefly readable by others.
func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ckks_sk_seed-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// deriveSkShard expands the seed into a ternary secret-key shard (NTT, Montgomery
// form), the same distribution kgen.GenSecretKey uses.
func deriveSkShard(params *ckks.Parameters, ctx *dckks.Context, seed []byte) *ckks.SecretKey {
	prng, err := utils.NewKeyedPRNG(append([]byte(domainSkPRF), seed...))
	if err != nil {
		panic(err)
	}
	sk := ckks.NewSecretKey(params)
	sk.Value = ring.NewTernarySampler(prng, ctx.RingQP, 1.0/3.0, true).ReadNew()
	ctx.RingQP.NTT(sk.Value, sk.Value)
	return sk
}

// shardFingerprint is a domain-separated SHA-256 of the shard. The shard has far more
// than 256 bits of entropy, so the hash reveals nothing about it.
func shardFingerprint(sk *ckks.SecretKey) [32]byte {
	data, err := sk.Value.MarshalBinary()
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write([]byte(domainShardFP))
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func bytesToWords(b []byte) []uint64 {
	w := make([]uint64, len(b)/8)
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
	return w
}

func wordsToBytes(w []uint64) []byte {
	b := make([]byte, 8*len(w))
	for i := range w {
		binary.LittleEndian.PutUint64(b[8*i:], w[i])
	}
	return b
}

// keySetupExchange runs once per CollectiveInit, on thread 0. Every data party sends the
// hub a fresh 32-byte random contribution and its shard fingerprint; the hub hashes the
// contributions into a run nonce and the fingerprints into a joint key fingerprint, and
// sends both to every other party (party 0 included).
//
//   - The run nonce re-randomizes the common reference polynomials of this run's key
//     generation. They used to be a fixed function of the shared global PRG key, which
//     is harmless with per-run keys but not with a persisted shard: the CKG/RKG/RTG
//     shares each party sends the hub have the form ±s·a + e with fresh e, and with a
//     fixed a, averaging the shares of many runs strips e and exposes s·a.
//   - The joint fingerprint identifies the collective secret key (it changes iff some
//     party's shard changes) and is stored next to every ciphertext cache. A public-key
//     fingerprint would not do: the public key changes every run even for a fixed
//     secret key, because both the CRP and the CKG noise are fresh.
func keySetupExchange(net *Network, skShard *ckks.SecretKey) (runNonce []byte, jointFP string) {
	pid, hub, nparty := net.GetPid(), net.GetHubPid(), net.GetNParty()

	if pid == 0 {
		msg := wordsToBytes(net.ReceiveIntVector(runNonceWords+fingerprintWords, hub))
		return msg[:8*runNonceWords], hex.EncodeToString(msg[8*runNonceWords:])
	}

	contrib, err := randomBytes(8 * runNonceWords)
	if err != nil {
		panic(err)
	}
	fp := shardFingerprint(skShard)
	mine := append(append([]byte{}, contrib...), fp[:]...)

	if pid != hub {
		net.SendIntVector(bytesToWords(mine), hub)
		msg := wordsToBytes(net.ReceiveIntVector(runNonceWords+fingerprintWords, hub))
		return msg[:8*runNonceWords], hex.EncodeToString(msg[8*runNonceWords:])
	}

	hNonce := sha256.New()
	hNonce.Write([]byte(domainRunNonce))
	hFP := sha256.New()
	hFP.Write([]byte(domainJointFP))
	for p := 1; p < nparty; p++ {
		msg := mine
		if p != pid {
			msg = wordsToBytes(net.ReceiveIntVector(runNonceWords+fingerprintWords, p))
		}
		hNonce.Write(msg[:8*runNonceWords])
		hFP.Write(msg[8*runNonceWords:])
	}
	nonce := hNonce.Sum(nil)
	jfp := hFP.Sum(nil)
	out := bytesToWords(append(append([]byte{}, nonce...), jfp...))
	for p := 0; p < nparty; p++ {
		if p != pid {
			net.SendIntVector(out, p)
		}
	}
	return nonce, hex.EncodeToString(jfp)
}

// crpSeed mixes the run nonce into a seed drawn from the shared global PRG.
func crpSeed(globalSeed, runNonce []byte, keySize int) []byte {
	h := sha256.New()
	h.Write([]byte(domainCRPSeed))
	h.Write(runNonce)
	h.Write(globalSeed)
	sum := h.Sum(nil)
	if keySize > len(sum) {
		panic("crpSeed: key size larger than SHA-256 output")
	}
	return sum[:keySize]
}

func logKeySetup(pid int, status, jointFP string) {
	if pid > 0 {
		log.LLvl1("CKKS secret-key shard:", status)
	}
	log.LLvl1("CKKS joint key fingerprint:", jointFP[:16]+"...")
}
