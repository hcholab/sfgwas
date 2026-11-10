package crypto

import (
	"fmt"
	"math"

	"github.com/ldsec/lattigo/v2/ckks"
	"go.dedis.ch/onet/v3/log"
)

// SameScaleTol is the largest relative scale difference CheckSameScale accepts.
//
// Lattigo's Add/Sub reconcile operands of different scales only by multiplying the
// lower-scale one by uint64(ratio). For a ratio in (1, 2) that multiplier is 1, so the
// lower-scale operand is silently read at the higher scale and shrinks by the ratio.
// Every Rescale divides by a prime q_i, and PN14QP438's 34-bit primes differ from the
// default scale 2^34 by up to ~8e-5, so "raw sum (fresh, scale Δ) minus rescaled
// projection (scale Δ·Δ'/q_i)" is off by up to ~1e-4 relative to the raw sum. Callers
// that subtract such quantities must put both operands at the same scale (see
// EncryptFloatVectorAtScale) and use the checked helpers below.
const SameScaleTol = 1e-12

// CheckSameScale returns an error describing the mismatch unless a and b carry the same
// scale to within SameScaleTol.
func CheckSameScale(what string, a, b *ckks.Ciphertext) error {
	if a == nil || b == nil {
		return fmt.Errorf("%s: nil ciphertext", what)
	}
	if d := math.Abs(a.Scale()/b.Scale() - 1); d > SameScaleTol {
		return fmt.Errorf("%s: CKKS scale mismatch: %.17g vs %.17g (relative difference %.3g > %g); "+
			"Lattigo's Add/Sub would silently misread one operand", what, a.Scale(), b.Scale(), d, SameScaleTol)
	}
	return nil
}

// MustSameScale is CheckSameScale that aborts the process on a mismatch.
func MustSameScale(what string, a, b *ckks.Ciphertext) {
	if err := CheckSameScale(what, a, b); err != nil {
		log.Fatal(err)
	}
}

// CSubSameScale returns X - Y elementwise, aborting if any pair of operands differs in
// scale (see SameScaleTol). Levels may differ; the result is at the lower one.
func CSubSameScale(cryptoParams *CryptoParams, what string, X, Y CipherVector) CipherVector {
	if len(X) != len(Y) {
		log.Fatalf("%s: length mismatch %d vs %d", what, len(X), len(Y))
	}
	for i := range X {
		MustSameScale(fmt.Sprintf("%s [ciphertext %d]", what, i), X[i], Y[i])
	}
	return CSub(cryptoParams, X, Y)
}

// EncryptFloatVectorAtScale is EncryptFloatVector with an explicit plaintext scale and
// level, used to encrypt a raw local quantity exactly at the scale of the (rescaled)
// ciphertext it will be combined with. Scales of rescaled ciphertexts are not integers;
// Encode rounds value*scale to the nearest integer either way, so this costs no
// precision compared with encrypting at the default scale.
func EncryptFloatVectorAtScale(cryptoParams *CryptoParams, f []float64, scale float64, level int) CipherVector {
	slots := cryptoParams.GetSlots()
	if level < 0 || level > cryptoParams.Params.MaxLevel() {
		log.Fatalf("EncryptFloatVectorAtScale: level %d outside [0, %d]", level, cryptoParams.Params.MaxLevel())
	}
	out := make(CipherVector, 0, (len(f)+slots-1)/slots)
	for start := 0; start < len(f); start += slots {
		end := Min(start+slots, len(f))
		buf := make([]float64, slots) // zero-padded copy; never append into the caller's slice
		copy(buf, f[start:end])
		pt := ckks.NewPlaintext(cryptoParams.Params, level, scale)
		cryptoParams.WithEncoder(func(encoder ckks.Encoder) error {
			encoder.Encode(pt, ConvertVectorFloat64ToComplex(buf), cryptoParams.Params.LogSlots())
			return nil
		})
		cryptoParams.WithEncryptor(func(encryptor ckks.Encryptor) error {
			out = append(out, encryptor.EncryptNew(pt))
			return nil
		})
	}
	return out
}
