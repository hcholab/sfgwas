package crypto

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"go.dedis.ch/onet/v3/log"
)

func Max(x, y int) int {
	if x <= y {
		return y
	}
	return x
}

func Min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}
func Mod(n int, modulus int) int {
	n = n % modulus
	if n < 0 {
		n = n + modulus
	}
	return n
}

// MarshalCiphermatrix returns byte array corresponding to ciphertext sizes (int array) and byte array corresponding to marshaling
func MarshalCM(cm CipherMatrix) ([]byte, []byte) {
	cmBytes, ctSizes, err := cm.MarshalBinary()
	if err != nil {
		panic(err)
	}

	r, c := len(cm), len(cm[0])
	intsize := uint64(unsafe.Sizeof(ctSizes[0][0]))
	sizesbuf := make([]byte, intsize*uint64(r)*uint64(c))

	offset := uint64(0)
	for i := range ctSizes {
		for j := range ctSizes[i] {
			binary.LittleEndian.PutUint64(sizesbuf[offset:offset+intsize], uint64(ctSizes[i][j]))
			offset += intsize
		}

	}

	return sizesbuf, cmBytes

}

// MarshalCiphermatrix returns byte array corresponding to ciphertext sizes (int array) and byte array corresponding to marshaling
func UnmarshalCM(cryptoParams *CryptoParams, r, c int, sbytes, ctbytes []byte) CipherMatrix {
	intsize := uint64(8)
	offset := uint64(0)
	sizes := make([][]int, r)
	for i := range sizes {
		sizes[i] = make([]int, c)
		for j := range sizes[i] {
			sizes[i][j] = int(binary.LittleEndian.Uint64(sbytes[offset:]))
			offset += intsize

		}
	}

	cm := make(CipherMatrix, 1)
	err := (&cm).UnmarshalBinary(cryptoParams, ctbytes, sizes)
	if err != nil {
		panic(err)

	}

	return cm
}

// keyFingerprintSuffix names the sidecar file that records which joint secret key a
// ciphertext cache was written under.
const keyFingerprintSuffix = ".keyfp"

// keyFingerprint returns cps.KeyFingerprint, or for a context built without
// mpc.CollectiveInit (single-party tests) a fingerprint of its own secret key.
func keyFingerprint(cps *CryptoParams) string {
	if cps.KeyFingerprint != "" {
		return cps.KeyFingerprint
	}
	if cps.Sk == nil {
		log.Fatal("ciphertext cache: crypto parameters carry neither a key fingerprint nor a secret key")
	}
	data, err := cps.Sk.Value.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.Sum256(append([]byte("sfgwas/ckks-local-sk-fp/v1"), data...))
	return hex.EncodeToString(h[:])
}

// CheckCipherCacheKey returns an error unless filename's key-fingerprint sidecar matches
// the key in cps. Ciphertexts decrypt to garbage under any other key, silently, so a
// cache without a matching sidecar (written by an older build, or before a key change)
// is refused rather than used.
func CheckCipherCacheKey(cps *CryptoParams, filename string) error {
	want := keyFingerprint(cps)
	data, err := os.ReadFile(filename + keyFingerprintSuffix)
	if os.IsNotExist(err) {
		return fmt.Errorf("ciphertext cache %s has no key fingerprint (%s%s); it predates key "+
			"fingerprinting or was copied without it, and may be encrypted under a different CKKS key. "+
			"Delete it (or disable the use_cached_* option) to recompute", filename, filename, keyFingerprintSuffix)
	} else if err != nil {
		return err
	}
	if got := strings.TrimSpace(string(data)); got != want {
		return fmt.Errorf("ciphertext cache %s was written under a different CKKS key "+
			"(cache key %.16s..., current key %.16s...): the joint key changed (a party's seed was "+
			"regenerated, ckks_fresh_keys was set, or the cache comes from another deployment). "+
			"Delete the cache (or disable the use_cached_* option) to recompute", filename, got, want)
	}
	return nil
}

// SaveCipherMatrixToFile writes cm to filename, plus a sidecar recording the key
// fingerprint that LoadCipherMatrixFromFile checks.
func SaveCipherMatrixToFile(cps *CryptoParams, cm CipherMatrix, filename string) {
	if err := os.WriteFile(filename+keyFingerprintSuffix, []byte(keyFingerprint(cps)+"\n"), 0644); err != nil {
		log.Fatal(err)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	sbytes, cmbytes := MarshalCM(cm)

	nrbuf := make([]byte, 4)
	ncbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(nrbuf, uint32(len(cm)))
	binary.LittleEndian.PutUint32(ncbuf, uint32(len(cm[0])))

	sbuf := make([]byte, 8) //TODO: see if 4 bytes is enough
	cmbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sbuf, uint64(len(sbytes)))
	binary.LittleEndian.PutUint64(cmbuf, uint64(len(cmbytes)))

	writer.Write(nrbuf)
	writer.Write(ncbuf)
	writer.Write(sbuf)
	writer.Write(sbytes)
	writer.Write(cmbuf)
	writer.Write(cmbytes)

	writer.Flush()
}

// LoadCipherMatrixFromFile reads a cache written by SaveCipherMatrixToFile. It refuses
// (log.Fatal) a cache whose key fingerprint does not match cps.
func LoadCipherMatrixFromFile(cps *CryptoParams, filename string) CipherMatrix {
	if err := CheckCipherCacheKey(cps, filename); err != nil {
		log.Fatal(err)
	}

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	ibuf := make([]byte, 4)
	io.ReadFull(reader, ibuf)
	nrows := int(binary.LittleEndian.Uint32(ibuf))
	io.ReadFull(reader, ibuf)
	numCtxPerRow := int(binary.LittleEndian.Uint32(ibuf))

	sbuf := make([]byte, 8)
	io.ReadFull(reader, sbuf)
	sbyteSize := binary.LittleEndian.Uint64(sbuf)
	sdata := make([]byte, sbyteSize)
	io.ReadFull(reader, sdata)

	cmbuf := make([]byte, 8)
	io.ReadFull(reader, cmbuf)
	cbyteSize := binary.LittleEndian.Uint64(cmbuf)
	cdata := make([]byte, cbyteSize)
	io.ReadFull(reader, cdata)

	return UnmarshalCM(cps, nrows, numCtxPerRow, sdata, cdata)
}

//
// // *** FILE MANAGEMENT
//
// // SaveModel saves weights/model to a binary file
// func SaveModel(file string, model CipherMatrix) error {
// 	binaryData, sizes, err := model.MarshalBinary()
//
// 	if err != nil {
// 		return err
// 	}
//
// 	data := make([]byte, binary.MaxVarintLen64*(len(sizes)*(1+len(sizes[0]))+1))
//
// 	index := 0
// 	// Write the int array
// 	index += binary.PutUvarint(data, uint64(len(sizes)))
// 	for _, elt := range sizes {
// 		index += binary.PutUvarint(data[index:], uint64(len(elt)))
// 		for _, e := range elt {
// 			index += binary.PutUvarint(data[index:], uint64(e))
// 		}
// 	}
//
// 	data = data[:index]
// 	data = append(data, binaryData...)
//
// 	return ioutil.WriteFile(file, data, os.ModePerm)
// }
//
// //
// // // LoadModel loads weights/model to a binary file
// func LoadModel(params *CryptoParams, file string) (CipherMatrix, error) {
// 	bts, err := ioutil.ReadFile(file)
// 	if err != nil {
// 		return nil, fmt.Errorf("reading file: %w", err)
// 	}
// 	reader := bytes.NewReader(bts)
//
// 	mainSize, err := binary.ReadUvarint(reader)
// 	if err != nil {
// 		return nil, fmt.Errorf("reading uint: %w", err)
// 	}
//
// 	sizes := make([][]int, mainSize)
// 	for i := range sizes {
// 		childSize, err := binary.ReadUvarint(reader)
// 		if err != nil {
// 			return nil, fmt.Errorf("reading uint: %w", err)
// 		}
//
// 		sizes[i] = make([]int, childSize)
//
// 		for j := range sizes[i] {
// 			size, err := binary.ReadUvarint(reader)
// 			if err != nil {
// 				return nil, fmt.Errorf("reading uint: %w", err)
// 			}
//
// 			sizes[i][j] = int(size)
// 		}
// 	}
//
// 	var mat = make(CipherMatrix, 0)
//
// 	f := make([]byte, reader.Len())
// 	_, err = reader.Read(f)
// 	if err != nil {
// 		return nil, fmt.Errorf("reading file block: %w", err)
// 	}
//
// 	err = mat.UnmarshalBinary(params, f, sizes)
// 	if err != nil {
// 		return nil, fmt.Errorf("unmarshalling weights: %w", err)
// 	}
//
// 	return mat, nil
// }
