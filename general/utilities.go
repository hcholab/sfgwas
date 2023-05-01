package general

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/hcholab/sfgwas/crypto"
	"github.com/hcholab/sfgwas/mpc"
	"go.dedis.ch/onet/v3/log"
	"gonum.org/v1/gonum/mat"
)

func TransposeMatrixFile(inputFile string, nrows, ncols int, outputFile string, dtype string) {
	cmd := exec.Command("/bin/sh", "scripts/transposeMatrix.sh", inputFile, strconv.Itoa(nrows), strconv.Itoa(ncols), outputFile, dtype)
	cout, e := cmd.CombinedOutput()
	fmt.Print(string(cout))
	if e != nil {
		log.Fatal(e)
	}
}

func SaveMatrixToFile(cps *crypto.CryptoParams, mpcObj *mpc.MPC, cm crypto.CipherMatrix, nElemCol int, sourcePid int, filename string) {
	pid := mpcObj.GetPid()
	if pid == 0 {
		return
	}

	pm := mpcObj.Network.CollectiveDecryptMat(cps, cm, sourcePid)

	M := mat.NewDense(len(cm), nElemCol, nil)
	for i := range pm {
		M.SetRow(i, crypto.DecodeFloatVector(cps, pm[i])[:nElemCol])
	}

	if pid == sourcePid || sourcePid < 0 {

		f, err := os.Create(filename)

		if err != nil {
			panic(err)
		}

		defer f.Close()

		rows, cols := M.Dims()

		for row := 0; row < rows; row++ {
			line := make([]string, cols)
			for col := 0; col < cols; col++ {
				line[col] = fmt.Sprintf("%.6e", M.At(row, col))
			}

			f.WriteString(strings.Join(line, ",") + "\n")
		}

		f.Sync()

		fmt.Println("Saved data to", filename)

	}

}

func SaveIntVectorToFile(filename string, x []int) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	writer := bufio.NewWriter(file)

	for i := range x {
		writer.WriteString(fmt.Sprintf("%d\n", x[i]))
	}

	writer.Flush()
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
