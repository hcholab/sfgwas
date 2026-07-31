package mpc

import (
	mpc_core "github.com/hhcho/mpc-core"
	"gonum.org/v1/gonum/mat"
)

// "bufio"

// for processing terminal input => to get pid and ip addresses and port
// func split(s string) (int, string, string) {
// 	info := strings.SplitN(s, ":", 3)
// 	// fmt.Println(info)
// 	id, _ := strconv.Atoi(info[0])
// 	return id, info[1], info[2]
// }

func DenseToRMat(rtype mpc_core.RElem, src mat.Matrix, fracBits int) mpc_core.RMat {
	rows, cols := src.Dims()
	dst := mpc_core.InitRMat(rtype.Zero(), rows, cols)

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			dst[i][j] = rtype.FromFloat64(src.At(i, j), fracBits)
		}
	}

	return dst
}

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}
