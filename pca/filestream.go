package pca

import (
	"bufio"
	"encoding/binary"
	"io"
	"math"
	"os"
	"time"

	"go.dedis.ch/onet/v3/log"
)

type FileStream struct {
	filename  string
	file      *os.File
	reader    *bufio.Reader
	numRows   uint64
	numCols   uint64
	lineCount uint64
	buf       []byte
}

func NewFileStream(filename string, numRows, numCols uint64) *FileStream {
	log.LLvl1(time.Now().Format(time.RFC3339), "NewFileStream", filename, numRows, numCols)

	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	return &FileStream{
		filename:  filename,
		buf:       make([]byte, numCols*8),
		numRows:   numRows,
		numCols:   numCols,
		reader:    bufio.NewReader(file),
		lineCount: 0,
	}
}

func (fs *FileStream) readRow() []float64 {
	if fs.CheckEOF() {
		return nil
	}

	_, err := io.ReadFull(fs.reader, fs.buf)
	if err != nil {
		panic(err)
	}

	intBuf := make([]float64, fs.numCols)

	// idx := 0
	// for i := range fs.buf {
	// 	intBuf[idx] = float64(fs.buf[i])
	// 	idx++
	// }
	idx := 0
	i := 0
	for i < len(fs.buf) {
		intBuf[idx] = Float64frombytes(fs.buf[i : i+8])
		i += 8
		idx++
	}

	fs.lineCount++

	return intBuf
}

func (fs *FileStream) Reset() {
	var err error
	if fs.file == nil {
		fs.file, err = os.Open(fs.filename)
	} else {
		_, err = fs.file.Seek(0, io.SeekStart)
	}

	if err != nil {
		panic(err)
	}

	fs.reader = bufio.NewReader(fs.file)
	fs.lineCount = 0
}

func (fs *FileStream) NumRows() uint64 {
	return fs.numRows
}

func (fs *FileStream) NumCols() uint64 {
	return fs.numCols
}

func (fs *FileStream) CheckEOF() bool {
	if fs.lineCount >= fs.numRows {
		if fs.file != nil {
			fs.file.Close()
		}
		fs.file = nil
		fs.reader = nil

		return true
	}

	return false
}

func (fs *FileStream) NextRow() []float64 {
	if fs.CheckEOF() {
		return nil
	}

	return fs.readRow()
}

func Float64frombytes(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	float := math.Float64frombits(bits)
	return float
}
