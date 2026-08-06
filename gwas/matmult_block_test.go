package gwas

import "testing"

// fakeBlock is a minimal Block, so the test exercises BlockToDense without depending on
// the unexported internals of BlockI8.
type fakeBlock struct{ r, c int }

func (b fakeBlock) Dims() (int, int)    { return b.r, b.c }
func (b fakeBlock) At(i, j int) float64 { return float64(i*b.c + j) }

// MatMult4StreamPlain hands BlockToDense a scratch buffer sized for the largest possible
// block (slots-by-slots) and reuses it for every block. mat.NewDense requires its backing
// slice to be exactly r*c long, so an oversized buffer has to be resliced — otherwise
// every real-world block, all of which are smaller than slots-by-slots, panics with
// "mat: dimension mismatch".
func TestBlockToDenseAcceptsOversizedBuffer(t *testing.T) {
	const rows, cols = 5, 7

	buffer := make([]float64, 4096) // far larger than rows*cols, as in the real caller
	d := BlockToDense(fakeBlock{r: rows, c: cols}, buffer)

	if r, c := d.Dims(); r != rows || c != cols {
		t.Fatalf("dims: got %dx%d, want %dx%d", r, c, rows, cols)
	}
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			if want := float64(i*cols + j); d.At(i, j) != want {
				t.Errorf("[%d][%d]: got %v, want %v", i, j, d.At(i, j), want)
			}
		}
	}
}

// A nil or too-small buffer must still work, allocating as needed.
func TestBlockToDenseAllocatesWhenBufferTooSmall(t *testing.T) {
	for _, buf := range [][]float64{nil, make([]float64, 3)} {
		d := BlockToDense(fakeBlock{r: 4, c: 6}, buf)
		if r, c := d.Dims(); r != 4 || c != 6 {
			t.Fatalf("dims: got %dx%d, want 4x6", r, c)
		}
		if d.At(3, 5) != 23 {
			t.Errorf("At(3,5): got %v, want 23", d.At(3, 5))
		}
	}
}
