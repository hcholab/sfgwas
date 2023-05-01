import sys
import numpy as np

in_fname = sys.argv[1]
nrows = int(sys.argv[2])
ncols = int(sys.argv[3])
out_fname = sys.argv[4]

print("Called convertToBinary.py:", in_fname, nrows, ncols, out_fname)

print("Loading matrix.. ", end="")
# read in tab-delimited matrix
arr = np.loadtxt(in_fname, delimiter="\t", dtype=np.float64)  # float

print("done.")

print("Input array length:", len(arr))
print("Input dimensions:", arr.shape)

arr = arr.astype(np.float64)

print("Writing to disk.. ", end="")
with open(out_fname, "wb") as outfile:
    arr.tofile(outfile)
print("done.")
