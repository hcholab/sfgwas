import sys
import numpy as np

in_prefix = sys.argv[1]
nrows = int(sys.argv[2])
ncols = [int(line) for line in open(sys.argv[3])]
out_fname = sys.argv[4]

print("Called mergeMatrices.py:", in_prefix, nrows, sys.argv[3], out_fname)

print("Loading matrices.. ", end="")
arrs = [None] * len(ncols)
for i in range(len(arrs)):
    arrs[i] = np.fromfile(f"{in_prefix}.{i}.bin", dtype=np.int8)
    arrs[i] = np.reshape(arrs[i], (nrows, ncols[i]))
print("done.")

print("Merging.. ", end="")
arr = np.concatenate(arrs, axis=1)
print("done.")

print("Output dimensions:", arr.shape)

print("Writing to disk.. ", end="")
with open(out_fname, "wb") as outfile:
    arr.tofile(outfile)
print("done.")
