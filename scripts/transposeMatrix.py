import sys
import numpy as np

in_fname = sys.argv[1]
nrows = int(sys.argv[2])
ncols = int(sys.argv[3])
out_fname = sys.argv[4]
dtype_str = sys.argv[5] if len(sys.argv) > 5 else "int8"
if dtype_str == "int8":
    dtype = np.int8
elif dtype_str == "float64":
    dtype = np.float64
else:
    raise ValueError(f"Invalid dtype: {dtype_str}")

print("Called transposeMatrix.py:", in_fname, nrows, ncols, out_fname, dtype_str)

print("Loading matrix.. ", end="")
arr = np.fromfile(in_fname, dtype=dtype)
print("done.")

print("Input array length:", len(arr))

arr = np.reshape(arr, (nrows, ncols))

print("Input dimensions:", arr.shape)

print("Transposing.. ", end="")
arr = arr.transpose()
print("done.")

print("Output dimensions:", arr.shape)

print("Writing to disk.. ", end="")
with open(out_fname, "wb") as outfile:
    arr.tofile(outfile)
print("done.")
