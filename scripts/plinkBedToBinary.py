import sys
import numpy as np
import math

in_fname = sys.argv[1]
num_sample = int(sys.argv[2])
num_snp = int(sys.argv[3])
out_fname = sys.argv[4]

print("Called plinkBedToBinary.py:", in_fname, num_sample, num_snp, out_fname)

x = np.fromfile(in_fname, dtype=np.uint8)[3:]  # Skip magic numbers

byte_per_snp = int(math.ceil(num_sample / 4.0))
expected_bytes = num_snp * byte_per_snp

if len(x) != expected_bytes:
    # Report everything needed to tell apart the possible causes right here, in the log,
    # at the moment of failure -- rather than needing a live filesystem check afterward,
    # which is unreliable: something else (e.g. the next variant/protocol run, which
    # reuses this same temp filename) can overwrite this file within seconds/minutes,
    # so by the time anyone looks, the evidence is gone and whatever's there reflects a
    # LATER, unrelated write, not the one that actually failed.
    implied_snps = len(x) / byte_per_snp
    snps_txt = out_fname + ".snps.txt"
    try:
        with open(snps_txt) as f:
            extract_list_len = sum(1 for _ in f)
    except OSError as e:
        extract_list_len = f"<could not read {snps_txt}: {e}>"
    sys.exit(
        f"plinkBedToBinary.py: size mismatch reading {in_fname}\n"
        f"  actual bytes (post-header) : {len(x)}\n"
        f"  expected bytes             : {expected_bytes}  (num_snp={num_snp} x byte_per_snp={byte_per_snp}, num_sample={num_sample})\n"
        f"  implied variant count      : {implied_snps}"
        f"{'  (non-integer -> .bed itself is truncated mid-variant, not just short some whole variants)' if not implied_snps.is_integer() else ''}\n"
        f"  extract list ({snps_txt}) : {extract_list_len} lines"
    )

masks = [3, 12, 48, 192]
y = np.zeros((4, len(x)), dtype=np.int8)
for i in range(len(masks)):
    z = np.right_shift(np.bitwise_and(x, masks[i]), 2 * i).astype(np.int8)
    z0 = z == 0
    z1 = z == 1
    z[z0] = 1
    z = 3 - z
    z[z1] = -1
    y[i] = z
y = y.transpose().reshape((num_snp, -1)).transpose()[:num_sample]

print("Exporting matrix.. ", end="")
with open(out_fname, "wb") as outfile:
    y.tofile(outfile)
print("done.")
