"""Cross-check a Tractor MPC run against the reference notebook (tractor.ipynb).

usage: python -I scripts/compare_tractor_notebook.py RUN_DIR [--notebook PATH]

RUN_DIR is the directory the three parties ran in (it holds config/tractor/). The
notebook's own precompute_tractor_stats and tractor_from_precomputed (its cells 1 and 2)
are executed unchanged and called the way the notebook calls them, with Z_reg = [1 | Z]
(Z = covariates, plus PCs if the run used them), and with the run's
tractor_count_threshold / tractor_det_tol. Inputs are prepared exactly as the protocol
prepares them: QC sample/SNP filters from the run's cache, missing calls imputed as 0.

Validity rules differ from the protocol only in degenerate cases (the protocol also
requires (S^-1)_ii > 0 and finite statistics, and det > det_tol rather than |det|), so
the flags are expected to match on realistic data. Prints per-phenotype maxima of
|dbeta|/SE, |dSE|/SE, |dt| and |dlog10 p| and exits 1 if any exceeds 1e-2, 1e-3,
1e-2 + 1e-3|t|, 1e-2 respectively or a validity flag differs.
"""
import argparse
import json
import os
import sys

import numpy as np


def strip_comment(line):
    """Drops a # comment that is not inside a double-quoted string."""
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            return line[:i]
    return line


def parse_toml(path):
    """Minimal parser for the flat key = value TOML the configs use (sections ignored)."""
    out = {}
    section = None
    for line in open(path):
        line = strip_comment(line).strip()
        if not line:
            continue
        if line.startswith("["):
            section = line
            continue
        if section is not None or "=" not in line:
            continue
        key, val = (s.strip() for s in line.split("=", 1))
        if val.startswith('"'):
            out[key] = val.strip('"')
        elif val.startswith("["):
            inner = val.strip("[]").strip()
            out[key] = [int(x) for x in inner.split(",") if x.strip()] if inner else []
        elif val in ("true", "false"):
            out[key] = val == "true"
        else:
            try:
                out[key] = int(val)
            except ValueError:
                out[key] = float(val)
    return out


def load_notebook_functions(path):
    nb = json.load(open(path))
    ns = {}
    for cell in nb["cells"]:
        src = "".join(cell["source"])
        if cell["cell_type"] == "code" and ("def precompute_tractor_stats" in src or "def tractor_from_precomputed" in src):
            exec(compile(src, f"{path}:cell", "exec"), ns)
    for fn in ("precompute_tractor_stats", "tractor_from_precomputed"):
        if fn not in ns:
            sys.exit(f"{path}: no cell defines {fn}")
    return ns["precompute_tractor_stats"], ns["tractor_from_precomputed"]


def read_bools(path, n=None):
    v = np.array([l.strip() != "0" for l in open(path) if l.strip()], dtype=bool)
    if n is not None and len(v) != n:
        sys.exit(f"{path}: {len(v)} entries, expected {n}")
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--notebook", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tractor.ipynb"))
    args = ap.parse_args()

    run = os.path.abspath(args.run_dir)
    resolve = lambda p: p if os.path.isabs(p) else os.path.join(run, p)
    cfgdir = os.path.join(run, "config", "tractor")
    g = parse_toml(os.path.join(cfgdir, "configGlobal.toml"))
    nparty = g["num_main_parties"]
    loc = {p: {**g, **parse_toml(os.path.join(cfgdir, f"configLocal.Party{p}.toml"))} for p in range(1, nparty + 1)}

    precompute, from_precomputed = load_notebook_functions(args.notebook)

    m_all = g["num_snps"]
    sizes = [int(x) for x in open(resolve(loc[1]["geno_block_size_file"])).read().split()]
    qc = (not g.get("skip_qc", False)) or g.get("use_cached_qc", False)
    precomp = g.get("use_precomputed_geno_count", False)
    cache1 = resolve(loc[1]["cache_dir"])

    snp_keep = np.ones(m_all, dtype=bool)
    if qc:
        if precomp:
            snp_keep = read_bools(os.path.join(cache1, "gkeep.txt"), m_all)
        else:
            miss = read_bools(os.path.join(cache1, "gkeep_miss.txt"), m_all)
            snp_keep = np.zeros(m_all, dtype=bool)
            snp_keep[miss] = read_bools(os.path.join(cache1, "gkeep_maf_hwe.txt"), int(miss.sum()))
    blocks = g.get("blocks_for_assoc_test", [])
    if blocks:
        off = np.cumsum([0] + sizes)
        for b in range(len(sizes)):
            if b not in blocks:
                snp_keep[off[b]:off[b + 1]] = False
    npc = g.get("num_pcs_to_remove", 0) if (not g.get("skip_pca", False) or g.get("use_cached_pca", False)) else 0

    Zs, Ys, As, Ms, Es = [], [], [], [], []
    for p in range(1, nparty + 1):
        c = loc[p]
        n = g["num_inds"][p]
        cov = np.loadtxt(resolve(c["covar_file"]), ndmin=2)
        y = np.loadtxt(resolve(c["pheno_file"]), ndmin=2)
        keep = np.ones(n, dtype=bool)
        if qc and not precomp:
            keep = read_bools(os.path.join(resolve(c["cache_dir"]), "ikeep.txt"), n)
        mats = []
        for key in ("tractor_geno_prefix_a", "tractor_geno_prefix_amr", "tractor_geno_prefix_eur"):
            blks = [np.fromfile(f"{resolve(c[key])}.{b}.bin", dtype=np.int8).reshape(n, s) for b, s in enumerate(sizes)]
            X = np.hstack(blks).astype(float)[:, snp_keep]
            X[X < 0] = 0  # missing calls imputed as 0, as in the protocol
            mats.append(X[keep])
        Z = cov[keep]
        if npc:
            pcs = np.loadtxt(os.path.join(resolve(c["output_dir"]), "pca.txt"), delimiter=",", ndmin=2)
            Z = np.column_stack([Z, pcs.T])
        Zs.append(Z); Ys.append(y[keep]); As.append(mats[0]); Ms.append(mats[1]); Es.append(mats[2])

    Z = np.vstack(Zs); Y = np.vstack(Ys); A = np.vstack(As); M = np.vstack(Ms); E = np.vstack(Es)
    Z_reg = np.column_stack([np.ones(Z.shape[0]), Z])
    thr = g.get("tractor_count_threshold", 0)
    ref = from_precomputed(precompute(y=Y, Z=Z_reg, A=A, X_AMR=M, X_EUR=E),
                           count_threshold=(thr if thr > 0 else None), det_tol=g.get("tractor_det_tol", 0.0))
    m = A.shape[1]
    out = resolve(loc[1]["output_dir"])
    idx_file = os.path.join(out, "tractor_snp_index.txt")
    if os.path.exists(idx_file):
        idx = [int(l) for l in open(idx_file) if l.strip()]
        if idx != list(np.flatnonzero(snp_keep)):
            sys.exit("tractor_snp_index.txt does not match the QC/block filters")
    else:  # output of a build that predates the index file: rows are all SNPs, in order
        print("  (no tractor_snp_index.txt: assuming one row per SNP, QC filters not applied)")
    print(f"{os.path.basename(run)}: n={Z_reg.shape[0]} m={m}/{m_all} q={Z_reg.shape[1]} p={Y.shape[1]} "
          f"count_threshold={thr} det_tol={g.get('tractor_det_tol')} notebook-valid={int(ref['valid'].sum())}")

    ok = True
    for k in range(Y.shape[1]):
        rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(out, f"tractor_{k}.txt"))]
        if len(rows) != m:
            print(f"  pheno {k}: output has {len(rows)} rows, expected {m}"); ok = False; continue
        got = np.array([[float(x) for x in r[:9]] for r in rows])
        gvalid = np.array([r[9] == "true" for r in rows])
        mism = int((gvalid != ref["valid"]).sum())
        both = gvalid & ref["valid"]
        worst = {"beta": 0.0, "se": 0.0, "t": 0.0, "log10p": 0.0}
        viol = 0
        for e, (cb, cs, cp) in {"A": (0, 1, 2), "AMR": (3, 4, 5), "EUR": (6, 7, 8)}.items():
            rb, rs, rt, rp = (np.asarray(ref[f"{s}_{e}"])[both, k] for s in ("beta", "se", "t", "p"))
            gb, gs, gp = got[both, cb], got[both, cs], got[both, cp]
            d = {"beta": np.abs(gb - rb) / rs, "se": np.abs(gs - rs) / rs, "t": np.abs(gb / gs - rt),
                 "log10p": np.abs(np.log10(np.maximum(gp, 5e-324)) - np.log10(np.maximum(rp, 5e-324)))}
            tol = {"beta": 1e-2, "se": 1e-3, "t": 1e-2 + 1e-3 * np.abs(rt), "log10p": 1e-2}
            for key in d:
                if d[key].size:
                    # NaN (e.g. a NaN SE) counts as a violation and makes the maximum NaN
                    worst[key] = float("nan") if np.isnan(d[key]).any() or np.isnan(worst[key]) else max(worst[key], float(d[key].max()))
                    viol += int((~(d[key] <= tol[key])).sum())
        print(f"  pheno {k}: compared {int(both.sum())}/{m}, validity mismatches {mism}, max |dbeta|/SE={worst['beta']:.3g} "
              f"|dSE|/SE={worst['se']:.3g} |dt|={worst['t']:.3g} |dlog10p|={worst['log10p']:.3g}, tolerance violations {viol}")
        ok = ok and mism == 0 and viol == 0
    print("  notebook check:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
