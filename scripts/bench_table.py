#!/usr/bin/env python3
"""Turns a bench CSV into the markdown tables used in README / MIGRATION.md.

Usage: bench_table.py results/bench-<host>.csv
"""
import csv
import sys
from collections import defaultdict

rows = list(csv.DictReader(open(sys.argv[1])))
cell = {(r["impl"], r["op"], int(r["size"])): r for r in rows}


def fmt(r):
    if r is None:
        return "-"
    med, lo, hi = float(r["median_ns"]), float(r["min_ns"]), float(r["max_ns"])
    if med >= 10000:
        return f"{med/1000:.1f} µs"
    return f"{med:.0f} ns"


def rng(r):
    return f"{float(r['min_ns']):.0f}–{float(r['max_ns']):.0f}" if r else "-"


print("### Software backends (median ns/op; 15 reps)\n")
impls = ["cpp", "cpp-cxx", "rust", "rust-cabi-rs", "rust-cabi"]
heads = {
    "cpp": "C++ direct",
    "cpp-cxx": "C++ via cxx (from Rust)",
    "rust": "Rust direct",
    "rust-cabi-rs": "Rust via C ABI (from Rust)",
    "rust-cabi": "Rust via C ABI (from C++)",
}
print("| op | size | " + " | ".join(heads[i] for i in impls) + " | Rust/C++ |")
print("|---|---:|" + "---:|" * (len(impls) + 1))
ops = [("hmac_sign", s) for s in (64, 1024, 16384)] + [("seal", s) for s in (64, 1024, 16384)] + [
    ("open", s) for s in (64, 1024, 16384)
] + [("hkdf_derive", 32)]
for op, sz in ops:
    cs = [cell.get((i, op, sz)) for i in impls]
    c, r = cell.get(("cpp", op, sz)), cell.get(("rust", op, sz))
    ratio = f"{float(r['median_ns'])/float(c['median_ns']):.2f}×" if c and r else "-"
    print(f"| {op} | {sz} | " + " | ".join(fmt(x) for x in cs) + f" | {ratio} |")

print("\n### Bare crossing\n")
for op in ("noinline_cpp_call", "c_abi_call"):
    r = cell.get(("crossing", op, 0))
    if r:
        print(f"- {op}: {float(r['median_ns']):.2f} ns (min–max {rng(r)})")

z = [cell.get(("attrib", "zeroize_vec", sz)) for sz in (64, 1024, 16384)]
if all(z):
    print("\n- zeroize of the intermediate plaintext (64 / 1024 / 16384 B): " + " / ".join(fmt(x) for x in z))

p11 = [i for i in ("cpp-p11", "cpp-cxx-p11", "rust-p11", "rust-cabi-p11") if any(k[0] == i for k in cell)]
if p11:
    print("\n### PKCS#11 backends, SoftHSM2 (median ns/op)\n")
    print("| op | size | " + " | ".join(p11) + " |")
    print("|---|---:|" + "---:|" * len(p11))
    for op in ("hmac_sign", "seal", "open"):
        for sz in (64, 1024):
            print(f"| {op} | {sz} | " + " | ".join(fmt(cell.get((i, op, sz))) for i in p11) + " |")
