#!/usr/bin/env python3
"""Flattens the Wycheproof PQ vectors into a line format the C++ harness can
read without a JSON library: one test per line, `key=hex` fields separated by
spaces, group-level fields (publicKey) repeated on every line.

Usage: flatten_vectors.py WYCHEPROOF_DIR OUT_DIR
"""
import json
import os
import sys

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
for name, fields in [
    ("mlkem_768_keygen_seed_test", ["seed", "ek", "dk"]),
    ("mlkem_768_encaps_test", ["m", "ek", "c", "K"]),
    ("mldsa_65_verify_test", ["publicKey", "msg", "sig", "ctx"]),
]:
    data = json.load(open(os.path.join(src, name + ".json")))
    lines = []
    for g in data["testGroups"]:
        for t in g["tests"]:
            kv = {**{k: v for k, v in g.items() if isinstance(v, str)}, **t}
            parts = [f"tc={t['tcId']}", f"result={t['result']}", f"has_ctx={int('ctx' in t)}"]
            parts += [f"{f}={kv.get(f, '')}" for f in fields]
            lines.append(" ".join(parts))
    with open(os.path.join(out, name + ".txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{name}: {len(lines)} tests")
