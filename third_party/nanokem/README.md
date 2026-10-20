# nanokem (vendored subset, one patch)

ML-KEM-768 and Keccak from [nanokem](https://github.com/Other-Now/nanokem)
(my from-scratch FIPS 203 implementation), commit `9986d50`:
`include/nanokem/{mlkem768,sha3,types}.h`, `src/{mlkem768,keccak}.c`.
Used only by `pq/`, which checks it byte-for-byte against OpenSSL 3.5's
ML-KEM-768 and against the Wycheproof ML-KEM vectors.

## Patch 0001: the cross-check found a real nonconformance

`patches/0001-fips203-final-keygen-domain-separator.patch`, one line in
`nk_mlkem768_keygen`: `G(d)` becomes `G(d || k)`.

Final FIPS 203 (August 2024), Algorithm 13 line 1, derives
`(rho, sigma) <- G(d || k)`; the domain-separation byte `k` was added after
the 2023 draft. nanokem used plain `G(d)`. Its own known-answer test agreed
with it because that vector file followed the draft convention, and a code
comment even records "fixing" the byte away to match it.

| `pq/pq_interop`, 2026-10-20 | upstream `9986d50` | patched |
|---|---:|---:|
| Wycheproof keygen-from-seed, nanokem `ek` | **0/100** | 100/100 |
| Wycheproof encaps (given `ek`, `m`), nanokem `(c, K)` | 133/133 | 133/133 |
| Wycheproof invalid `ek` rejected by nanokem | 132/132 | 132/132 |
| 1000 random seeds: same `ek` as OpenSSL | **0/1000** | 1000/1000 |
| same `(ct, ss)` for the same `m` | **0/1000** | 1000/1000 |
| each decapsulates the other's ciphertext | **0/1000** | 1000/1000 |
| same implicit-rejection key for a tampered ciphertext | 1000/1000 | 1000/1000 |

Full outputs: `results/pq-interop-nanokem-upstream-9986d50.txt`,
`results/pq-interop.txt`.

**What it did and did not break.** Encapsulation and decapsulation were
always correct: any peer that sends its encapsulation key as bytes
interoperates (the 133/133 row). What was wrong is the mapping from a
64-byte seed to a key pair, so a key stored as its seed (the private-key
form OpenSSL 3.5 and the IETF ML-KEM key-format draft prefer) would load as
a different key pair in nanokem than in any FIPS 203 implementation. The
implicit-rejection row stays 1000/1000 before the fix because that key is
`J(z || c)` and does not depend on `rho`/`sigma`.

The fix belongs upstream in nanokem as well; this copy carries it so the
interop test is green.
