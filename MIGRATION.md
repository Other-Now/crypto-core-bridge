# MIGRATION.md: what to move to Rust first

**Recommendation: move the key-store and key-derivation module first** (key
lifecycle, key-ID derivation, HKDF, HMAC, and the C ABI that takes caller
input). **Leave bulk AES-GCM on OpenSSL's assembly** for now, even after
the module moves. **Move the PKCS#11 backend last.** The measurements behind
each part follow.

## Where the numbers come from

* **CI**: GitHub Actions run 39369946741, AMD EPYC 9V45 (4 vCPU), Ubuntu 24.04,
  OpenSSL 3.0.13, Rust stable. CSV: `results/bench-ci-ubuntu-24.04.csv`.
* **Local**: i5-9300H under WSL2, pinned to one core, run only when no other
  process was busy (the run is discarded and repeated if one starts).
  CSV: `results/bench-wsl-i5-9300H.csv`.
* Method (both harnesses, `cpp/bench/bench.cpp` and
  `crates/ccb-cpp/examples/bench.rs`): N calls per repetition with N calibrated to
  about 20 ms; 15 repetitions; the median is reported and min/max are in the CSV.
  Each op goes through the full store path (key lookup, the primitive, and
  the output buffer), not just the primitive.

## 1. The boundary itself is free

| | CI (9V45) | local (i5) |
|---|---:|---:|
| bare `ccb_abi_version()` through the C ABI | 0.9 ns | 1.2 ns |
| a `noinline` C++ call, for comparison | 1.0 ns | 1.2 ns |

A C ABI call is a plain call. What costs time is the work done at the
boundary, and in this code that is small:

| CI, median | Rust direct | Rust through its C ABI (from Rust) | Rust through its C ABI (from C++) |
|---|---:|---:|---:|
| hmac_sign 64 B | 226 ns | 229 ns | 235 ns |
| seal 1 KiB | 1271 ns | 1235 ns | 1288 ns |
| open 16 KiB | 11.5 µs | 13.6 µs | 13.5 µs |

The ABI layer (`catch_unwind`, mutex, pointer checks, copy-out) is within
noise everywhere except `open` on large inputs. There it adds ~2 µs at
16 KiB, and **1.83 µs of that is zeroizing the intermediate plaintext** (the
`zeroize_vec` attribution row: 7 ns / 114 ns / 1830 ns at 64 B / 1 KiB / 16 KiB).
That cost comes from a policy choice, not from the crossing.

The other direction is similar: C++ called from Rust through cxx is +0–22%
over C++ called directly (`hmac_sign` 64 B: 752 vs 715 ns; the worst case is
`open` 1 KiB, 551 vs 453 ns, one extra copy into the Rust-owned buffer). That held only
after one fix. The first version of the cxx shim grew a `rust::Vec` one
`push_back` (one call into Rust) per byte, and was **16× slower** than the C++
it wrapped (seal 16 KiB, local: 119.9 µs through cxx vs 7.5 µs direct;
`results/bench-wsl-i5-9300H-before-cxx-fix.csv`). Now Rust pre-sizes a
`&mut [u8]` and C++ does one `memcpy`: 9.3 vs 7.3 µs.

**So the boundary does not decide what to migrate.** A module can move
without its callers paying for the crossing.

## 2. Rust vs C++ on the software path

| op | size | C++ (OpenSSL 3) CI | Rust (RustCrypto) CI | Rust/C++ CI | Rust/C++ local |
|---|---:|---:|---:|---:|---:|
| hmac_sign | 64 | 715 ns | 226 ns | 0.32× | 0.79× |
| hmac_sign | 1024 | 1154 ns | 675 ns | 0.58× | 1.42× |
| hmac_sign | 16384 | 8.3 µs | 7.8 µs | 0.94× | 2.55× |
| hkdf_derive | 32 | 2544 ns | 711 ns | 0.28× | 0.77× |
| seal | 64 | 1131 ns | 608 ns | 0.54× | 0.60× |
| seal | 1024 | 1300 ns | 1271 ns | 0.98× | 0.96× |
| seal | 16384 | 2.2 µs | 11.9 µs | **5.54×** | 2.25× |
| open | 64 | 354 ns | 260 ns | 0.73× | 0.47× |
| open | 1024 | 453 ns | 924 ns | 2.04× | 1.28× |
| open | 16384 | 1.3 µs | 11.5 µs | **9.15×** | 3.12× |

Two regimes:

* **Small operations: Rust is faster** (0.28–0.73× for HMAC, HKDF and
  64 B seal/open on CI). OpenSSL 3 pays a fixed per-call cost on its
  provider path: context allocation, `OSSL_PARAM` decoding, dispatch. An
  algorithm fetch is 153 ns (HMAC) / 181 ns (AES-256-GCM) per call (attribution
  rows), which the C++ core already avoids by fetching once
  (`primitives.cpp`). The rest of the gap was not decomposed further.
* **Bulk AES-GCM: OpenSSL is much faster** (5.5× seal, 9.2× open at 16 KiB
  on CI). OpenSSL has hand-written AES-GCM assembly (VAES/AVX-512 on this Zen 5
  part), and RustCrypto uses AES-NI plus a CLMUL POLYVAL. The gap is smaller on
  the older i5 (2.3×/3.1×), which has no VAES. HMAC at 16 KiB is even on CI
  because both use SHA-NI; the i5 has no SHA-NI, so there OpenSSL's AVX2
  SHA-256 wins (2.55×).

## 3. PKCS#11: the token dominates

| CI, median | C++ backend | Rust backend (cryptoki) |
|---|---:|---:|
| hmac_sign 64 B | 38.4 µs | 57.4 µs |
| seal 1 KiB | 39.9 µs | 55.9 µs |
| open 1 KiB | 39.0 µs | 56.9 µs |

* Both backends started near **0.45 ms per operation** (local), because
  every operation ran `C_FindObjects`, which costs ~0.5 ms on SoftHSM's file
  store (a direct probe measured 506 µs vs 51 µs for the in-token HMAC
  itself). A KeyId→handle cache, re-validated on every hit, cut that ~5×
  (local 446–460 µs → 83–101 µs).
* The Rust backend is **~1.45× the C++ one** (57 vs 39 µs on CI), and the gap
  is one token round trip. Re-validating a cached handle reads `CKA_ID` and
  the key type. C++ does that in one `C_GetAttributeValue` with a 32-byte
  buffer it sized itself. `cryptoki`'s safe `get_attributes` cannot be told
  the size of a variable-length attribute, so it makes two calls.

## Recommendation, part by part

**1. First: the key store, key IDs, HKDF, HMAC, and the boundary layer.**
* This is the code that takes untrusted lengths and pointers, owns secret
  buffers, and manages their lifetimes. Memory-safety bugs live there, and
  Rust removes them (all 32 `unsafe` blocks sit in one audited, Miri-checked
  file).
* Performance is equal or better: 0.28–0.58× on HKDF and HMAC up to 1 KiB,
  and the crossing costs about 1 ns.
* The differential harness can gate the switch: 0 divergences in 47k ops,
  with 8/8 planted port bugs caught.

**2. Bulk AES-GCM moves with the module, but not onto RustCrypto.** Keep
OpenSSL's GCM behind the Rust API: the Rust store calls the C++ primitive
through cxx (the stage-2 direction this repo already has, +0–22% overhead).
The alternative is a Rust crate that wraps vendor assembly (aws-lc-rs; not
measured here). At 16 KiB, RustCrypto would cost 5–9× on this hardware. The
rule is to move the module's logic, not necessarily its assembly.

**3. Last: the PKCS#11 backend.**
* It is thin glue, and the secrets stay in the token, so the memory-safety
  gain is smallest here.
* Per-operation cost is set by the token.
* Today the Rust version costs +18 µs per operation on SoftHSM. Before
  switching, remove the second `C_GetAttributeValue`: read `CKA_ID` into a
  caller-sized buffer through cryptoki's raw function list, or cache the
  key type and validate the handle with a fixed-size attribute.
* Then rerun the PKCS#11 differential test, which already proves the two
  backends agree on statuses and bytes.

**Gate for every step:** the differential suite (software and PKCS#11), the
planted-bug check, Wycheproof on both sides, and the fuzzers, all in CI.
Switch the module only when the gate is green.

## Caveats

* SoftHSM is not an HSM: its cost profile (file-backed objects, a re-read on
  each access) is far from a network or PCIe HSM's. The *ratios* between the
  backends are the meaningful part, not the absolute microseconds.
* GitHub runners vary: the run before this one landed on an EPYC 9V74
  (Zen 4) and measured C++ seal at 16 KiB as 3.7 µs instead of 2.2 µs. The
  ordering and regimes above held on both CI machines and on the local i5.
