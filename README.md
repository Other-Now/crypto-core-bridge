# crypto-core-bridge

A small C++20 "crypto core" on OpenSSL 3 and a Rust implementation of the
same module. Both sit behind one C-ABI boundary, both run on the same
PKCS#11 key store (SoftHSM2), and the tests show they behave identically.
This is the C++ → Rust migration of a security module at small scale: two
implementations, one contract, and evidence the contract holds.

```
             C++ caller                                   Rust caller
                 │                                             │
                 │ include/ccb.h  (cbindgen)                   │ cxx bridge
                 ▼                                             ▼
   ┌──────────────────────────┐                 ┌──────────────────────────┐
   │ Rust impl  crates/ccb    │   same contract │ C++ core  cpp/           │
   │  ffi.rs: catch_unwind,   │  ◄────────────► │  OpenSSL 3 EVP only      │
   │  NULL/len checks, mutex  │  docs/CONTRACT  │  KeyStore interface      │
   │  RustCrypto, zeroize     │                 │  OPENSSL_cleanse         │
   │  software │ PKCS#11      │                 │  software │ PKCS#11      │
   │           │ (cryptoki)   │                 │           │ (dlopen)     │
   └───────────┴──────┬───────┘                 └───────────┴──────┬───────┘
                      └──────────────► SoftHSM2 token ◄────────────┘
                                 (keys found by CKA_ID = key ID)
```

**Only key IDs cross the boundary.** A key ID is SHA-256 over the key type
and a key check value that a PKCS#11 token can compute *inside* the token,
so a key generated in the HSM by C++ is usable from Rust knowing only its
32-byte ID, and gets the same ID in every backend.

## What it does

| | C++ core | Rust implementation |
|---|---|---|
| Primitives | OpenSSL 3 `EVP_MAC` / `EVP_CIPHER` / `EVP_KDF` | RustCrypto (`hmac`, `aes-gcm`, `hkdf`, `aes-kw`) |
| Key lifecycle | generate, import, wrap/unwrap (RFC 3394), destroy | same |
| Operations | HMAC-SHA256 sign/verify, AES-256-GCM seal/open, HKDF-SHA256 derive | same |
| Secrets | `ccb::Secret`, wiped with `OPENSSL_cleanse` | `Zeroizing<…>` (boxed; see below) |
| PKCS#11 | `dlopen` + `C_GetFunctionList`, in-token `CKM_SHA256_HMAC`, `CKM_AES_GCM`, `CKM_AES_KEY_WRAP` | `cryptoki` 0.12, same mechanisms and templates |
| Non-extractable | `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE` only for keys created exportable; even those leave only wrapped | same |
| Boundary | called from Rust through `cxx` | exported to C/C++ through `cbindgen` (`include/ccb.h`) |

The full behavioural contract (check order, error codes, formats,
ownership, threading) is [docs/CONTRACT.md](docs/CONTRACT.md).

## Evidence

All numbers from 2026-10-20. Local = i5-9300H under WSL2; CI = GitHub Actions
(the same suites run in every CI build; all 8 jobs green).

### Conformance

| check | result |
|---|---|
| Differential, software stores, Rust vs C++ (`tests/differential.rs`) | **46,848 random ops over 200 seeds, 0 divergences** in status or output |
| Differential, PKCS#11 stores, Rust vs C++, one SoftHSM token each | **3,340 ops over 10 seeds, 0 divergences** |
| Does the differential engine catch real port bugs? | **8/8 planted bugs caught** (wrong error code, check order swapped, AAD ignored, salt/info swapped, …), 7 of them on the first seed |
| Wycheproof on both primitive layers | AES-256-GCM 66/66 in scope (of 316), AES-256-KW 68/68 (of 165), HMAC-SHA256 174/174, HKDF-SHA256 86/86 |
| Cross-language, one process (`cpp/tests/xlang.cpp`) | 91/91: Rust seals → C++ opens and back; same tags, same ciphertexts under a fixed nonce, same wrap blobs, same derived-key IDs; a key generated *in the token by C++* used from Rust by ID only |
| Token vs host key IDs | a key generated inside SoftHSM (in-token KCV) gets the same ID once unwrapped into the software store (host KCV) |
| C++ unit suite, both backends | 148/148 |

### Security testing

| check | result |
|---|---|
| `cargo-fuzz` `ffi_ops` (raw C ABI: NULLs, short buffers, garbage IDs, canary-checked outputs) | CI: **1.92M execs in 5 min, 0 crashes** |
| `cargo-fuzz` `differential` (fuzzer bytes → op sequence on both implementations) | CI: **1.27M execs in 5 min, 0 divergences** |
| Miri on every `unsafe` block (FFI layer driven with the pure-Rust backend) | clean |
| C++ under ASan + UBSan (unit, cross-language, zeroize) | clean |
| Zeroization, C++ (OpenSSL + `operator new` hooked, every freed block scanned) | 0 key hits in 6,217 freed blocks; positive control caught |
| Zeroization, Rust (scanning `#[global_allocator]`) | 0 key hits in 786 freed blocks; two positive controls caught |
| `cargo-deny` / `cargo-audit` | advisories, bans, licenses, sources ok / 0 vulnerabilities in 75 crates |
| `unsafe` | 32 blocks, all in `ffi.rs`, 32 `SAFETY:` comments (`clippy::undocumented_unsafe_blocks`); 1 `unsafe impl Send` for the cxx type |
| Hardened build (`scripts/checksec.sh`) | PIE, full RELRO, NX, stack protector, `_FORTIFY_SOURCE=3`, CET on the C++ binaries — **but not** on a binary that links the Rust staticlib (see findings) |

### Cost per operation (CI, AMD EPYC 9V45, median of 15)

| | C++ (OpenSSL 3) | Rust (RustCrypto) | Rust/C++ |
|---|---:|---:|---:|
| HMAC-SHA256, 64 B | 715 ns | 226 ns | 0.32× |
| HKDF derive | 2544 ns | 711 ns | 0.28× |
| AES-GCM seal, 1 KiB | 1300 ns | 1271 ns | 0.98× |
| AES-GCM seal, 16 KiB | 2.2 µs | 11.9 µs | 5.5× |
| AES-GCM open, 16 KiB | 1.3 µs | 11.5 µs | 9.2× |
| PKCS#11 (SoftHSM2) HMAC, 64 B | 38.4 µs | 57.4 µs | 1.5× |
| bare C-ABI call / noinline C++ call | 0.9 ns / 1.0 ns | | |

Rust wins small operations (OpenSSL 3's per-call provider overhead);
OpenSSL's AES-GCM assembly wins bulk. The boundary costs what any call
costs. [MIGRATION.md](MIGRATION.md) has the full tables, the local numbers,
and the recommendation that follows from them.

## Findings worth retelling

1. **The textbook AES key check value would have leaked the GCM hash key.**
   `E_K(0^128)` is GCM's `H`. Key IDs use a GCM tag under a reserved nonce
   instead, and the reserved nonce is refused everywhere else.
2. **SoftHSM reports a GCM tag failure as `CKR_GENERAL_ERROR`.** The first
   PKCS#11 run returned `BACKEND` where software returned `VERIFY_FAILED`.
   Both backends now map it on `C_Decrypt` / `C_UnwrapKey` only.
3. **`Zeroizing` inline in a `HashMap` leaks.** A rehash moves entries with
   `memcpy` and frees the old table without running destructors; the Rust
   zeroize test's control finds 5 stale copies. The store boxes keys.
4. **Linking a Rust staticlib silently strips CET from the C++ binary.** The
   linker ANDs the GNU property notes of every object, and stable rustc /
   the prebuilt std emit none. `checksec` shows IBT/SHSTK on `test_core`,
   not on `xlang`.
5. **The cxx bridge was 16× slower than the C++ it bridged** at 16 KiB, until
   outputs went into a Rust-presized slice instead of a `rust::Vec` grown by
   `push_back` (one call into Rust per byte).
6. **`C_FindObjects` dominated every PKCS#11 operation.** A direct probe
   measured 506 µs per lookup vs 51 µs for the in-token HMAC itself. A
   KeyId→handle cache, re-validated on every hit because PKCS#11 does not
   promise handles are never reused, cut an operation ~5× (local
   446–460 µs → 83–101 µs). The Rust side stays ~1.45× slower because
   `cryptoki`'s safe `get_attributes` needs two `C_GetAttributeValue` calls
   for a variable-length attribute.
7. **Stretch goal: OpenSSL 3.5 found a bug in my own ML-KEM.** nanokem's
   KeyGen used the 2023-draft `G(d)` instead of final FIPS 203's `G(d ‖ k)`:
   0/100 Wycheproof keygen vectors, 0/1000 seed cross-checks; 100/100 and
   1000/1000 after a one-line patch. See
   [third_party/nanokem/README.md](third_party/nanokem/README.md).
8. **CI that could not fail.** GitHub's default `bash -e` has no `pipefail`,
   so `cargo test | tee log` reports `tee`'s status. Noticed when the fuzz
   job "passed" in 22 s without fuzzing (a musl `cargo-fuzz` cannot build
   with sanitizers); fixed for every job.

## Post-quantum stretch (OpenSSL 3.5.9)

| check | result |
|---|---|
| ML-KEM-768 keygen from seed, Wycheproof | nanokem 100/100 (patched; 0/100 upstream), OpenSSL 100/100 (`ek` and `dk`) |
| ML-KEM-768 encaps, Wycheproof | valid `(c, K)` byte-exact on both 133/133; invalid keys rejected by both 132/132 |
| 1000 random seeds, nanokem vs OpenSSL | same `ek`, same `(ct, ss)`, each decapsulates the other's, same implicit-rejection key: 1000/1000 each |
| ML-DSA-65 (OpenSSL), Wycheproof verify incl. context strings | 210/210 |

## Layout

```
cpp/            C++ core (include/ccb/core.hpp, src/), tests/, bench/
crates/ccb/     Rust implementation; src/ffi.rs is the C ABI (all the unsafe)
crates/ccb-cpp/ C++ core behind cxx as a Rust KeyStore; differential engine;
                tests/differential.rs, tests/wycheproof.rs; examples/bench.rs
include/ccb.h   generated by cbindgen (CI fails if stale)
fuzz/           cargo-fuzz targets: ffi_ops, differential
pq/             ML-KEM / ML-DSA interop against OpenSSL 3.5
third_party/    PKCS#11 2.40 headers, vendored nanokem subset (+1 patch)
testvectors/    Wycheproof JSON
docs/CONTRACT.md, THREAT_MODEL.md, MIGRATION.md, docs/NOTES.md
```

## Running it

Linux (or WSL) with gcc ≥ 12, CMake, Ninja, OpenSSL 3 headers, Rust stable
(+ nightly for Miri/fuzz). No root needed: `scripts/fetch-softhsm.sh`
unpacks SoftHSM2 from the Ubuntu debs.

```bash
bash scripts/fetch-softhsm.sh && bash scripts/init-token.sh   # two tokens: ccb, ccb-b
source scripts/env.sh
cargo test --release --workspace --all-features -- --nocapture --test-threads=1
bash scripts/build-cpp.sh release && $CCB_BUILD/release/xlang   # also: test_core, zeroize_check
bash scripts/build-cpp.sh asan                                 # ASan + UBSan build
cargo +nightly miri test -p ccb --features test-hooks --test miri
(cd fuzz && cargo +nightly fuzz run -O differential -- -max_total_time=300)
bash scripts/bench.sh 15
bash scripts/build-openssl35.sh 3.5.9 && bash scripts/pq.sh    # PQ stretch
```

## Not done

* No real HSM: everything PKCS#11 is SoftHSM2 2.6.1, whose costs (file-backed
  object store) are not representative of hardware.
* HKDF is software-only (SoftHSM has no `CKM_HKDF_DERIVE`).
* The C++ code under `cargo fuzz` is compiled by gcc without coverage
  instrumentation, so the fuzzer is guided by Rust-side coverage only;
  ASan/UBSan for C++ run in the CMake build instead.
* Key-usage separation is coarse: an AES key can both seal and wrap.
