# Study sheet: crypto-core-bridge

What to be able to say without notes, in rough order of how likely it is to
come up. Numbers are in README.md / MIGRATION.md; re-read those before
quoting.

## The 30-second version

One small crypto module, two implementations: C++20 on OpenSSL 3 and Rust on
RustCrypto, with the same API, the same PKCS#11 backend (SoftHSM2), and one C
ABI between them in both directions (Rust exported via cbindgen, C++
called via cxx). Only 32-byte key IDs cross the boundary. The evidence is
differential testing: the same random op sequences go into both, and every
status code and byte must match. That ran over ~47k software ops and ~3.3k
PKCS#11 ops with 0 divergences, and caught 8/8 planted port bugs. On top
of that: Wycheproof on both primitive layers, fuzzing, Miri, ASan/UBSan,
allocator-level zeroization checks, and measured per-op cost to decide
what to migrate first.

## Design decisions, and the "why"

**Key IDs from a KCV, not from the key.** A token can't hash a sensitive
key (`C_DigestKey` is refused for `CKA_SENSITIVE`), but it *can* run HMAC or
GCM with it. So ID = SHA-256(domain ‖ type ‖ KCV), where the KCV is an
operation the token performs. The same key gets the same ID whether it was
generated in the token or imported in software, and the tests check exactly
that.

**Why not `E_K(0)` as the AES KCV?** In GCM, `H = E_K(0^128)` is the GHASH
key. Publish it and anyone can forge tags (GHASH is linear in H). I used a
GCM tag over a fixed label under a *reserved* nonce (all 0xFF), which seal
refuses, random draws skip, and open refuses. One tag under a never-reused
nonce leaks nothing useful (you need two messages under one nonce to solve
for H).

**Error codes are part of the contract.** "Same behaviour" has to include
failures, or a port can be "correct" and still change what callers see.
The order of checks is specified (CONTRACT.md §3). The planted-bug test
shows the engine notices a swapped check order.

**One code for every authentication failure.** A short ciphertext, a bad tag,
the wrong key and the reserved nonce are all `VERIFY_FAILED`, so there is no
oracle.

**C ABI rules**: `(ptr,len)` with NULL only when `len==0`; `len ≤ isize::MAX`
(else `slice::from_raw_parts` is UB); capacity checked *before* the op, with
nothing written on `BUFFER_TOO_SMALL`; outputs must not overlap inputs
(we build `&[u8]` from inputs, and writing through an aliasing `*mut` would
break Rust's aliasing rules); the context is an opaque `Box::into_raw`
pointer; `ccb_ctx_free(NULL)` is a no-op.

**Panics**: since Rust 1.81 a panic escaping an `extern "C"` fn aborts the
process (before that it was UB). Neither is acceptable in a host process, so
every entry point is `catch_unwind` → `CCB_ERR_PANIC`. Caveats:
`catch_unwind` does nothing under `panic = "abort"`, and a panic while
the mutex is held poisons the context, so later calls report `PANIC`
instead of running on half-updated state.

**Send/Sync**: `ccb_ctx` is `Send + Sync` because it is a
`Mutex<Box<dyn KeyStore>>` with `KeyStore: Send`, and that is
asserted at compile time. PKCS#11 sessions are not thread-safe, so
serialising per context is the honest model. `CppStore` (the cxx type) gets
`unsafe impl Send` with a SAFETY note (its C++ side has its own mutex);
it is not `Sync`.

**cxx vs bindgen for Rust → C++**: cxx needs no libclang, checks both sides'
signatures at build time, owns the C++ object through `UniquePtr` (Drop
calls `delete`), and gives slices without hand-written `unsafe`. The C++
API returns status codes, never throws, so no `Result`/exception mapping was
needed.

**Zeroization**: C++ `Secret` (non-copyable, fixed buffer, `OPENSSL_cleanse`
in the destructor). Rust `Box<Zeroizing<[u8; 32]>>`. The `Box` matters:
`HashMap` rehash `memcpy`s values to a new table and frees the old one
**without running Drop**, so `Zeroizing` stored inline leaves copies (the
zeroize test's control finds 5).

## How the evidence works

* **Differential engine** (`crates/ccb-cpp/src/diff.rs`): bytes → ops
  (import/generate/destroy/wrap/unwrap/sign/verify/seal/open/hkdf/cross-open).
  Keys imported from the same bytes have equal IDs, so outputs must be
  byte-identical. Generated keys differ per side and are tracked as pairs
  (statuses and lengths only). The same engine is driven by seeded bytes
  (tests) and fuzzer bytes (`fuzz/differential`).
* **Does it work?** 8 planted bugs (wrong code, swapped check order, reserved
  nonce accepted, AAD ignored, salt/info swapped, export flag ignored, wrong
  ID derivation, …): 8/8 caught. The point: a 0-divergence result is only
  meaningful if you know the harness can find divergences.
* **PKCS#11 differential**: each implementation gets its own token (object
  sets evolve independently); tokens are wiped per seed because objects
  persist across runs.
* **Zeroization check**: hook every free (OpenSSL via
  `CRYPTO_set_mem_functions`, C++ via global `operator new/delete`, Rust via
  `#[global_allocator]`), scan the block for 16-byte windows of the test
  keys (raw and word-byteswapped, since table AES stores the first round
  keys that way), with positive controls. Limit: heap only. The stack and
  registers aren't covered.
* **Miri**: all hand-written `unsafe` is in `ffi.rs`; `tests/miri.rs` drives
  every entry point with the pure-Rust backend. Miri can't call C, so the
  PKCS#11 constructor is compiled to return `UNSUPPORTED` under `cfg(miri)`
  *after* its pointer/string handling.

## Findings (the stories)

1. SoftHSM returns `CKR_GENERAL_ERROR` for a bad GCM tag → mapped to
   `VERIFY_FAILED` only on `C_Decrypt`/`C_UnwrapKey`.
2. Linking a Rust staticlib drops CET from the C++ binary (GNU property
   notes are ANDed; rustc stable emits none).
3. cxx: growing a `rust::Vec` with `push_back` is one call into Rust per byte,
   which made the bridge 16× slower than the C++ it wrapped at 16 KiB. Fix:
   Rust pre-sizes a `&mut [u8]` and C++ does one `memcpy`.
4. PKCS#11: `C_FindObjects` ≈ 0.5 ms on SoftHSM vs ~50 µs for the HMAC
   itself. Handle cache → ~5×. The cache is re-validated per hit (`CKA_ID` +
   type in one `C_GetAttributeValue`), because handles may be reused and a
   stale handle could name a *different* key.
5. Rust PKCS#11 is ~1.4× the C++ one: `cryptoki::get_attributes` can't
   pre-size a variable-length attribute (`CKA_ID`), so it makes two
   `C_GetAttributeValue` calls, at ~40 µs each on SoftHSM token objects.
6. OpenSSL 3 per-call overhead: an algorithm fetch is 153–181 ns per call
   (bench attribution rows); the core fetches once. Rust is still 0.28–0.73×
   of C++ on small ops: the rest is provider-path setup, not decomposed
   further. Bulk GCM is the reverse (OpenSSL 5–9× faster at 16 KiB, VAES
   assembly).
7. ML-KEM stretch: OpenSSL 3.5 + Wycheproof showed my nanokem KeyGen used the
   draft `G(d)` instead of final FIPS 203 `G(d‖k)`. Encaps/decaps were fine,
   but seed→key-pair was not. The one-byte fix took it from 0/100 to 100/100.
   Lesson: a KAT from the wrong revision of a standard can "verify" a bug.
8. CI: GitHub's default `bash -e` has no `pipefail`; `cargo test | tee`
   would have passed with failing tests. The fuzz job "passed" in 22 s
   without fuzzing, which is how it was noticed.

## Likely questions

* *How do you know the two implementations are equivalent?* You don't prove
  it. You make divergence observable (statuses + bytes), drive it with
  random and coverage-guided input, and show the harness catches planted
  divergences. Wycheproof pins both to the spec, not just to each other.
* *Why not just test against vectors?* Vectors test primitives. The port bugs
  that matter are in the glue: check order, error mapping, dedup semantics,
  buffer handling. All 8 planted bugs sit above the primitive layer, so all
  8 would pass every Wycheproof vector.
* *What crosses the boundary?* Key IDs, caller-owned buffers, status codes.
  Never key bytes, never Rust-allocated memory, never exceptions or panics.
* *What would you migrate first?* See MIGRATION.md; the answer comes from the
  measurements.
* *What would change with a real HSM?* Per-op cost moves from SoftHSM's file
  object store to device latency, and handle-cache invalidation matters more
  (multi-process / clustered HSMs). `CKM_HKDF_DERIVE` and
  `CKA_WRAP_WITH_TRUSTED` become available.
* *Is the FFI crossing expensive?* No: ~1.5 ns for a bare call, the same as a
  noinline C++ call, because it *is* a plain C call. The cost is in what you
  do at the boundary (copies, zeroizing, locking), not in the crossing.
