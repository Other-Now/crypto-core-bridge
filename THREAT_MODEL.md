# Threat model: the C++ ⇄ Rust boundary

Scope: the boundary itself. That covers the C ABI exported by the Rust
implementation (`include/ccb.h`), the cxx bridge into the C++ core, and the
two PKCS#11 backends sharing a token. It does not cover the cryptographic
primitives (OpenSSL, RustCrypto) or SoftHSM itself.

## Assets

| asset | where it lives | must not |
|---|---|---|
| Key material | software store memory (`ccb::Secret`, `Box<Zeroizing<[u8; 32]>>`), or inside the token | cross the API in clear; outlive its key in freed memory |
| Integrity of results | every return code and output buffer | report success for a failed authentication; disagree between implementations |
| The process | the C++ host that loads the Rust library, and vice versa | be crashed or corrupted by malformed input at the boundary |
| PKCS#11 PIN | passed once at context creation | be kept or logged by the library |

## Trust boundaries

1. **Caller → C ABI.** The caller is trusted to follow the ABI (valid
   pointers, non-overlapping buffers, no use after `ccb_ctx_free`). The
   *data* the caller passes is not trusted: message, AAD, ciphertext, wrapped
   blob and key ID can all be attacker-influenced.
2. **Rust ⇄ C++ in one process.** Neither side may unwind into the other, or
   assume the other's allocator, or hold the other's pointers past a call.
3. **Library → token.** The token is trusted to keep sensitive keys inside,
   not to return well-formed error codes (see T7).

## Threats and mitigations

| # | threat | mitigation | evidence |
|---|---|---|---|
| T1 | Raw key bytes cross the boundary (logged, copied into caller memory, leaked to a less-trusted module) | The API names keys by a 32-byte ID only. No function returns key bytes. Export is only as an AES-KW blob, only for keys created `EXPORTABLE`, and in PKCS#11 only via `C_WrapKey` from a `CKA_SENSITIVE` object | `ccb.h` has no key-returning function; `NOT_EXTRACTABLE` asserted in unit, xlang and differential tests |
| T2 | The key ID leaks something about the key | ID = SHA-256 over a key check value. The obvious AES KCV, `E_K(0^128)`, **is GCM's hash subkey H** (it would enable tag forgery), so the KCV is a GCM tag under a nonce reserved for this purpose; `seal` refuses that nonce, random nonces are redrawn, `open` refuses inputs carrying it | `CONTRACT.md` §2; the test that the KCV does not open as a ciphertext |
| T3 | Memory-safety bug at the boundary (NULL with nonzero length, huge length, short output buffer, overlapping buffers) | Every `(ptr, len)` goes through one checked helper (`NULL` only with `len == 0`, `len ≤ isize::MAX`); output capacity is checked *before* the operation and nothing is written on `BUFFER_TOO_SMALL`. All 32 `unsafe` blocks are in `ffi.rs`, each with a `SAFETY:` argument | Miri over every block; `ffi_ops` fuzzer with canary-filled outputs; ASan/UBSan on the C++ callers |
| T4 | A Rust panic unwinds into C++ (UB before Rust 1.81, abort since) | Every entry point runs inside `catch_unwind` → `CCB_ERR_PANIC`; `ccb_ctx_free` too. A context whose mutex was poisoned by a panic refuses further calls | `ccb_test_panic()` asserted from C++ (`xlang`) and under Miri |
| T5 | C++ exception or error crossing into Rust | The C++ core does not throw across its API: every method returns `ccb::Status`; the cxx bridge passes `int32_t` codes, mapped back by one function; an unknown code becomes `INTERNAL` | compile-time `static_assert`s that both enums match |
| T6 | Error oracle: different failures distinguishable to an attacker | Every authentication failure (short input, bad tag, wrong key, reserved nonce, KW integrity) is the single code `VERIFY_FAILED`; HMAC compare is constant-time (`CRYPTO_memcmp`, `subtle`); unauthenticated GCM plaintext is wiped before returning | differential tests compare codes, not just success |
| T7 | Backend error codes differ from the spec, so a forged ciphertext looks like an outage | SoftHSM returns `CKR_GENERAL_ERROR` for a GCM tag mismatch; both backends map it to `VERIFY_FAILED` on `C_Decrypt`/`C_UnwrapKey` only (fail closed) | found by the C++ unit suite; held equal by the PKCS#11 differential test |
| T8 | Stale PKCS#11 handle names a different key (handle reuse after another process / library destroys a key) | Handle cache is re-validated on every hit (`CKA_ID` + key type in one call); mismatch or invalid handle → full `C_FindObjects` | xlang: C++ destroys a key Rust has cached → Rust gets `NO_SUCH_KEY` |
| T9 | Secrets left in freed heap memory | C++: `ccb::Secret` + `OPENSSL_cleanse`; Rust: `Zeroizing`, keys **boxed** so map rehashes move only pointers | allocator-hook scans: 0 hits (C++ 6,217 frees, Rust 786 frees), with positive controls including the inline-`HashMap` leak |
| T10 | Concurrency: two threads in one session / context | Each context serialises calls on a mutex (`Send + Sync`); `CppStore` is `Send`, not `Sync` | 8 threads × 2,000 seal/open on one context in `xlang` |
| T11 | Use after free / double free of a context | Not prevented (C ABI ownership); `ccb_ctx_free(NULL)` is a no-op; documented as caller contract | — |
| T12 | Exploit hardening missing on shipped binaries | `_FORTIFY_SOURCE=3`, PIE, full RELRO, NX, `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full` | `scripts/checksec.sh` in CI |
| T13 | Supply chain | `cargo-deny` (advisories, licenses, sources, bans), `cargo-audit`; `Cargo.lock` committed; PKCS#11 headers vendored from OASIS | CI `supply-chain` job |

## Known gaps

* **CET is lost when the Rust staticlib is linked.** The linker ANDs the
  GNU property notes of all objects; stable rustc and the prebuilt std do
  not emit IBT/SHSTK, so `xlang` has no CET even though every C++ object was
  built with `-fcf-protection=full`. Closing it needs nightly
  `-Zcf-protection=full` plus `-Zbuild-std`.
* **Caller-chosen nonces** are allowed (for the deterministic tests and the
  differential harness). A production API would not take a nonce from the
  caller, or would use a nonce-misuse-resistant mode.
* **PIN handling**: the PIN goes to `C_Login` and is not kept, but the
  caller's own copy is outside our control.
* **One key, two uses**: an AES key can both seal and wrap.
* **SoftHSM ≠ HSM**: the token here is software; its key material sits in
  files encrypted under the PIN-derived key.
* Use-after-free of a context is not detected (T11); a production ABI might
  hand out generation-checked handles instead of raw pointers.
