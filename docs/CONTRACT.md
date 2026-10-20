# The contract both implementations follow

The C++ core (`cpp/`) and the Rust implementation (`crates/ccb`) are two
implementations of this document. Anything not pinned down here is a place
where they could legitimately differ, and the differential tests could not
tell a port bug from a design choice, so the list is deliberately long.

## 1. Key model

| | |
|---|---|
| Key types | `1` = AES-256 (GCM seal/open, AES-KW wrap/unwrap), `2` = HMAC-SHA256 (sign/verify, HKDF base) |
| Key length | 32 bytes for both types |
| Flags | bit 0 = `EXPORTABLE`: the key may leave the store, **only** as an AES-KW blob. Any other bit is `BAD_ARG`. |
| Handle | a 32-byte **key ID**. Raw key bytes never cross the API (except going *in*, via import). |
| Duplicates | importing / unwrapping / deriving a key that is already present returns `OK` with the existing ID; the stored flags are not changed |

PKCS#11 objects: `CKO_SECRET_KEY`, `CKK_AES` or `CKK_GENERIC_SECRET`,
`CKA_TOKEN = CKA_PRIVATE = CKA_SENSITIVE = true`, `CKA_EXTRACTABLE = EXPORTABLE`,
`CKA_LABEL = "ccb"`, `CKA_ID = key ID`. AES keys: `ENCRYPT/DECRYPT/WRAP/UNWRAP`;
HMAC keys: `SIGN/VERIFY`.

## 2. Key ID derivation

```
kcv(AES-256, K)     = GCM-tag_K(nonce = 0xFF * 12, aad = "ccb-kcv-v1", pt = "")   16 bytes
kcv(HMAC-SHA256, K) = HMAC-SHA256_K("ccb-kcv-v1")                                  32 bytes
id                  = SHA-256("ccb-key-id-v1" || type_byte || kcv)
```

Both KCVs can be computed **inside a PKCS#11 token** with `CKM_AES_GCM` /
`CKM_SHA256_HMAC`, so a key generated in the token gets the same ID it would
get anywhere else, without ever leaving it. The software stores compute the
same value from the raw bytes.

Why not the textbook KCV, `E_K(0^128)`? For a GCM key that value **is** the
GHASH subkey `H`, and anyone holding `H` can forge GCM tags. The nonce
`0xFF * 12` is reserved for the KCV: `seal` rejects it as an explicit nonce,
random nonces are redrawn if they hit it, and `open` refuses any input that
carries it (so the KCV itself is not a valid ciphertext).

## 3. Operations: validation order and results

Checks run in exactly this order; the first failure is the result.

| op | order of checks | output |
|---|---|---|
| `generate(type, flags)` | type/flags → `BAD_ARG` | new ID |
| `import(type, key, flags)` | type/flags/len≠32 → `BAD_ARG` | ID |
| `destroy(id)` | missing → `NO_SUCH_KEY` | – |
| `wrap(kek, target)` | kek missing → `NO_SUCH_KEY`; kek not AES → `WRONG_KEY_TYPE`; target missing → `NO_SUCH_KEY`; target not exportable → `NOT_EXTRACTABLE` | 40-byte RFC 3394 blob |
| `unwrap(kek, type, blob, flags)` | type/flags/len≠40 → `BAD_ARG`; kek missing / not AES; integrity failure → `VERIFY_FAILED` | ID |
| `hmac_sign(id, msg)` | missing → `NO_SUCH_KEY`; not HMAC → `WRONG_KEY_TYPE` | 32-byte tag |
| `hmac_verify(id, msg, tag)` | tag len≠32 → `BAD_ARG`; then as sign; mismatch → `VERIFY_FAILED` (constant-time compare) | – |
| `seal(id, nonce?, aad, pt)` | explicit reserved nonce → `BAD_ARG`; missing / not AES | `nonce ‖ ct ‖ tag` (pt+28 bytes) |
| `open(id, aad, sealed)` | missing / not AES; len<28, reserved nonce, or bad tag → `VERIFY_FAILED` | plaintext |
| `hkdf_derive(base, salt, info, type, flags)` | type/flags → `BAD_ARG`; [PKCS#11: `UNSUPPORTED`]; base missing / not HMAC | ID of `HKDF-SHA256(ikm = base, salt, info, L = 32)` stored as `type` |

Every authentication failure is the same code (`VERIFY_FAILED`): a short
input, a wrong tag, a wrong key and the reserved nonce are indistinguishable.

**PKCS#11 specifics.** SoftHSM 2.6.1 reports a GCM tag mismatch and an AES-KW
integrity failure as `CKR_GENERAL_ERROR`, not `CKR_ENCRYPTED_DATA_INVALID` /
`CKR_WRAPPED_KEY_INVALID`; both backends map `CKR_GENERAL_ERROR` to
`VERIFY_FAILED` on `C_Decrypt` and `C_UnwrapKey` only. HKDF is `UNSUPPORTED`
(SoftHSM has no `CKM_HKDF_DERIVE`, and deriving on the host would take the
base key out of the token).

## 4. The C ABI (`include/ccb.h`)

* Every function returns a `CCB_*` status. Nothing unwinds across the
  boundary: each body runs in `catch_unwind`, and a panic becomes
  `CCB_ERR_PANIC`. A context that panicked is poisoned; every later call on
  it returns `CCB_ERR_PANIC`.
* `(ptr, len)` inputs: `ptr` may be NULL only if `len == 0`, otherwise
  `CCB_ERR_NULL_ARG`. `len > isize::MAX` is `CCB_ERR_BAD_ARG`.
* Required out-pointers (`out_id`, `out_len`, `out_tag`) that are NULL →
  `CCB_ERR_NULL_ARG`.
* Variable-size outputs take `(out, out_cap, out_len)`. The capacity check
  runs **before** the operation: if `out_cap` is too small, nothing is
  written to `out`, `*out_len` is the size needed, and the result is
  `CCB_ERR_BUFFER_TOO_SMALL`.
* Output buffers must not overlap inputs.

### Ownership

| object | created by | released by | notes |
|---|---|---|---|
| `ccb_ctx*` | `ccb_ctx_new_software` / `ccb_ctx_new_pkcs11` | `ccb_ctx_free` | NULL is a no-op; double free is UB |
| `ccb_key_id` | caller-owned 32-byte value | – | plain data, copy freely |
| input buffers | caller | caller | borrowed for the duration of the call only |
| output buffers | caller | caller | the library never allocates for the caller |
| strings from `ccb_status_str` | static | never | |

### Threads (Send / Sync)

A `ccb_ctx` is `Send + Sync`: it may be created on one thread, used from
many, and freed on another. Each call takes the context's mutex, so calls on
one context are serialised (a PKCS#11 session must not be used concurrently
anyway). Use one context per thread for parallelism. In the Rust → C++
direction, `CppStore` is `Send` but not `Sync` (its C++ store has its own
mutex, but the Rust wrapper needs `&mut` per call).

The two status enums are asserted equal at compile time
(`cpp/tests/xlang.cpp`), so the C++ and Rust sides cannot drift apart on
codes.
