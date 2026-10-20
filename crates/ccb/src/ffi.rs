//! The C ABI. `include/ccb.h` is generated from this file by cbindgen
//! (`scripts/gen-header.sh`); CI fails if the committed header is stale.
//!
//! Rules every entry point follows (docs/CONTRACT.md §4):
//! * Returns a `CCB_*` status; never unwinds. The body runs inside
//!   `catch_unwind`, and a caught panic becomes `CCB_ERR_PANIC`.
//! * Only key IDs (`ccb_key_id`, 32 bytes) cross the boundary, never key bytes.
//! * `(ptr, len)` inputs: `ptr` may be NULL only when `len == 0`.
//! * Outputs with a caller-chosen size take `(out, out_cap, out_len)`. If
//!   `out_cap` is too small nothing is written to `out`, `*out_len` is set to
//!   the size needed, and `CCB_ERR_BUFFER_TOO_SMALL` is returned.
//! * Output buffers must not overlap input buffers.
//!
//! All `unsafe` in the crate lives here; `scripts/unsafe-audit.sh` counts it
//! and `tests/miri.rs` drives every block under Miri.
#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use crate::*;

pub const CCB_OK: i32 = 0;
pub const CCB_ERR_NULL_ARG: i32 = -1;
pub const CCB_ERR_BAD_ARG: i32 = -2;
pub const CCB_ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const CCB_ERR_NO_SUCH_KEY: i32 = -4;
pub const CCB_ERR_WRONG_KEY_TYPE: i32 = -5;
pub const CCB_ERR_VERIFY_FAILED: i32 = -6;
pub const CCB_ERR_NOT_EXTRACTABLE: i32 = -7;
pub const CCB_ERR_UNSUPPORTED: i32 = -8;
pub const CCB_ERR_BACKEND: i32 = -9;
pub const CCB_ERR_PANIC: i32 = -10;
pub const CCB_ERR_INTERNAL: i32 = -11;

pub const CCB_KEY_AES256: u32 = 1;
pub const CCB_KEY_HMAC_SHA256: u32 = 2;
pub const CCB_FLAG_EXPORTABLE: u32 = 1;
pub const CCB_KEY_ID_LEN: usize = 32;
pub const CCB_NONCE_LEN: usize = 12;
pub const CCB_MAC_LEN: usize = 32;
pub const CCB_WRAP_LEN: usize = 40;
pub const CCB_SEAL_OVERHEAD: usize = 28;
pub const CCB_ABI_VERSION: u32 = 1;

/// Opaque context. Created by `ccb_ctx_new_*`, released by `ccb_ctx_free`.
///
/// Thread safety: a context is Send + Sync. Every call takes an internal
/// mutex, so one context may be shared across threads; calls on it are
/// serialised. If a call panics, the context is poisoned and every later call
/// on it returns `CCB_ERR_PANIC`; free it and create a new one.
pub struct ccb_ctx {
    store: Mutex<Box<dyn KeyStore>>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ccb_ctx>();
};

/// A key's identity: SHA-256 over its type and key check value. Never secret.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ccb_key_id {
    pub bytes: [u8; 32],
}

// ---- boundary helpers ---------------------------------------------------------

fn guard(f: impl FnOnce() -> Result<()>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CCB_OK,
        Ok(Err(s)) => s as i32,
        Err(_) => CCB_ERR_PANIC,
    }
}

/// Borrows `(p, len)` as a slice; NULL is allowed only for `len == 0`.
unsafe fn input<'a>(p: *const u8, len: usize) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(Status::NullArg);
    }
    if len > isize::MAX as usize {
        return Err(Status::BadArg);
    }
    // SAFETY: p is non-null and len is in range; the caller guarantees p points
    // to len readable bytes that stay valid and unmodified for this call
    // (docs/CONTRACT.md §4).
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}

unsafe fn key_id<'a>(p: *const ccb_key_id) -> Result<&'a KeyId> {
    // SAFETY: the caller guarantees a non-null p points to a valid ccb_key_id
    // for this call; repr(C) with a single [u8; 32] field, alignment 1.
    unsafe { p.as_ref() }.map(|k| &k.bytes).ok_or(Status::NullArg)
}

unsafe fn put_id(out: *mut ccb_key_id, id: KeyId) {
    // SAFETY: callers check out for null first; the caller of the entry point
    // guarantees it is valid for a write of one ccb_key_id.
    unsafe { out.write(ccb_key_id { bytes: id }) }
}

/// Copies `data` to `(out, cap)`, reporting the length through `out_len`.
unsafe fn output(data: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> Result<()> {
    // SAFETY: callers check out_len for null; it is valid for one usize write.
    unsafe { out_len.write(data.len()) };
    if cap < data.len() {
        return Err(Status::BufferTooSmall);
    }
    if !data.is_empty() {
        // SAFETY: out is non-null (callers check it whenever cap > 0, and here
        // cap >= data.len() > 0); the caller guarantees cap writable bytes that
        // do not overlap any input, so a non-overlapping copy is sound.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    }
    Ok(())
}

fn with_store<T>(ctx: &ccb_ctx, f: impl FnOnce(&mut dyn KeyStore) -> Result<T>) -> Result<T> {
    let mut g = ctx.store.lock().map_err(|_| Status::Panic)?;
    f(g.as_mut())
}

unsafe fn context<'a>(ctx: *const ccb_ctx) -> Result<&'a ccb_ctx> {
    // SAFETY: the caller guarantees a non-null ctx came from ccb_ctx_new_* and
    // has not been freed; ccb_ctx is Sync, so a shared borrow is fine even if
    // other threads use the same context concurrently.
    unsafe { ctx.as_ref() }.ok_or(Status::NullArg)
}

fn out_ptr_ok<T>(p: *mut T) -> Result<()> {
    if p.is_null() {
        Err(Status::NullArg)
    } else {
        Ok(())
    }
}

fn new_ctx(store: Box<dyn KeyStore>, out: *mut *mut ccb_ctx) {
    let raw = Box::into_raw(Box::new(ccb_ctx { store: Mutex::new(store) }));
    // SAFETY: out was checked non-null by the caller and is valid for a write.
    unsafe { out.write(raw) };
}

// ---- entry points ---------------------------------------------------------------

/// ABI version of this library (`CCB_ABI_VERSION`). Also the cheapest call
/// across the boundary, used to measure the bare FFI crossing.
#[no_mangle]
pub extern "C" fn ccb_abi_version() -> u32 {
    CCB_ABI_VERSION
}

/// Static, NUL-terminated name for a status code. Never NULL.
#[no_mangle]
pub extern "C" fn ccb_status_str(status: i32) -> *const c_char {
    let s: &'static CStr = match status {
        CCB_OK => c"ok",
        CCB_ERR_NULL_ARG => c"null argument",
        CCB_ERR_BAD_ARG => c"bad argument",
        CCB_ERR_BUFFER_TOO_SMALL => c"buffer too small",
        CCB_ERR_NO_SUCH_KEY => c"no such key",
        CCB_ERR_WRONG_KEY_TYPE => c"wrong key type",
        CCB_ERR_VERIFY_FAILED => c"verification failed",
        CCB_ERR_NOT_EXTRACTABLE => c"key not extractable",
        CCB_ERR_UNSUPPORTED => c"unsupported",
        CCB_ERR_BACKEND => c"backend error",
        CCB_ERR_PANIC => c"panic caught at FFI boundary",
        CCB_ERR_INTERNAL => c"internal error",
        _ => c"unknown status",
    };
    s.as_ptr()
}

/// Creates a context over an in-memory software key store.
#[no_mangle]
pub unsafe extern "C" fn ccb_ctx_new_software(out: *mut *mut ccb_ctx) -> i32 {
    guard(|| {
        out_ptr_ok(out)?;
        new_ctx(software_store(), out);
        Ok(())
    })
}

/// Creates a context over a PKCS#11 token: `module` is the path of the
/// PKCS#11 library, `token_label` the token to log into as CKU_USER.
#[no_mangle]
pub unsafe extern "C" fn ccb_ctx_new_pkcs11(
    module: *const c_char,
    token_label: *const c_char,
    pin: *const u8,
    pin_len: usize,
    out: *mut *mut ccb_ctx,
) -> i32 {
    guard(|| {
        out_ptr_ok(out)?;
        if module.is_null() || token_label.is_null() {
            return Err(Status::NullArg);
        }
        // SAFETY: both checked non-null; the caller guarantees NUL-terminated
        // strings valid for this call.
        let (module, label) = unsafe { (CStr::from_ptr(module), CStr::from_ptr(token_label)) };
        let module = module.to_str().map_err(|_| Status::BadArg)?;
        let label = label.to_str().map_err(|_| Status::BadArg)?;
        // SAFETY: see input().
        let pin = unsafe { input(pin, pin_len) }?;
        #[cfg(not(miri))]
        {
            new_ctx(pkcs11_store(module, label, pin)?, out);
            Ok(())
        }
        #[cfg(miri)]
        {
            let _ = (module, label, pin);
            Err(Status::Unsupported)
        }
    })
}

/// Releases a context. NULL is a no-op. Freeing twice is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn ccb_ctx_free(ctx: *mut ccb_ctx) {
    if ctx.is_null() {
        return;
    }
    // Dropping a store can run arbitrary backend code; keep a panic there from
    // crossing the boundary too.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: ctx is non-null and, per the contract, came from
        // Box::into_raw in new_ctx and has not been freed before.
        drop(unsafe { Box::from_raw(ctx) });
    }));
}

#[no_mangle]
pub unsafe extern "C" fn ccb_key_generate(ctx: *const ccb_ctx, ty: u32, flags: u32, out_id: *mut ccb_key_id) -> i32 {
    guard(|| {
        // SAFETY: see context().
        let ctx = unsafe { context(ctx) }?;
        out_ptr_ok(out_id)?;
        let id = with_store(ctx, |s| s.generate(ty, flags))?;
        // SAFETY: out_id checked non-null above.
        unsafe { put_id(out_id, id) };
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn ccb_key_import(
    ctx: *const ccb_ctx,
    ty: u32,
    key: *const u8,
    key_len: usize,
    flags: u32,
    out_id: *mut ccb_key_id,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / input().
        let (ctx, key) = unsafe { (context(ctx)?, input(key, key_len)?) };
        out_ptr_ok(out_id)?;
        let id = with_store(ctx, |s| s.import_key(ty, key, flags))?;
        // SAFETY: out_id checked non-null above.
        unsafe { put_id(out_id, id) };
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn ccb_key_destroy(ctx: *const ccb_ctx, id: *const ccb_key_id) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id().
        let (ctx, id) = unsafe { (context(ctx)?, key_id(id)?) };
        with_store(ctx, |s| s.destroy(id))
    })
}

/// Wraps `target` under `kek` (RFC 3394). Fails with
/// `CCB_ERR_NOT_EXTRACTABLE` unless `target` was created exportable.
#[no_mangle]
pub unsafe extern "C" fn ccb_key_wrap(
    ctx: *const ccb_ctx,
    kek: *const ccb_key_id,
    target: *const ccb_key_id,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id().
        let (ctx, kek, target) = unsafe { (context(ctx)?, key_id(kek)?, key_id(target)?) };
        out_ptr_ok(out_len)?;
        if out_cap > 0 {
            out_ptr_ok(out)?;
        }
        if out_cap < CCB_WRAP_LEN {
            // SAFETY: out_len checked non-null above.
            unsafe { out_len.write(CCB_WRAP_LEN) };
            return Err(Status::BufferTooSmall);
        }
        let blob = with_store(ctx, |s| s.wrap(kek, target))?;
        // SAFETY: out / out_len checked above; see output().
        unsafe { output(&blob, out, out_cap, out_len) }
    })
}

#[no_mangle]
pub unsafe extern "C" fn ccb_key_unwrap(
    ctx: *const ccb_ctx,
    kek: *const ccb_key_id,
    ty: u32,
    blob: *const u8,
    blob_len: usize,
    flags: u32,
    out_id: *mut ccb_key_id,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id() / input().
        let (ctx, kek, blob) = unsafe { (context(ctx)?, key_id(kek)?, input(blob, blob_len)?) };
        out_ptr_ok(out_id)?;
        let id = with_store(ctx, |s| s.unwrap(kek, ty, blob, flags))?;
        // SAFETY: out_id checked non-null above.
        unsafe { put_id(out_id, id) };
        Ok(())
    })
}

/// HMAC-SHA256; writes exactly `CCB_MAC_LEN` bytes to `out_tag`.
#[no_mangle]
pub unsafe extern "C" fn ccb_hmac_sign(
    ctx: *const ccb_ctx,
    id: *const ccb_key_id,
    msg: *const u8,
    msg_len: usize,
    out_tag: *mut u8,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id() / input().
        let (ctx, id, msg) = unsafe { (context(ctx)?, key_id(id)?, input(msg, msg_len)?) };
        out_ptr_ok(out_tag)?;
        let tag = with_store(ctx, |s| s.hmac_sign(id, msg))?;
        // SAFETY: out_tag non-null; the caller guarantees CCB_MAC_LEN writable
        // bytes not overlapping msg.
        unsafe { std::ptr::copy_nonoverlapping(tag.as_ptr(), out_tag, MAC_LEN) };
        Ok(())
    })
}

/// Constant-time HMAC check. `tag_len` must be `CCB_MAC_LEN`.
#[no_mangle]
pub unsafe extern "C" fn ccb_hmac_verify(
    ctx: *const ccb_ctx,
    id: *const ccb_key_id,
    msg: *const u8,
    msg_len: usize,
    tag: *const u8,
    tag_len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id() / input().
        let (ctx, id, msg, tag) = unsafe { (context(ctx)?, key_id(id)?, input(msg, msg_len)?, input(tag, tag_len)?) };
        with_store(ctx, |s| s.hmac_verify(id, msg, tag))
    })
}

/// AES-256-GCM. `nonce` is NULL (random nonce, the normal case) or
/// `CCB_NONCE_LEN` bytes; the all-0xFF nonce is reserved and rejected.
/// Output: nonce || ciphertext || tag, `pt_len + CCB_SEAL_OVERHEAD` bytes.
#[no_mangle]
pub unsafe extern "C" fn ccb_aead_seal(
    ctx: *const ccb_ctx,
    id: *const ccb_key_id,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id() / input().
        let (ctx, id, aad, pt) = unsafe { (context(ctx)?, key_id(id)?, input(aad, aad_len)?, input(pt, pt_len)?) };
        let nonce: Option<&[u8; NONCE_LEN]> = if nonce.is_null() {
            None
        } else {
            // SAFETY: non-null; the caller guarantees CCB_NONCE_LEN readable
            // bytes. [u8; 12] has alignment 1.
            Some(unsafe { &*(nonce as *const [u8; NONCE_LEN]) })
        };
        out_ptr_ok(out_len)?;
        let need = pt.len().checked_add(SEAL_OVERHEAD).ok_or(Status::BadArg)?;
        if out_cap < need {
            // SAFETY: out_len checked non-null above.
            unsafe { out_len.write(need) };
            return Err(Status::BufferTooSmall);
        }
        out_ptr_ok(out)?;
        let sealed = with_store(ctx, |s| s.seal(id, nonce, aad, pt))?;
        // SAFETY: out / out_len checked above; see output().
        unsafe { output(&sealed, out, out_cap, out_len) }
    })
}

/// Opens `nonce || ciphertext || tag`. Every authentication failure,
/// including truncated input, is `CCB_ERR_VERIFY_FAILED`.
#[no_mangle]
pub unsafe extern "C" fn ccb_aead_open(
    ctx: *const ccb_ctx,
    id: *const ccb_key_id,
    aad: *const u8,
    aad_len: usize,
    sealed: *const u8,
    sealed_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id() / input().
        let (ctx, id, aad, sealed) =
            unsafe { (context(ctx)?, key_id(id)?, input(aad, aad_len)?, input(sealed, sealed_len)?) };
        out_ptr_ok(out_len)?;
        let need = sealed.len().saturating_sub(SEAL_OVERHEAD);
        if out_cap < need {
            // SAFETY: out_len checked non-null above.
            unsafe { out_len.write(need) };
            return Err(Status::BufferTooSmall);
        }
        if out_cap > 0 {
            out_ptr_ok(out)?;
        }
        let pt = zeroize::Zeroizing::new(with_store(ctx, |s| s.open(id, aad, sealed))?);
        // SAFETY: out / out_len checked above; see output().
        unsafe { output(&pt, out, out_cap, out_len) }
    })
}

/// HKDF-SHA256 with the HMAC key `base` as IKM; the 32-byte output becomes a
/// new key of type `out_ty` inside the store. Software backend only.
#[no_mangle]
pub unsafe extern "C" fn ccb_hkdf_derive(
    ctx: *const ccb_ctx,
    base: *const ccb_key_id,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out_ty: u32,
    out_flags: u32,
    out_id: *mut ccb_key_id,
) -> i32 {
    guard(|| {
        // SAFETY: see context() / key_id() / input().
        let (ctx, base, salt, info) =
            unsafe { (context(ctx)?, key_id(base)?, input(salt, salt_len)?, input(info, info_len)?) };
        out_ptr_ok(out_id)?;
        let id = with_store(ctx, |s| s.hkdf_derive(base, salt, info, out_ty, out_flags))?;
        // SAFETY: out_id checked non-null above.
        unsafe { put_id(out_id, id) };
        Ok(())
    })
}

/// Test hook: panics inside the boundary. Must return `CCB_ERR_PANIC`.
#[cfg(feature = "test-hooks")]
#[no_mangle]
pub extern "C" fn ccb_test_panic() -> i32 {
    guard(|| panic!("ccb_test_panic"))
}
