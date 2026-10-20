//! Rust implementation of the crypto-core-bridge key store.
//!
//! Mirrors `cpp/include/ccb/core.hpp` method for method; the behaviour both
//! must share (validation order, error codes, output formats, key-ID
//! derivation) is written down in `docs/CONTRACT.md`, and
//! `crates/ccb-cpp/tests/differential.rs` checks the two against each other.
//!
//! C and C++ callers use the C ABI in [`ffi`] (header: `include/ccb.h`).
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod ffi;
#[cfg(not(miri))]
mod p11;
pub mod prim;
mod soft;

use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAC_LEN: usize = 32;
pub const WRAP_LEN: usize = KEY_LEN + 8;
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
pub const FLAG_EXPORTABLE: u32 = 1;

/// Status codes shared with the C++ core (`ccb::Status`) and the C ABI.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    NullArg = -1,
    BadArg = -2,
    BufferTooSmall = -3,
    NoSuchKey = -4,
    WrongKeyType = -5,
    VerifyFailed = -6,
    NotExtractable = -7,
    Unsupported = -8,
    Backend = -9,
    Panic = -10,
    Internal = -11,
}

pub type Result<T> = core::result::Result<T, Status>;
pub type KeyId = [u8; 32];
pub type Mac = [u8; MAC_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Aes256 = 1,
    HmacSha256 = 2,
}

impl KeyType {
    pub fn from_u32(t: u32) -> Option<Self> {
        match t {
            1 => Some(Self::Aes256),
            2 => Some(Self::HmacSha256),
            _ => None,
        }
    }
}

pub(crate) fn valid_flags(f: u32) -> bool {
    f & !FLAG_EXPORTABLE == 0
}

/// Validates `(type, flags)` the way every creating operation does.
pub(crate) fn check_type_flags(ty: u32, flags: u32) -> Result<KeyType> {
    match KeyType::from_u32(ty) {
        Some(t) if valid_flags(flags) => Ok(t),
        _ => Err(Status::BadArg),
    }
}

/// One key store. `&mut self` everywhere: callers serialise access (the C ABI
/// wraps each store in a `Mutex`), which is also what a PKCS#11 session needs.
pub trait KeyStore: Send {
    fn generate(&mut self, ty: u32, flags: u32) -> Result<KeyId>;
    fn import_key(&mut self, ty: u32, material: &[u8], flags: u32) -> Result<KeyId>;
    fn destroy(&mut self, id: &KeyId) -> Result<()>;
    fn wrap(&mut self, kek: &KeyId, target: &KeyId) -> Result<Vec<u8>>;
    fn unwrap(&mut self, kek: &KeyId, ty: u32, blob: &[u8], flags: u32) -> Result<KeyId>;
    fn hmac_sign(&mut self, id: &KeyId, msg: &[u8]) -> Result<Mac>;
    fn hmac_verify(&mut self, id: &KeyId, msg: &[u8], tag: &[u8]) -> Result<()>;
    /// `nonce == None` draws a random nonce. Output: nonce || ciphertext || tag.
    fn seal(&mut self, id: &KeyId, nonce: Option<&[u8; NONCE_LEN]>, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>;
    fn open(&mut self, id: &KeyId, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>>;
    fn hkdf_derive(&mut self, base: &KeyId, salt: &[u8], info: &[u8], out_ty: u32, out_flags: u32) -> Result<KeyId>;
}

pub fn software_store() -> Box<dyn KeyStore> {
    Box::new(soft::SoftwareStore::default())
}

#[cfg(not(miri))]
pub fn pkcs11_store(module: &str, token_label: &str, pin: &[u8]) -> Result<Box<dyn KeyStore>> {
    Ok(Box::new(p11::Pkcs11Store::open(module, token_label, pin)?))
}

// ---- key IDs (CONTRACT.md §2) -------------------------------------------------

pub const KCV_NONCE: [u8; NONCE_LEN] = [0xff; NONCE_LEN];
pub const KCV_LABEL: &[u8] = b"ccb-kcv-v1";

pub fn is_reserved_nonce(n: &[u8]) -> bool {
    n == KCV_NONCE
}

/// Key check value computed from the raw key. The PKCS#11 backends compute
/// the same value inside the token.
pub fn kcv_software(t: KeyType, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match t {
        KeyType::HmacSha256 => Ok(Zeroizing::new(prim::hmac_sha256(key, KCV_LABEL).to_vec())),
        // GCM tag under a reserved nonce, not the classic E_K(0^128): for GCM
        // that value is the hash subkey H, and publishing it enables forgeries.
        KeyType::Aes256 => prim::gcm_seal(key, &KCV_NONCE, KCV_LABEL, &[]).map(Zeroizing::new).ok_or(Status::Internal),
    }
}

pub fn key_id_from_kcv(t: KeyType, kcv: &[u8]) -> KeyId {
    let mut buf = Vec::with_capacity(14 + 1 + kcv.len());
    buf.extend_from_slice(b"ccb-key-id-v1");
    buf.push(t as u8);
    buf.extend_from_slice(kcv);
    prim::sha256(&buf)
}
