//! Rust -> C++ direction: the C++ core behind a `cxx` bridge, wrapped so it
//! implements the same [`ccb::KeyStore`] trait as the Rust implementation.
//! This is the second migration stage (a Rust caller still using the C++
//! module); the differential tests and the fuzzer drive both through the trait.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod diff;

use ccb::{KeyId, KeyStore, Mac, Result, Status, NONCE_LEN};
use cxx::UniquePtr;

#[cxx::bridge(namespace = "ccb_rs")]
pub mod sys {
    unsafe extern "C++" {
        include!("ccb-cpp/src/bridge.hpp");

        type CppStore;

        fn new_software_store() -> UniquePtr<CppStore>;
        fn new_pkcs11_store(module: &str, label: &str, pin: &[u8], status: &mut i32) -> UniquePtr<CppStore>;

        fn generate(self: Pin<&mut CppStore>, ty: u32, flags: u32, out_id: &mut [u8]) -> i32;
        fn import_key(self: Pin<&mut CppStore>, ty: u32, material: &[u8], flags: u32, out_id: &mut [u8]) -> i32;
        fn destroy(self: Pin<&mut CppStore>, id: &[u8]) -> i32;
        fn wrap(self: Pin<&mut CppStore>, kek: &[u8], target: &[u8], out: &mut [u8], out_len: &mut usize) -> i32;
        fn unwrap(self: Pin<&mut CppStore>, kek: &[u8], ty: u32, blob: &[u8], flags: u32, out_id: &mut [u8]) -> i32;
        fn hmac_sign(self: Pin<&mut CppStore>, id: &[u8], msg: &[u8], out_tag: &mut [u8]) -> i32;
        fn hmac_verify(self: Pin<&mut CppStore>, id: &[u8], msg: &[u8], tag: &[u8]) -> i32;
        #[allow(clippy::too_many_arguments)]
        fn seal(
            self: Pin<&mut CppStore>,
            id: &[u8],
            nonce: &[u8],
            aad: &[u8],
            pt: &[u8],
            out: &mut [u8],
            out_len: &mut usize,
        ) -> i32;
        fn open(
            self: Pin<&mut CppStore>,
            id: &[u8],
            aad: &[u8],
            sealed: &[u8],
            out: &mut [u8],
            out_len: &mut usize,
        ) -> i32;
        #[allow(clippy::too_many_arguments)]
        fn hkdf_derive(
            self: Pin<&mut CppStore>,
            base: &[u8],
            salt: &[u8],
            info: &[u8],
            out_ty: u32,
            out_flags: u32,
            out_id: &mut [u8],
        ) -> i32;

        fn prim_hmac_sha256(key: &[u8], msg: &[u8], out: &mut [u8]) -> bool;
        fn prim_gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8], out: &mut Vec<u8>) -> bool;
        fn prim_gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8], out: &mut Vec<u8>) -> bool;
        fn prim_hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> bool;
        fn prim_aes_kw_wrap(kek: &[u8], key: &[u8], out: &mut Vec<u8>) -> bool;
        fn prim_aes_kw_unwrap(kek: &[u8], blob: &[u8], out: &mut Vec<u8>) -> bool;
    }
}

// SAFETY: CppStore owns a std::unique_ptr<ccb::KeyStore>. Both C++ stores
// guard all state with a std::mutex and hold no thread-affine resources (the
// PKCS#11 session is opened with CKF_OS_LOCKING_OK semantics and used under
// that mutex), so moving one to another thread is sound. Not Sync: the Rust
// wrapper below needs &mut for every call anyway.
unsafe impl Send for sys::CppStore {}

/// Maps a C++ status back to the shared enum. Unknown codes are a contract
/// violation, reported as Internal.
pub fn status(code: i32) -> Result<()> {
    let s = match code {
        0 => return Ok(()),
        -1 => Status::NullArg,
        -2 => Status::BadArg,
        -3 => Status::BufferTooSmall,
        -4 => Status::NoSuchKey,
        -5 => Status::WrongKeyType,
        -6 => Status::VerifyFailed,
        -7 => Status::NotExtractable,
        -8 => Status::Unsupported,
        -9 => Status::Backend,
        -10 => Status::Panic,
        _ => Status::Internal,
    };
    Err(s)
}

/// The C++ core as a Rust `KeyStore`.
pub struct CppKeyStore(UniquePtr<sys::CppStore>);

impl CppKeyStore {
    pub fn software() -> Self {
        CppKeyStore(sys::new_software_store())
    }

    pub fn pkcs11(module: &str, label: &str, pin: &[u8]) -> Result<Self> {
        let mut st = 0;
        let p = sys::new_pkcs11_store(module, label, pin, &mut st);
        status(st)?;
        if p.is_null() {
            return Err(Status::Internal);
        }
        Ok(CppKeyStore(p))
    }

    fn s(&mut self) -> std::pin::Pin<&mut sys::CppStore> {
        self.0.pin_mut()
    }
}

impl KeyStore for CppKeyStore {
    fn generate(&mut self, ty: u32, flags: u32) -> Result<KeyId> {
        let mut id = [0u8; 32];
        status(self.s().generate(ty, flags, &mut id))?;
        Ok(id)
    }
    fn import_key(&mut self, ty: u32, material: &[u8], flags: u32) -> Result<KeyId> {
        let mut id = [0u8; 32];
        status(self.s().import_key(ty, material, flags, &mut id))?;
        Ok(id)
    }
    fn destroy(&mut self, id: &KeyId) -> Result<()> {
        status(self.s().destroy(id))
    }
    fn wrap(&mut self, kek: &KeyId, target: &KeyId) -> Result<Vec<u8>> {
        let mut out = vec![0u8; ccb::WRAP_LEN];
        let mut n = 0;
        status(self.s().wrap(kek, target, &mut out, &mut n))?;
        out.truncate(n);
        Ok(out)
    }
    fn unwrap(&mut self, kek: &KeyId, ty: u32, blob: &[u8], flags: u32) -> Result<KeyId> {
        let mut id = [0u8; 32];
        status(self.s().unwrap(kek, ty, blob, flags, &mut id))?;
        Ok(id)
    }
    fn hmac_sign(&mut self, id: &KeyId, msg: &[u8]) -> Result<Mac> {
        let mut tag = [0u8; 32];
        status(self.s().hmac_sign(id, msg, &mut tag))?;
        Ok(tag)
    }
    fn hmac_verify(&mut self, id: &KeyId, msg: &[u8], tag: &[u8]) -> Result<()> {
        status(self.s().hmac_verify(id, msg, tag))
    }
    fn seal(&mut self, id: &KeyId, nonce: Option<&[u8; NONCE_LEN]>, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; pt.len() + ccb::SEAL_OVERHEAD];
        let mut len = 0;
        let n: &[u8] = nonce.map_or(&[], |n| &n[..]);
        status(self.s().seal(id, n, aad, pt, &mut out, &mut len))?;
        out.truncate(len);
        Ok(out)
    }
    fn open(&mut self, id: &KeyId, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; sealed.len().saturating_sub(ccb::SEAL_OVERHEAD)];
        let mut len = 0;
        status(self.s().open(id, aad, sealed, &mut out, &mut len))?;
        out.truncate(len);
        Ok(out)
    }
    fn hkdf_derive(&mut self, base: &KeyId, salt: &[u8], info: &[u8], out_ty: u32, out_flags: u32) -> Result<KeyId> {
        let mut id = [0u8; 32];
        status(self.s().hkdf_derive(base, salt, info, out_ty, out_flags, &mut id))?;
        Ok(id)
    }
}
