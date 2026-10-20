//! RustCrypto primitives, the counterpart of `ccb::prim` in the C++ core.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Mac, NONCE_LEN};

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Mac {
    // HMAC accepts keys of any length, so this cannot fail.
    let mut m = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key).expect("any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    Sha256::digest(msg).into()
}

/// AES-256-GCM, 96-bit nonce, 128-bit tag. Returns ciphertext || tag.
pub fn gcm_seal(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Option<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    c.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad }).ok()
}

pub fn gcm_open(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], ct_tag: &[u8]) -> Option<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ct_tag, aad }).ok()
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, okm).is_ok()
}

/// RFC 3394 AES key wrap with a 256-bit KEK.
pub fn aes_kw_wrap(kek: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let kek = aes_kw::KekAes256::try_from(kek).ok()?;
    if key.len() < 16 || key.len() % 8 != 0 {
        return None;
    }
    let mut out = vec![0u8; key.len() + 8];
    kek.wrap(key, &mut out).ok()?;
    Some(out)
}

pub fn aes_kw_unwrap(kek: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let kek = aes_kw::KekAes256::try_from(kek).ok()?;
    if blob.len() < 24 || blob.len() % 8 != 0 {
        return None;
    }
    let mut out = Zeroizing::new(vec![0u8; blob.len() - 8]);
    kek.unwrap(blob, &mut out).ok()?;
    Some(out)
}

pub fn random(out: &mut [u8]) -> bool {
    getrandom::getrandom(out).is_ok()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
