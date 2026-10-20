//! Software backend; the counterpart of `cpp/src/software_store.cpp`.
use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::*;

struct Entry {
    ty: KeyType,
    flags: u32,
    // Boxed so a HashMap resize moves only the pointer. With the key inline,
    // every rehash would free a table holding unwiped copies of it
    // (tests/zeroize.rs has the control case that shows this).
    key: SecretKey,
}

type SecretKey = Box<Zeroizing<[u8; KEY_LEN]>>;

fn new_key() -> SecretKey {
    Box::new(Zeroizing::new([0u8; KEY_LEN]))
}

#[derive(Default)]
pub(crate) struct SoftwareStore {
    keys: HashMap<KeyId, Entry>,
}

impl SoftwareStore {
    fn find(&self, id: &KeyId, want: KeyType) -> Result<&Entry> {
        let e = self.keys.get(id).ok_or(Status::NoSuchKey)?;
        if e.ty != want {
            return Err(Status::WrongKeyType);
        }
        Ok(e)
    }

    /// Importing a key that is already present is idempotent: same ID, and the
    /// stored flags are left unchanged.
    fn insert(&mut self, ty: KeyType, key: SecretKey, flags: u32) -> Result<KeyId> {
        let kcv = kcv_software(ty, &key[..])?;
        let id = key_id_from_kcv(ty, &kcv);
        self.keys.entry(id).or_insert(Entry { ty, flags, key });
        Ok(id)
    }
}

fn boxed_key(material: &[u8]) -> SecretKey {
    let mut k = new_key();
    k.copy_from_slice(material);
    k
}

impl KeyStore for SoftwareStore {
    fn generate(&mut self, ty: u32, flags: u32) -> Result<KeyId> {
        let t = check_type_flags(ty, flags)?;
        let mut k = new_key();
        if !prim::random(&mut k[..]) {
            return Err(Status::Internal);
        }
        self.insert(t, k, flags)
    }

    fn import_key(&mut self, ty: u32, material: &[u8], flags: u32) -> Result<KeyId> {
        let t = check_type_flags(ty, flags)?;
        if material.len() != KEY_LEN {
            return Err(Status::BadArg);
        }
        self.insert(t, boxed_key(material), flags)
    }

    fn destroy(&mut self, id: &KeyId) -> Result<()> {
        self.keys.remove(id).map(|_| ()).ok_or(Status::NoSuchKey)
    }

    fn wrap(&mut self, kek: &KeyId, target: &KeyId) -> Result<Vec<u8>> {
        let w = self.find(kek, KeyType::Aes256)?;
        let t = self.keys.get(target).ok_or(Status::NoSuchKey)?;
        if t.flags & FLAG_EXPORTABLE == 0 {
            return Err(Status::NotExtractable);
        }
        prim::aes_kw_wrap(&w.key[..], &t.key[..]).ok_or(Status::Internal)
    }

    fn unwrap(&mut self, kek: &KeyId, ty: u32, blob: &[u8], flags: u32) -> Result<KeyId> {
        let t = check_type_flags(ty, flags)?;
        if blob.len() != WRAP_LEN {
            return Err(Status::BadArg);
        }
        let w = self.find(kek, KeyType::Aes256)?;
        let k = prim::aes_kw_unwrap(&w.key[..], blob).ok_or(Status::VerifyFailed)?;
        self.insert(t, boxed_key(&k), flags)
    }

    fn hmac_sign(&mut self, id: &KeyId, msg: &[u8]) -> Result<Mac> {
        let e = self.find(id, KeyType::HmacSha256)?;
        Ok(prim::hmac_sha256(&e.key[..], msg))
    }

    fn hmac_verify(&mut self, id: &KeyId, msg: &[u8], tag: &[u8]) -> Result<()> {
        if tag.len() != MAC_LEN {
            return Err(Status::BadArg);
        }
        let m = self.hmac_sign(id, msg)?;
        if prim::ct_eq(&m, tag) {
            Ok(())
        } else {
            Err(Status::VerifyFailed)
        }
    }

    fn seal(&mut self, id: &KeyId, nonce: Option<&[u8; NONCE_LEN]>, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        if nonce.is_some_and(|n| is_reserved_nonce(n)) {
            return Err(Status::BadArg);
        }
        let e = self.find(id, KeyType::Aes256)?;
        let n = match nonce {
            Some(n) => *n,
            None => fresh_nonce()?,
        };
        let ct = prim::gcm_seal(&e.key[..], &n, aad, pt).ok_or(Status::Internal)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&n);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&mut self, id: &KeyId, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        let e = self.find(id, KeyType::Aes256)?;
        if sealed.len() < SEAL_OVERHEAD || is_reserved_nonce(&sealed[..NONCE_LEN]) {
            return Err(Status::VerifyFailed);
        }
        let (n, body) = sealed.split_at(NONCE_LEN);
        let n: &[u8; NONCE_LEN] = n.try_into().map_err(|_| Status::Internal)?;
        prim::gcm_open(&e.key[..], n, aad, body).ok_or(Status::VerifyFailed)
    }

    fn hkdf_derive(&mut self, base: &KeyId, salt: &[u8], info: &[u8], out_ty: u32, out_flags: u32) -> Result<KeyId> {
        let t = check_type_flags(out_ty, out_flags)?;
        let b = self.find(base, KeyType::HmacSha256)?;
        let mut okm = new_key();
        if !prim::hkdf_sha256(&b.key[..], salt, info, &mut okm[..]) {
            return Err(Status::Internal);
        }
        self.insert(t, okm, out_flags)
    }
}

/// Random nonce that is never the reserved KCV nonce (p = 2^-96, but the
/// invariant should not depend on luck).
pub(crate) fn fresh_nonce() -> Result<[u8; NONCE_LEN]> {
    loop {
        let mut n = [0u8; NONCE_LEN];
        if !prim::random(&mut n) {
            return Err(Status::Internal);
        }
        if !is_reserved_nonce(&n) {
            return Ok(n);
        }
    }
}
