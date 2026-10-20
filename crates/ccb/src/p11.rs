//! PKCS#11 backend over `cryptoki`; the counterpart of
//! `cpp/src/pkcs11_store.cpp`. Same object templates, same CKA_ID scheme, so
//! the two backends can share one token.
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType as CkKeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::RawAuthPin;

use std::collections::HashMap;

use crate::soft::fresh_nonce;
use crate::*;

pub(crate) struct Pkcs11Store {
    session: Option<Session>,
    /// KeyId -> handle; see `resolve`.
    cache: HashMap<KeyId, ObjectHandle>,
    ctx: Option<Pkcs11>,
    we_initialized: bool,
}

fn map(e: Error) -> Status {
    match e {
        Error::Pkcs11(rv, _) => match rv {
            RvError::SignatureInvalid
            | RvError::SignatureLenRange
            | RvError::EncryptedDataInvalid
            | RvError::EncryptedDataLenRange
            | RvError::WrappedKeyInvalid
            | RvError::WrappedKeyLenRange => Status::VerifyFailed,
            RvError::KeyUnextractable => Status::NotExtractable,
            RvError::MechanismInvalid => Status::Unsupported,
            _ => Status::Backend,
        },
        _ => Status::Backend,
    }
}

/// For C_Decrypt / C_UnwrapKey only: SoftHSM 2.6.1 reports a GCM tag mismatch
/// and an AES-KW integrity failure as CKR_GENERAL_ERROR. Same rule as the C++
/// backend's map_auth_rv.
fn map_auth(e: Error) -> Status {
    match e {
        Error::Pkcs11(RvError::GeneralError, _) => Status::VerifyFailed,
        e => map(e),
    }
}

fn template(t: KeyType, flags: u32) -> Vec<Attribute> {
    let mut a = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(ck_type(t)),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(flags & FLAG_EXPORTABLE != 0),
        Attribute::Label(b"ccb".to_vec()),
    ];
    match t {
        KeyType::Aes256 => a.extend([
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
        ]),
        KeyType::HmacSha256 => a.extend([Attribute::Sign(true), Attribute::Verify(true)]),
    }
    a
}

fn ck_type(t: KeyType) -> CkKeyType {
    match t {
        KeyType::Aes256 => CkKeyType::AES,
        KeyType::HmacSha256 => CkKeyType::GENERIC_SECRET,
    }
}

impl Pkcs11Store {
    pub(crate) fn open(module: &str, token_label: &str, pin: &[u8]) -> Result<Self> {
        let ctx = Pkcs11::new(module).map_err(|_| Status::Backend)?;
        let we_initialized = match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => true,
            // The C++ backend in the same process got there first.
            Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => false,
            Err(e) => return Err(map(e)),
        };
        let mut store = Pkcs11Store { session: None, cache: HashMap::new(), ctx: Some(ctx), we_initialized };
        let ctx = store.ctx.as_ref().ok_or(Status::Internal)?;
        for slot in ctx.get_slots_with_token().map_err(map)? {
            let info = ctx.get_token_info(slot).map_err(map)?;
            if info.label().trim_end() != token_label {
                continue;
            }
            let session = ctx.open_rw_session(slot).map_err(map)?;
            let pin = RawAuthPin::new(Box::new(pin.to_vec()));
            match session.login_with_raw(UserType::User, &pin) {
                Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(map(e)),
            }
            store.session = Some(session);
            return Ok(store);
        }
        Err(Status::Backend)
    }

    fn s(&self) -> Result<&Session> {
        self.session.as_ref().ok_or(Status::Internal)
    }

    fn lookup(&self, id: &KeyId) -> Result<ObjectHandle> {
        let q = [Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Id(id.to_vec())];
        self.s()?.find_objects(&q).map_err(map)?.first().copied().ok_or(Status::NoSuchKey)
    }

    /// KeyId -> (handle, key type). C_FindObjects dominates the cost of an
    /// operation on SoftHSM, so it runs only on a cache miss. A hit is
    /// re-validated (CKA_ID + key type in one call) because PKCS#11 does not
    /// promise handles are never reused. Same rule as the C++ backend.
    fn resolve(&mut self, id: &KeyId) -> Result<(ObjectHandle, CkKeyType)> {
        if let Some(&h) = self.cache.get(id) {
            if let Ok(attrs) = self.s()?.get_attributes(h, &[AttributeType::Id, AttributeType::KeyType]) {
                if let [Attribute::Id(got), Attribute::KeyType(kt)] = &attrs[..] {
                    if got[..] == id[..] {
                        return Ok((h, *kt));
                    }
                }
            }
            self.cache.remove(id);
        }
        let h = self.lookup(id)?;
        let attrs = self.s()?.get_attributes(h, &[AttributeType::KeyType]).map_err(map)?;
        match attrs.first() {
            Some(Attribute::KeyType(kt)) => {
                self.cache.insert(*id, h);
                Ok((h, *kt))
            }
            _ => Err(Status::Backend),
        }
    }

    fn find(&mut self, id: &KeyId, want: KeyType) -> Result<ObjectHandle> {
        let (h, kt) = self.resolve(id)?;
        if kt == ck_type(want) {
            Ok(h)
        } else {
            Err(Status::WrongKeyType)
        }
    }

    fn gcm_raw(&self, h: ObjectHandle, nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let mut iv = *nonce;
        let p = GcmParams::new(&mut iv, aad, (TAG_LEN as u64 * 8).into()).map_err(|_| Status::Internal)?;
        self.s()?.encrypt(&Mechanism::AesGcm(p), h, pt).map_err(map)
    }

    fn sign_raw(&self, h: ObjectHandle, msg: &[u8]) -> Result<Mac> {
        let v = self.s()?.sign(&Mechanism::Sha256Hmac, h, msg).map_err(map)?;
        v.try_into().map_err(|_| Status::Backend)
    }

    /// KCV computed inside the token, then CKA_ID stamped on the object; a
    /// duplicate of an existing key is dropped in favour of the original.
    fn assign_id(&self, t: KeyType, h: ObjectHandle) -> Result<KeyId> {
        let kcv = match t {
            KeyType::HmacSha256 => self.sign_raw(h, KCV_LABEL).map(|m| m.to_vec()),
            KeyType::Aes256 => self.gcm_raw(h, &KCV_NONCE, KCV_LABEL, &[]),
        };
        let kcv = match kcv {
            Ok(k) => k,
            Err(e) => {
                let _ = self.s()?.destroy_object(h);
                return Err(e);
            }
        };
        let id = key_id_from_kcv(t, &kcv);
        if self.lookup(&id).is_ok() {
            let _ = self.s()?.destroy_object(h);
        } else if let Err(e) = self.s()?.update_attributes(h, &[Attribute::Id(id.to_vec())]) {
            let _ = self.s()?.destroy_object(h);
            return Err(map(e));
        }
        Ok(id)
    }
}

impl Drop for Pkcs11Store {
    fn drop(&mut self) {
        self.session.take(); // closes the session
        if let Some(ctx) = self.ctx.take() {
            if self.we_initialized {
                let _ = ctx.finalize();
            }
        }
    }
}

impl KeyStore for Pkcs11Store {
    fn generate(&mut self, ty: u32, flags: u32) -> Result<KeyId> {
        let t = check_type_flags(ty, flags)?;
        let mech = match t {
            KeyType::Aes256 => Mechanism::AesKeyGen,
            KeyType::HmacSha256 => Mechanism::GenericSecretKeyGen,
        };
        let mut tpl = template(t, flags);
        tpl.push(Attribute::ValueLen((KEY_LEN as u64).into()));
        let h = self.s()?.generate_key(&mech, &tpl).map_err(map)?;
        self.assign_id(t, h)
    }

    fn import_key(&mut self, ty: u32, material: &[u8], flags: u32) -> Result<KeyId> {
        let t = check_type_flags(ty, flags)?;
        if material.len() != KEY_LEN {
            return Err(Status::BadArg);
        }
        let id = key_id_from_kcv(t, &kcv_software(t, material)?);
        if self.lookup(&id).is_ok() {
            return Ok(id);
        }
        let mut tpl = template(t, flags);
        tpl.push(Attribute::Value(material.to_vec()));
        tpl.push(Attribute::Id(id.to_vec()));
        self.s()?.create_object(&tpl).map_err(map)?;
        Ok(id)
    }

    fn destroy(&mut self, id: &KeyId) -> Result<()> {
        let (h, _) = self.resolve(id)?;
        self.cache.remove(id);
        self.s()?.destroy_object(h).map_err(map)
    }

    fn wrap(&mut self, kek: &KeyId, target: &KeyId) -> Result<Vec<u8>> {
        let w = self.find(kek, KeyType::Aes256)?;
        let (k, _) = self.resolve(target)?;
        match self.s()?.get_attributes(k, &[AttributeType::Extractable]).map_err(map)?.first() {
            Some(Attribute::Extractable(true)) => {}
            Some(Attribute::Extractable(false)) => return Err(Status::NotExtractable),
            _ => return Err(Status::Backend),
        }
        self.s()?.wrap_key(&Mechanism::AesKeyWrap, w, k).map_err(map)
    }

    fn unwrap(&mut self, kek: &KeyId, ty: u32, blob: &[u8], flags: u32) -> Result<KeyId> {
        let t = check_type_flags(ty, flags)?;
        if blob.len() != WRAP_LEN {
            return Err(Status::BadArg);
        }
        let w = self.find(kek, KeyType::Aes256)?;
        let h = self.s()?.unwrap_key(&Mechanism::AesKeyWrap, w, blob, &template(t, flags)).map_err(map_auth)?;
        self.assign_id(t, h)
    }

    fn hmac_sign(&mut self, id: &KeyId, msg: &[u8]) -> Result<Mac> {
        let h = self.find(id, KeyType::HmacSha256)?;
        self.sign_raw(h, msg)
    }

    fn hmac_verify(&mut self, id: &KeyId, msg: &[u8], tag: &[u8]) -> Result<()> {
        if tag.len() != MAC_LEN {
            return Err(Status::BadArg);
        }
        let h = self.find(id, KeyType::HmacSha256)?;
        self.s()?.verify(&Mechanism::Sha256Hmac, h, msg, tag).map_err(map)
    }

    fn seal(&mut self, id: &KeyId, nonce: Option<&[u8; NONCE_LEN]>, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        if nonce.is_some_and(|n| is_reserved_nonce(n)) {
            return Err(Status::BadArg);
        }
        let h = self.find(id, KeyType::Aes256)?;
        let n = match nonce {
            Some(n) => *n,
            None => fresh_nonce()?,
        };
        let ct = self.gcm_raw(h, &n, aad, pt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&n);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&mut self, id: &KeyId, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        let h = self.find(id, KeyType::Aes256)?;
        if sealed.len() < SEAL_OVERHEAD || is_reserved_nonce(&sealed[..NONCE_LEN]) {
            return Err(Status::VerifyFailed);
        }
        let mut iv: [u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().map_err(|_| Status::Internal)?;
        let p = GcmParams::new(&mut iv, aad, (TAG_LEN as u64 * 8).into()).map_err(|_| Status::Internal)?;
        self.s()?.decrypt(&Mechanism::AesGcm(p), h, &sealed[NONCE_LEN..]).map_err(map_auth)
    }

    fn hkdf_derive(&mut self, _: &KeyId, _: &[u8], _: &[u8], out_ty: u32, out_flags: u32) -> Result<KeyId> {
        check_type_flags(out_ty, out_flags)?;
        // SoftHSM 2.6 has no CKM_HKDF_DERIVE; see the C++ backend.
        Err(Status::Unsupported)
    }
}
