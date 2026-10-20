//! Differential conformance: the Rust and C++ implementations replay the same
//! seeded operation sequences and must agree on every status and output.
use ccb::KeyStore;
use ccb_cpp::diff::{seeded_bytes, Engine, Src, OP_NAMES};
use ccb_cpp::CppKeyStore;

fn report(label: &str, e: &Engine) {
    println!("{label}: {} ops", e.stats.ops);
    let names = [
        "ok",
        "null",
        "bad_arg",
        "buf",
        "no_key",
        "wrong_type",
        "verify",
        "not_extr",
        "unsupp",
        "backend",
        "panic",
        "internal",
    ];
    for (op, row) in e.stats.outcomes.iter().enumerate() {
        let parts: Vec<String> =
            row.iter().enumerate().filter(|(_, n)| **n > 0).map(|(i, n)| format!("{}={n}", names[i])).collect();
        println!("  {:<12} {}", OP_NAMES[op], parts.join(" "));
    }
}

#[test]
fn software_rust_vs_cpp() {
    let seeds = 200u64;
    let mut total = 0;
    for seed in 0..seeds {
        let mut r = ccb::software_store();
        let mut c = CppKeyStore::software();
        let bytes = seeded_bytes(seed + 1, 4000);
        let mut e = Engine::new(r.as_mut(), &mut c);
        if let Err(d) = e.run(&mut Src::new(&bytes)) {
            panic!("seed {seed}: {d}");
        }
        total += e.stats.ops;
        if seed == 0 {
            report("seed 0 (software)", &e);
        }
    }
    println!("software: {seeds} seeds, {total} ops, 0 divergences");
}

fn p11_env() -> Option<(String, String, String, String)> {
    let module = std::env::var("CCB_P11_MODULE").ok()?;
    let t1 = std::env::var("CCB_P11_TOKEN").ok()?;
    let t2 = std::env::var("CCB_P11_TOKEN2").ok()?;
    let pin = std::env::var("CCB_P11_PIN").unwrap_or_else(|_| "1234".into());
    Some((module, t1, t2, pin))
}

/// Token objects persist across runs; start both tokens empty so the two
/// object sets begin identical.
fn wipe_token(module: &str, label: &str, pin: &str) {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::object::{Attribute, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    let p = Pkcs11::new(module).unwrap();
    let _ = p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK));
    let slot = p
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| p.get_token_info(*s).unwrap().label().trim_end() == label)
        .expect("token");
    let s = p.open_rw_session(slot).unwrap();
    let _ = s.login(UserType::User, Some(&AuthPin::new(pin.into())));
    for h in s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY)]).unwrap() {
        s.destroy_object(h).unwrap();
    }
}

/// Rust and C++ PKCS#11 backends, each on its own SoftHSM token so the two
/// object sets evolve independently. One test owns both tokens, so the
/// PKCS#11 tests cannot interfere with each other when run in parallel.
#[test]
fn pkcs11_rust_vs_cpp() {
    let Some((module, t1, t2, pin)) = p11_env() else {
        println!("skipped: CCB_P11_MODULE / CCB_P11_TOKEN / CCB_P11_TOKEN2 unset");
        return;
    };
    let seeds = 10u64;
    let mut total = 0;
    for seed in 0..seeds {
        wipe_token(&module, &t1, &pin);
        wipe_token(&module, &t2, &pin);
        let mut r: Box<dyn KeyStore> = ccb::pkcs11_store(&module, &t1, pin.as_bytes()).expect("rust p11");
        let mut c = CppKeyStore::pkcs11(&module, &t2, pin.as_bytes()).expect("c++ p11");
        if seed == 0 {
            // Same imported key => same ID from the host-side KCV (software
            // store) and from the in-token KCV path.
            let mut soft = ccb::software_store();
            for (ty, m) in [(1u32, [0x31u8; 32]), (2, [0x32; 32])] {
                assert_eq!(soft.import_key(ty, &m, 1).unwrap(), c.import_key(ty, &m, 1).unwrap());
                c.destroy(&soft.import_key(ty, &m, 1).unwrap()).unwrap();
            }
        }
        let bytes = seeded_bytes(0xC0FFEE + seed, 6000);
        let mut e = Engine::new(r.as_mut(), &mut c);
        let res = e.run(&mut Src::new(&bytes));
        total += e.stats.ops;
        if seed == 0 {
            report("pkcs11 seed 0", &e);
        }
        if let Err(d) = res {
            panic!("seed {seed}: {d}");
        }
    }
    println!("pkcs11: {seeds} seeds, {total} ops, 0 divergences");
}

// ---- does the engine catch real porting bugs? -----------------------------------

/// The Rust store with one plausible porting bug planted.
struct Mutant {
    inner: Box<dyn KeyStore>,
    bug: usize,
}

const BUGS: [&str; 8] = [
    "open: truncated input reported as BadArg, not VerifyFailed",
    "hmac_verify: key lookup before the tag-length check",
    "seal: reserved KCV nonce accepted",
    "unwrap: integrity failure reported as BadArg",
    "hkdf_derive: salt and info swapped",
    "wrap: exportable flag ignored",
    "import: key ID from SHA-256(key) instead of the KCV",
    "open: AAD ignored",
];

impl KeyStore for Mutant {
    fn generate(&mut self, ty: u32, flags: u32) -> ccb::Result<ccb::KeyId> {
        self.inner.generate(ty, flags)
    }
    fn import_key(&mut self, ty: u32, m: &[u8], flags: u32) -> ccb::Result<ccb::KeyId> {
        let id = self.inner.import_key(ty, m, flags)?;
        if self.bug == 6 {
            return Ok(ccb::prim::sha256(m)); // and the real key is unreachable by this ID
        }
        Ok(id)
    }
    fn destroy(&mut self, id: &ccb::KeyId) -> ccb::Result<()> {
        self.inner.destroy(id)
    }
    fn wrap(&mut self, kek: &ccb::KeyId, target: &ccb::KeyId) -> ccb::Result<Vec<u8>> {
        match self.inner.wrap(kek, target) {
            Err(ccb::Status::NotExtractable) if self.bug == 5 => Ok(vec![0; 40]),
            r => r,
        }
    }
    fn unwrap(&mut self, kek: &ccb::KeyId, ty: u32, blob: &[u8], flags: u32) -> ccb::Result<ccb::KeyId> {
        match self.inner.unwrap(kek, ty, blob, flags) {
            Err(ccb::Status::VerifyFailed) if self.bug == 3 => Err(ccb::Status::BadArg),
            r => r,
        }
    }
    fn hmac_sign(&mut self, id: &ccb::KeyId, msg: &[u8]) -> ccb::Result<ccb::Mac> {
        self.inner.hmac_sign(id, msg)
    }
    fn hmac_verify(&mut self, id: &ccb::KeyId, msg: &[u8], tag: &[u8]) -> ccb::Result<()> {
        if self.bug == 1 {
            self.inner.hmac_sign(id, msg)?;
        }
        self.inner.hmac_verify(id, msg, tag)
    }
    fn seal(&mut self, id: &ccb::KeyId, nonce: Option<&[u8; 12]>, aad: &[u8], pt: &[u8]) -> ccb::Result<Vec<u8>> {
        if self.bug == 2 && nonce == Some(&ccb::KCV_NONCE) {
            return self.inner.seal(id, Some(&[0xfe; 12]), aad, pt);
        }
        self.inner.seal(id, nonce, aad, pt)
    }
    fn open(&mut self, id: &ccb::KeyId, aad: &[u8], sealed: &[u8]) -> ccb::Result<Vec<u8>> {
        match self.bug {
            0 if sealed.len() < ccb::SEAL_OVERHEAD => self.inner.open(id, aad, sealed).map_err(|e| {
                if e == ccb::Status::VerifyFailed {
                    ccb::Status::BadArg
                } else {
                    e
                }
            }),
            7 => {
                // Accept if it opens under any AAD we can think of: here, the
                // AAD the engine most often uses, b"x", or the empty AAD.
                self.inner.open(id, aad, sealed).or_else(|_| self.inner.open(id, b"", sealed))
            }
            _ => self.inner.open(id, aad, sealed),
        }
    }
    fn hkdf_derive(&mut self, b: &ccb::KeyId, salt: &[u8], info: &[u8], t: u32, f: u32) -> ccb::Result<ccb::KeyId> {
        if self.bug == 4 {
            return self.inner.hkdf_derive(b, info, salt, t, f);
        }
        self.inner.hkdf_derive(b, salt, info, t, f)
    }
}

#[test]
fn engine_catches_planted_bugs() {
    let mut caught = 0;
    for (bug, name) in BUGS.iter().enumerate() {
        let mut found = None;
        for seed in 0..200u64 {
            let mut m = Mutant { inner: ccb::software_store(), bug };
            let mut c = CppKeyStore::software();
            let bytes = seeded_bytes(seed + 1, 4000);
            let mut e = Engine::new(&mut m, &mut c);
            if let Err(d) = e.run(&mut Src::new(&bytes)) {
                found = Some((seed, e.stats.ops, d));
                break;
            }
        }
        match found {
            Some((seed, ops, d)) => {
                caught += 1;
                println!("caught  #{bug} {name}\n        seed {seed}, after {ops} ops: {d}");
            }
            None => println!("MISSED  #{bug} {name}"),
        }
    }
    println!("{caught}/{} planted bugs caught", BUGS.len());
    assert_eq!(caught, BUGS.len());
}
