//! Wycheproof vectors against the primitive layer of BOTH implementations
//! (RustCrypto and OpenSSL). Scope is the parameter set the API exposes:
//! AES-256-GCM with 96-bit IV and 128-bit tag, HMAC-SHA256, HKDF-SHA256,
//! AES-256 key wrap. Every vector in scope must give the expected result on
//! both sides; counts are printed so the coverage is visible.
use ccb_cpp::sys;
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = format!("{}/../../testvectors/wycheproof/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).expect(&p)).unwrap()
}
fn hx(t: &Value, k: &str) -> Vec<u8> {
    hex::decode(t[k].as_str().unwrap()).unwrap()
}
fn tests(v: &Value) -> Vec<(&Value, &Value)> {
    let mut out = vec![];
    for g in v["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            out.push((g, t));
        }
    }
    out
}
/// Some(true) = must accept, Some(false) = must reject, None = "acceptable".
fn expect_valid(t: &Value) -> Option<bool> {
    match t["result"].as_str().unwrap() {
        "valid" => Some(true),
        "invalid" => Some(false),
        _ => None,
    }
}

#[test]
fn aes_gcm() {
    let all = load("aes_gcm_test.json");
    let all = tests(&all);
    let mut run = 0;
    for &(g, t) in &all {
        if g["keySize"] != 256 || g["ivSize"] != 96 || g["tagSize"] != 128 {
            continue;
        }
        run += 1;
        let (key, iv, aad, msg, ct, tag) =
            (hx(t, "key"), hx(t, "iv"), hx(t, "aad"), hx(t, "msg"), hx(t, "ct"), hx(t, "tag"));
        let iv: [u8; 12] = iv.try_into().unwrap();
        let mut ct_tag = ct.clone();
        ct_tag.extend_from_slice(&tag);
        let valid = expect_valid(t);
        let id = &t["tcId"];

        let rust_open = ccb::prim::gcm_open(&key, &iv, &aad, &ct_tag);
        let mut cpp_pt = Vec::new();
        let cpp_open = sys::prim_gcm_open(&key, &iv, &aad, &ct_tag, &mut cpp_pt);
        if let Some(v) = valid {
            assert_eq!(rust_open.is_some(), v, "rust tc {id}");
            assert_eq!(cpp_open, v, "c++ tc {id}");
        }
        if valid == Some(true) {
            assert_eq!(rust_open.as_deref(), Some(&msg[..]), "rust tc {id}");
            assert_eq!(cpp_pt, msg, "c++ tc {id}");
            let mut c = Vec::new();
            assert!(sys::prim_gcm_seal(&key, &iv, &aad, &msg, &mut c));
            assert_eq!(c, ct_tag, "c++ seal tc {id}");
            assert_eq!(ccb::prim::gcm_seal(&key, &iv, &aad, &msg).unwrap(), ct_tag, "rust seal tc {id}");
        }
    }
    println!("aes_gcm: {run} of {} vectors in scope, all pass on Rust and C++", all.len());
    assert!(run > 0);
}

#[test]
fn hmac_sha256() {
    let all = load("hmac_sha256_test.json");
    let all = tests(&all);
    for &(g, t) in &all {
        let tag_len = g["tagSize"].as_u64().unwrap() as usize / 8;
        let (key, msg, tag) = (hx(t, "key"), hx(t, "msg"), hx(t, "tag"));
        let r = ccb::prim::hmac_sha256(&key, &msg);
        let mut c = [0u8; 32];
        assert!(sys::prim_hmac_sha256(&key, &msg, &mut c));
        assert_eq!(r, c, "rust/c++ disagree tc {}", t["tcId"]);
        if let Some(v) = expect_valid(t) {
            assert_eq!(r[..tag_len] == tag[..], v, "tc {}", t["tcId"]);
        }
    }
    println!("hmac_sha256: {} vectors, all pass on Rust and C++", all.len());
}

#[test]
fn hkdf_sha256() {
    let all = load("hkdf_sha256_test.json");
    let all = tests(&all);
    for &(_, t) in &all {
        let (ikm, salt, info, okm) = (hx(t, "ikm"), hx(t, "salt"), hx(t, "info"), hx(t, "okm"));
        let size = t["size"].as_u64().unwrap() as usize;
        let mut r = vec![0u8; size];
        let mut c = vec![0u8; size];
        let rok = ccb::prim::hkdf_sha256(&ikm, &salt, &info, &mut r);
        let cok = sys::prim_hkdf_sha256(&ikm, &salt, &info, &mut c);
        match expect_valid(t) {
            Some(true) => {
                assert!(rok && cok, "tc {}", t["tcId"]);
                assert_eq!(r, okm, "rust tc {}", t["tcId"]);
                assert_eq!(c, okm, "c++ tc {}", t["tcId"]);
            }
            Some(false) => {
                assert!(!rok, "rust accepted invalid tc {}", t["tcId"]);
                assert!(!cok, "c++ accepted invalid tc {}", t["tcId"]);
            }
            None => {}
        }
    }
    println!("hkdf_sha256: {} vectors, all pass on Rust and C++", all.len());
}

#[test]
fn aes_key_wrap() {
    let all = load("aes_wrap_test.json");
    let all = tests(&all);
    let mut run = 0;
    for &(g, t) in &all {
        if g["keySize"] != 256 {
            continue;
        }
        run += 1;
        let (kek, msg, ct) = (hx(t, "key"), hx(t, "msg"), hx(t, "ct"));
        let r = ccb::prim::aes_kw_unwrap(&kek, &ct);
        let mut c = Vec::new();
        let cok = sys::prim_aes_kw_unwrap(&kek, &ct, &mut c);
        match expect_valid(t) {
            Some(true) => {
                assert_eq!(r.as_deref().map(|v| &v[..]), Some(&msg[..]), "rust tc {}", t["tcId"]);
                assert!(cok && c == msg, "c++ tc {}", t["tcId"]);
                let mut w = Vec::new();
                assert!(sys::prim_aes_kw_wrap(&kek, &msg, &mut w) && w == ct, "c++ wrap tc {}", t["tcId"]);
                assert_eq!(ccb::prim::aes_kw_wrap(&kek, &msg).unwrap(), ct, "rust wrap tc {}", t["tcId"]);
            }
            Some(false) => {
                assert!(r.is_none(), "rust accepted invalid tc {}", t["tcId"]);
                assert!(!cok, "c++ accepted invalid tc {}", t["tcId"]);
            }
            None => {}
        }
    }
    println!("aes_key_wrap: {run} of {} vectors in scope, all pass on Rust and C++", all.len());
    assert!(run > 0);
}
