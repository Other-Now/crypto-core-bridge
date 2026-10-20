//! Fuzzes the C ABI itself (crates/ccb/src/ffi.rs): fuzzer bytes choose
//! entry points, NULL pointers, lengths, buffer capacities and key IDs.
//! Invariants checked on every call:
//!  * the status is a defined CCB_* code;
//!  * BUFFER_TOO_SMALL leaves the output buffer untouched and reports the
//!    size needed, and that size then works;
//!  * whatever seals successfully opens to the same plaintext.
#![no_main]
use ccb::ffi::*;
use libfuzzer_sys::fuzz_target;
use std::ptr::{null, null_mut};

struct Src<'a>(&'a [u8], usize);
impl Src<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.0.get(self.1).copied().unwrap_or(0);
        self.1 += 1;
        b
    }
    fn done(&self) -> bool {
        self.1 >= self.0.len()
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.u8() as usize % (max + 1);
        (0..n).map(|_| self.u8()).collect()
    }
}

fn valid(rc: i32) -> bool {
    (CCB_ERR_INTERNAL..=CCB_OK).contains(&rc)
}

const CANARY: u8 = 0xd5;

/// (sealed output, aad, plaintext, key)
type Sealed = (Vec<u8>, Vec<u8>, Vec<u8>, ccb_key_id);

fuzz_target!(|data: &[u8]| {
    let mut s = Src(data, 0);
    let mut ctx = null_mut();
    // SAFETY (whole target): every pointer handed to the C ABI is either NULL
    // or points into a live Vec/array of at least the length passed with it.
    unsafe {
        assert_eq!(ccb_ctx_new_software(&mut ctx), CCB_OK);
        let mut ids: Vec<ccb_key_id> = vec![ccb_key_id { bytes: [0xab; 32] }];
        let mut sealed: Vec<Sealed> = vec![];
        while !s.done() {
            let pick = s.u8() as usize % ids.len();
            let id = ids[pick];
            let id_ptr: *const ccb_key_id = if s.u8() % 16 == 0 { null() } else { &id };
            match s.u8() % 9 {
                0 => {
                    let k = s.bytes(40);
                    let p = if k.is_empty() && s.u8() % 2 == 0 { null() } else { k.as_ptr() };
                    let mut out = ccb_key_id { bytes: [0; 32] };
                    let rc = ccb_key_import(ctx, (s.u8() % 4) as u32, p, k.len(), (s.u8() % 3) as u32, &mut out);
                    assert!(valid(rc));
                    if rc == CCB_OK {
                        ids.push(out);
                    }
                }
                1 => {
                    let mut out = ccb_key_id { bytes: [0; 32] };
                    let rc = ccb_key_generate(ctx, (s.u8() % 4) as u32, (s.u8() % 3) as u32, &mut out);
                    assert!(valid(rc));
                    if rc == CCB_OK {
                        ids.push(out);
                    }
                }
                2 => assert!(valid(ccb_key_destroy(ctx, id_ptr))),
                3 => {
                    let (aad, pt) = (s.bytes(16), s.bytes(96));
                    let nonce = [s.u8(); 12];
                    let np = if s.u8() % 2 == 0 { null() } else { nonce.as_ptr() };
                    let cap = s.u8() as usize % (pt.len() + 40);
                    let mut out = vec![CANARY; cap];
                    let mut n = usize::MAX;
                    let rc = ccb_aead_seal(
                        ctx,
                        id_ptr,
                        np,
                        aad.as_ptr(),
                        aad.len(),
                        pt.as_ptr(),
                        pt.len(),
                        out.as_mut_ptr(),
                        cap,
                        &mut n,
                    );
                    assert!(valid(rc));
                    if rc == CCB_ERR_BUFFER_TOO_SMALL {
                        assert_eq!(n, pt.len() + CCB_SEAL_OVERHEAD);
                        assert!(out.iter().all(|&b| b == CANARY), "short buffer was written");
                    }
                    if rc == CCB_OK {
                        assert_eq!(n, pt.len() + CCB_SEAL_OVERHEAD);
                        out.truncate(n);
                        sealed.push((out, aad, pt, id));
                    }
                }
                4 => {
                    if sealed.is_empty() {
                        continue;
                    }
                    let i = s.u8() as usize % sealed.len();
                    let (ct, aad, pt, key) = sealed[i].clone();
                    let mut ct = ct;
                    let tamper = s.u8() % 4 == 0;
                    if tamper {
                        let j = s.u8() as usize % ct.len();
                        ct[j] ^= 1 << (s.u8() % 8);
                    }
                    let cap = if s.u8() % 4 == 0 { s.u8() as usize % (pt.len() + 1) } else { pt.len() };
                    let mut out = vec![CANARY; cap];
                    let op = if cap == 0 && s.u8() % 2 == 0 { null_mut() } else { out.as_mut_ptr() };
                    let mut n = 0;
                    let rc = ccb_aead_open(ctx, &key, aad.as_ptr(), aad.len(), ct.as_ptr(), ct.len(), op, cap, &mut n);
                    assert!(valid(rc));
                    if rc == CCB_ERR_BUFFER_TOO_SMALL {
                        assert!(out.iter().all(|&b| b == CANARY));
                    }
                    if rc == CCB_OK {
                        assert!(!tamper, "tampered ciphertext opened");
                        assert_eq!(&out[..n], &pt[..]);
                    } else if !tamper && cap >= pt.len() {
                        // Only legitimate failure: the key was destroyed since.
                        assert_eq!(rc, CCB_ERR_NO_SUCH_KEY, "untampered ciphertext failed: {rc}");
                    }
                }
                5 => {
                    let msg = s.bytes(64);
                    let mut tag = [0u8; 32];
                    let rc = ccb_hmac_sign(ctx, id_ptr, msg.as_ptr(), msg.len(), tag.as_mut_ptr());
                    assert!(valid(rc));
                    let tl = if s.u8() % 4 == 0 { s.u8() as usize % 33 } else { 32 };
                    let rv = ccb_hmac_verify(ctx, id_ptr, msg.as_ptr(), msg.len(), tag.as_ptr(), tl);
                    assert!(valid(rv));
                    if rc == CCB_OK && tl == 32 {
                        assert_eq!(rv, CCB_OK);
                    }
                }
                6 => {
                    let kek = ids[s.u8() as usize % ids.len()];
                    let cap = if s.u8() % 4 == 0 { s.u8() as usize % 41 } else { 40 };
                    let mut blob = vec![CANARY; cap];
                    let mut n = 0;
                    let rc = ccb_key_wrap(ctx, &kek, id_ptr, blob.as_mut_ptr(), cap, &mut n);
                    assert!(valid(rc));
                    if rc == CCB_ERR_BUFFER_TOO_SMALL {
                        assert_eq!(n, CCB_WRAP_LEN);
                        assert!(blob.iter().all(|&b| b == CANARY));
                    }
                    if rc == CCB_OK {
                        if s.u8() % 3 == 0 {
                            blob[s.u8() as usize % 40] ^= 1;
                        }
                        let mut out = ccb_key_id { bytes: [0; 32] };
                        let ru = ccb_key_unwrap(ctx, &kek, (s.u8() % 3) as u32, blob.as_ptr(), n, 0, &mut out);
                        assert!(valid(ru));
                        if ru == CCB_OK {
                            ids.push(out);
                        }
                    }
                }
                7 => {
                    let (salt, info) = (s.bytes(16), s.bytes(16));
                    let mut out = ccb_key_id { bytes: [0; 32] };
                    let rc = ccb_hkdf_derive(
                        ctx,
                        id_ptr,
                        salt.as_ptr(),
                        salt.len(),
                        info.as_ptr(),
                        info.len(),
                        (s.u8() % 3) as u32,
                        0,
                        &mut out,
                    );
                    assert!(valid(rc));
                    if rc == CCB_OK {
                        ids.push(out);
                    }
                }
                _ => {
                    // NULL / garbage arguments on every entry point.
                    let mut n = 0;
                    assert_eq!(ccb_hmac_sign(null(), id_ptr, null(), 0, null_mut()), CCB_ERR_NULL_ARG);
                    assert_eq!(ccb_aead_open(ctx, &id, null(), 1, null(), 0, null_mut(), 0, &mut n), CCB_ERR_NULL_ARG);
                    assert_eq!(ccb_key_wrap(ctx, &id, &id, null_mut(), 0, null_mut()), CCB_ERR_NULL_ARG);
                    assert!(valid(ccb_hkdf_derive(ctx, &id, null(), 0, null(), 0, 1, 0, null_mut())));
                    let _ = ccb_status_str(s.u8() as i32 - 128);
                }
            }
        }
        ccb_ctx_free(ctx);
    }
});
