//! Per-operation cost, Rust side of the harness (C++ side: cpp/bench/bench.cpp;
//! same method, same CSV format).
//!
//!   rust          Rust implementation through the KeyStore trait
//!   rust-cabi-rs  Rust implementation through its own C ABI, called from Rust
//!                 (the boundary layer: catch_unwind, mutex, checks, copy-out)
//!   cpp-cxx       C++ core called from Rust through the cxx bridge
//!   rust-p11 / cpp-cxx-p11   the PKCS#11 backends (SoftHSM2), if configured
use std::hint::black_box;
use std::time::Instant;

use ccb::ffi::*;
use ccb::KeyStore;
use ccb_cpp::CppKeyStore;

fn run(reps: usize, imp: &str, op: &str, size: usize, mut f: impl FnMut()) {
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        if t.elapsed().as_secs_f64() > 0.020 || n >= 1 << 26 {
            break;
        }
        n *= 2;
    }
    let mut ns: Vec<f64> = (0..reps)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed().as_nanos() as f64 / n as f64
        })
        .collect();
    ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("{imp},{op},{size},{:.1},{:.1},{:.1}", ns[ns.len() / 2], ns[0], ns[ns.len() - 1]);
}

fn bench_store(reps: usize, ks: &mut dyn KeyStore, imp: &str, sizes: &[usize], hkdf: bool) {
    let k = [0x42u8; 32];
    let aes = ks.import_key(1, &k, 0).unwrap();
    let mac = ks.import_key(2, &k, 0).unwrap();
    for &sz in sizes {
        let msg = vec![0x61u8; sz];
        run(reps, imp, "hmac_sign", sz, || {
            black_box(ks.hmac_sign(&mac, &msg).unwrap());
        });
        run(reps, imp, "seal", sz, || {
            black_box(ks.seal(&aes, None, b"", &msg).unwrap());
        });
        let s = ks.seal(&aes, None, b"", &msg).unwrap();
        run(reps, imp, "open", sz, || {
            black_box(ks.open(&aes, b"", &s).unwrap());
        });
    }
    if hkdf {
        run(reps, imp, "hkdf_derive", 32, || {
            black_box(ks.hkdf_derive(&mac, &[1, 2, 3, 4], b"", 1, 0).unwrap());
        });
    }
}

fn bench_cabi(reps: usize, sizes: &[usize]) {
    // SAFETY: all pointers are to live buffers of the stated sizes.
    unsafe {
        let mut ctx = std::ptr::null_mut();
        ccb_ctx_new_software(&mut ctx);
        let k = [0x42u8; 32];
        let (mut aes, mut mac) = (ccb_key_id { bytes: [0; 32] }, ccb_key_id { bytes: [0; 32] });
        ccb_key_import(ctx, 1, k.as_ptr(), 32, 0, &mut aes);
        ccb_key_import(ctx, 2, k.as_ptr(), 32, 0, &mut mac);
        for &sz in sizes {
            let msg = vec![0x61u8; sz];
            let mut out = vec![0u8; sz + 28];
            let mut pt = vec![0u8; sz];
            let mut tag = [0u8; 32];
            let (mut n, mut m) = (0usize, 0usize);
            run(reps, "rust-cabi-rs", "hmac_sign", sz, || {
                ccb_hmac_sign(ctx, &mac, msg.as_ptr(), sz, tag.as_mut_ptr());
            });
            run(reps, "rust-cabi-rs", "seal", sz, || {
                ccb_aead_seal(
                    ctx,
                    &aes,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    msg.as_ptr(),
                    sz,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut n,
                );
            });
            ccb_aead_seal(
                ctx,
                &aes,
                std::ptr::null(),
                std::ptr::null(),
                0,
                msg.as_ptr(),
                sz,
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            );
            run(reps, "rust-cabi-rs", "open", sz, || {
                ccb_aead_open(ctx, &aes, std::ptr::null(), 0, out.as_ptr(), n, pt.as_mut_ptr(), pt.len(), &mut m);
            });
        }
        ccb_ctx_free(ctx);
    }
}

fn main() {
    let reps: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    let sizes = [64, 1024, 16384];
    println!("impl,op,size,median_ns,min_ns,max_ns");
    bench_store(reps, ccb::software_store().as_mut(), "rust", &sizes, true);
    bench_cabi(reps, &sizes);
    // Attribution: what the C ABI's open path pays to wipe its intermediate
    // plaintext buffer before returning.
    for &sz in &sizes {
        let mut v = vec![0x61u8; sz];
        run(reps, "attrib", "zeroize_vec", sz, || {
            zeroize::Zeroize::zeroize(&mut v[..]);
            black_box(&mut v);
        });
    }
    bench_store(reps, &mut CppKeyStore::software(), "cpp-cxx", &sizes, true);

    if let Ok(module) = std::env::var("CCB_P11_MODULE") {
        let label = std::env::var("CCB_P11_TOKEN").unwrap_or_else(|_| "ccb".into());
        let pin = std::env::var("CCB_P11_PIN").unwrap_or_else(|_| "1234".into());
        let reps = (reps / 3).max(5);
        if let Ok(mut s) = ccb::pkcs11_store(&module, &label, pin.as_bytes()) {
            bench_store(reps, s.as_mut(), "rust-p11", &[64, 1024], false);
        }
        if let Ok(mut s) = CppKeyStore::pkcs11(&module, &label, pin.as_bytes()) {
            bench_store(reps, &mut s, "cpp-cxx-p11", &[64, 1024], false);
        }
    }
}
