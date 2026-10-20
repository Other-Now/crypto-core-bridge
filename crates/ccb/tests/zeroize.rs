//! Zeroization check for the Rust implementation.
//!
//! A scanning global allocator inspects every block before it is freed
//! (including the old block of every realloc) for 16-byte windows of the test
//! keys. Key material still readable in freed memory was not wiped.
//!
//! Two controls prove the detector works: an unwiped Vec copy, and a HashMap
//! that stores `Zeroizing<[u8; 32]>` inline. The latter is the trap the
//! software store avoids by boxing keys: `Zeroizing` wipes the value on drop,
//! but a rehash *moves* entries with memcpy and frees the old table without
//! dropping anything, so stale copies escape.
#![cfg(not(miri))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use zeroize::Zeroizing;

struct Scanner;

const MAX_PATTERNS: usize = 4;
static mut PATTERNS: [[u8; 32]; MAX_PATTERNS] = [[0; 32]; MAX_PATTERNS];
static NPATTERNS: AtomicUsize = AtomicUsize::new(0);
static ENABLED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static SCANNED: AtomicUsize = AtomicUsize::new(0);

fn scan(block: &[u8]) {
    SCANNED.fetch_add(1, Ordering::Relaxed);
    #[allow(clippy::needless_range_loop)] // indexing a static mut through addr_of!, on purpose
    for i in 0..NPATTERNS.load(Ordering::Acquire) {
        // SAFETY: PATTERNS[i] is written only before NPATTERNS is bumped past
        // i (Release), and never again; this read happens after the Acquire.
        let pat = unsafe { &*std::ptr::addr_of!(PATTERNS[i]) };
        for half in [&pat[..16], &pat[16..]] {
            if block.windows(16).any(|w| w == half) {
                HITS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
}

// SAFETY: forwards to System; the only addition is reading the block before
// it is released, while it is still allocated.
unsafe impl GlobalAlloc for Scanner {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if ENABLED.load(Ordering::Relaxed) && l.size() > 0 {
            // SAFETY: p is a live allocation of l.size() bytes until the
            // System.dealloc below.
            scan(unsafe { std::slice::from_raw_parts(p, l.size()) });
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, l) }
    }
    // realloc: the default implementation is alloc + copy + dealloc, so the
    // old block is scanned like any other free.
}

#[global_allocator]
static A: Scanner = Scanner;

fn add_pattern(k: &[u8; 32]) {
    let i = NPATTERNS.load(Ordering::Relaxed);
    assert!(i < MAX_PATTERNS);
    // SAFETY: single-threaded setup; slot i is not yet visible to scan().
    unsafe { (*std::ptr::addr_of_mut!(PATTERNS))[i] = *k };
    NPATTERNS.store(i + 1, Ordering::Release);
}

static AES_KEY: [u8; 32] =
    *b"ZERO-AES\x91\x82\x73\x64\x55\x46\x37\x28\x19\x0a\xfb\xec\xdd\xce\xbf\xb0\xa1\x92\x83\x74\x65\x56\x47\x38";
static MAC_KEY: [u8; 32] =
    *b"ZERO-MAC\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1\x02\x13\x24\x35\x46\x57\x68\x79\x8b";

fn exercise_store() {
    let mut ks = ccb::software_store();
    let a = ks.import_key(1, &AES_KEY, ccb::FLAG_EXPORTABLE).unwrap();
    let m = ks.import_key(2, &MAC_KEY, ccb::FLAG_EXPORTABLE).unwrap();
    let kek = ks.generate(1, 0).unwrap();
    // Enough keys to force the store's HashMap to grow several times.
    let extra: Vec<_> = (0..200).map(|_| ks.generate(2, 0).unwrap()).collect();
    for _ in 0..50 {
        let s = ks.seal(&a, None, b"", b"the quick brown fox").unwrap();
        ks.open(&a, b"", &s).unwrap();
        let t = ks.hmac_sign(&m, b"msg").unwrap();
        ks.hmac_verify(&m, b"msg", &t).unwrap();
    }
    let d = ks.hkdf_derive(&m, b"salt", b"info", 1, 0).unwrap();
    let blob = ks.wrap(&kek, &a).unwrap();
    ks.unwrap(&kek, 1, &blob, 0).unwrap();
    ks.wrap(&kek, &m).unwrap();
    for id in [a, m, d].iter().chain(&extra) {
        ks.destroy(id).unwrap();
    }
}

fn exercise_ffi() {
    use ccb::ffi::*;
    // SAFETY: valid pointers to live stack/static data throughout.
    unsafe {
        let mut ctx = std::ptr::null_mut();
        assert_eq!(ccb_ctx_new_software(&mut ctx), CCB_OK);
        let mut id = ccb_key_id { bytes: [0; 32] };
        assert_eq!(ccb_key_import(ctx, 1, AES_KEY.as_ptr(), 32, 0, &mut id), CCB_OK);
        let mut out = [0u8; 64];
        let mut pt = [0u8; 64];
        let mut n = 0;
        assert_eq!(
            ccb_aead_seal(
                ctx,
                &id,
                std::ptr::null(),
                std::ptr::null(),
                0,
                b"hi".as_ptr(),
                2,
                out.as_mut_ptr(),
                64,
                &mut n
            ),
            CCB_OK
        );
        assert_eq!(ccb_aead_open(ctx, &id, std::ptr::null(), 0, out.as_ptr(), n, pt.as_mut_ptr(), 64, &mut n), CCB_OK);
        ccb_ctx_free(ctx);
    }
}

#[test]
fn freed_memory_holds_no_key_bytes() {
    add_pattern(&AES_KEY);
    add_pattern(&MAC_KEY);
    let mut derived = [0u8; 32];
    assert!(ccb::prim::hkdf_sha256(&MAC_KEY, b"salt", b"info", &mut derived));
    add_pattern(&derived);

    ENABLED.store(true, Ordering::SeqCst);
    exercise_store();
    exercise_ffi();
    let core_hits = HITS.load(Ordering::SeqCst);
    let scanned = SCANNED.load(Ordering::SeqCst);

    // Control 1: an unwiped heap copy is caught.
    drop(AES_KEY.to_vec());
    let after_vec = HITS.load(Ordering::SeqCst);

    // Control 2: Zeroizing values stored inline in a HashMap leak on rehash.
    {
        let mut m: HashMap<u32, Zeroizing<[u8; 32]>> = HashMap::new();
        m.insert(0, Zeroizing::new(MAC_KEY));
        for i in 1..100 {
            m.insert(i, Zeroizing::new([0u8; 32]));
        }
    }
    let after_map = HITS.load(Ordering::SeqCst);
    ENABLED.store(false, Ordering::SeqCst);

    println!("freed blocks scanned: {scanned}");
    println!("hits from store + FFI: {core_hits}");
    println!("control, unwiped Vec copy: {} hit(s)", after_vec - core_hits);
    println!("control, inline Zeroizing in a rehashing HashMap: {} hit(s)", after_map - after_vec);
    assert_eq!(core_hits, 0);
    assert!(after_vec > core_hits, "detector missed an unwiped Vec");
    assert!(after_map > after_vec, "detector missed the HashMap rehash leak");
}
