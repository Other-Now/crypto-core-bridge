//! Drives every `unsafe` block in `src/ffi.rs` through the C ABI from Rust, so
//! `cargo +nightly miri test -p ccb --features test-hooks --test miri` checks
//! them for UB. Miri cannot call C, so the PKCS#11 backend is compiled out
//! under cfg(miri) (`ccb_ctx_new_pkcs11` returns CCB_ERR_UNSUPPORTED after
//! its argument handling, which is the part with unsafe in it); everything
//! else is the real code with the pure-Rust software backend.
//!
//! Also runs natively as an ordinary test.
use ccb::ffi::*;
use std::ptr::{null, null_mut};

fn id0() -> ccb_key_id {
    ccb_key_id { bytes: [0; 32] }
}

#[test]
fn every_entry_point() {
    // SAFETY: all pointers below point to live locals of the stated lengths.
    unsafe {
        assert_eq!(ccb_abi_version(), CCB_ABI_VERSION);
        assert!(!ccb_status_str(CCB_ERR_PANIC).is_null());

        let mut ctx = null_mut();
        assert_eq!(ccb_ctx_new_software(null_mut()), CCB_ERR_NULL_ARG);
        assert_eq!(ccb_ctx_new_software(&mut ctx), CCB_OK);

        // PKCS#11 constructor: string + pin handling.
        let mut p11 = null_mut();
        let pin = b"1234";
        assert_eq!(ccb_ctx_new_pkcs11(null(), c"x".as_ptr(), pin.as_ptr(), 4, &mut p11), CCB_ERR_NULL_ARG);
        let rc = ccb_ctx_new_pkcs11(c"/nonexistent.so".as_ptr(), c"ccb".as_ptr(), pin.as_ptr(), 4, &mut p11);
        assert!(rc == CCB_ERR_UNSUPPORTED || rc == CCB_ERR_BACKEND);
        assert!(p11.is_null());

        let key = [0x42u8; 32];
        let (mut aes, mut mac, mut kek, mut exp, mut back, mut der) = (id0(), id0(), id0(), id0(), id0(), id0());
        assert_eq!(ccb_key_import(ctx, 1, key.as_ptr(), 32, 0, &mut aes), CCB_OK);
        assert_eq!(ccb_key_import(ctx, 1, null(), 32, 0, &mut aes), CCB_ERR_NULL_ARG);
        assert_eq!(ccb_key_import(ctx, 2, key.as_ptr(), 32, 0, &mut mac), CCB_OK);
        assert_eq!(ccb_key_generate(ctx, 1, 0, &mut kek), CCB_OK);
        assert_eq!(ccb_key_generate(null(), 1, 0, &mut kek), CCB_ERR_NULL_ARG);
        assert_eq!(ccb_key_generate(ctx, 2, CCB_FLAG_EXPORTABLE, &mut exp), CCB_OK);

        // AEAD: fixed and random nonce, short buffer, empty everything.
        let nonce = [7u8; 12];
        let pt = b"miri payload";
        let mut sealed = [0u8; 64];
        let mut n = 0usize;
        assert_eq!(
            ccb_aead_seal(
                ctx,
                &aes,
                nonce.as_ptr(),
                b"aad".as_ptr(),
                3,
                pt.as_ptr(),
                pt.len(),
                sealed.as_mut_ptr(),
                10,
                &mut n
            ),
            CCB_ERR_BUFFER_TOO_SMALL
        );
        assert_eq!(n, pt.len() + 28);
        assert_eq!(
            ccb_aead_seal(
                ctx,
                &aes,
                nonce.as_ptr(),
                b"aad".as_ptr(),
                3,
                pt.as_ptr(),
                pt.len(),
                sealed.as_mut_ptr(),
                64,
                &mut n
            ),
            CCB_OK
        );
        let mut opened = [0u8; 64];
        let mut m = 0usize;
        assert_eq!(
            ccb_aead_open(ctx, &aes, b"aad".as_ptr(), 3, sealed.as_ptr(), n, opened.as_mut_ptr(), 64, &mut m),
            CCB_OK
        );
        assert_eq!(&opened[..m], pt);
        assert_eq!(ccb_aead_seal(ctx, &aes, null(), null(), 0, null(), 0, sealed.as_mut_ptr(), 64, &mut n), CCB_OK);
        assert_eq!(ccb_aead_open(ctx, &aes, null(), 0, sealed.as_ptr(), n, null_mut(), 0, &mut m), CCB_OK);
        assert_eq!(m, 0);

        // HMAC
        let mut tag = [0u8; 32];
        assert_eq!(ccb_hmac_sign(ctx, &mac, pt.as_ptr(), pt.len(), tag.as_mut_ptr()), CCB_OK);
        assert_eq!(ccb_hmac_verify(ctx, &mac, pt.as_ptr(), pt.len(), tag.as_ptr(), 32), CCB_OK);
        tag[0] ^= 1;
        assert_eq!(ccb_hmac_verify(ctx, &mac, pt.as_ptr(), pt.len(), tag.as_ptr(), 32), CCB_ERR_VERIFY_FAILED);

        // wrap / unwrap
        let mut blob = [0u8; 40];
        assert_eq!(ccb_key_wrap(ctx, &kek, &exp, blob.as_mut_ptr(), 8, &mut n), CCB_ERR_BUFFER_TOO_SMALL);
        assert_eq!(ccb_key_wrap(ctx, &kek, &exp, blob.as_mut_ptr(), 40, &mut n), CCB_OK);
        assert_eq!(ccb_key_wrap(ctx, &kek, &aes, blob.as_mut_ptr(), 40, &mut n), CCB_ERR_NOT_EXTRACTABLE);
        assert_eq!(ccb_key_wrap(ctx, &kek, &exp, blob.as_mut_ptr(), 40, &mut n), CCB_OK);
        assert_eq!(ccb_key_unwrap(ctx, &kek, 2, blob.as_ptr(), 40, 0, &mut back), CCB_OK);
        assert_eq!(back.bytes, exp.bytes);

        // HKDF
        assert_eq!(ccb_hkdf_derive(ctx, &mac, b"s".as_ptr(), 1, null(), 0, 1, 0, &mut der), CCB_OK);
        assert_eq!(ccb_hkdf_derive(ctx, &mac, null(), 1, null(), 0, 1, 0, &mut der), CCB_ERR_NULL_ARG);

        // destroy
        for k in [&aes, &mac, &kek, &exp, &der] {
            assert_eq!(ccb_key_destroy(ctx, k), CCB_OK);
        }
        assert_eq!(ccb_key_destroy(ctx, &aes), CCB_ERR_NO_SUCH_KEY);
        assert_eq!(ccb_key_destroy(ctx, null()), CCB_ERR_NULL_ARG);

        #[cfg(feature = "test-hooks")]
        assert_eq!(ccb_test_panic(), CCB_ERR_PANIC);

        ccb_ctx_free(ctx);
        ccb_ctx_free(null_mut());
    }
}
