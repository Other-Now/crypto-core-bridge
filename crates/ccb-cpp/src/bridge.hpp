// cxx shim: exposes the C++ core (cpp/include/ccb/core.hpp) to Rust.
// Status codes cross as int32_t, the same contract as the C ABI.
#pragma once
#include <cstdint>
#include <memory>

#include "ccb/core.hpp"
#include "rust/cxx.h"

namespace ccb_rs {

using u8s = rust::Slice<const uint8_t>;

class CppStore {
public:
    explicit CppStore(std::unique_ptr<ccb::KeyStore> s) : s_(std::move(s)) {}
    int32_t generate(uint32_t ty, uint32_t flags, rust::Slice<uint8_t> out_id);
    int32_t import_key(uint32_t ty, u8s material, uint32_t flags, rust::Slice<uint8_t> out_id);
    int32_t destroy(u8s id);
    int32_t wrap(u8s kek, u8s target, rust::Slice<uint8_t> out, size_t& out_len);
    int32_t unwrap(u8s kek, uint32_t ty, u8s blob, uint32_t flags, rust::Slice<uint8_t> out_id);
    int32_t hmac_sign(u8s id, u8s msg, rust::Slice<uint8_t> out_tag);
    int32_t hmac_verify(u8s id, u8s msg, u8s tag);
    int32_t seal(u8s id, u8s nonce, u8s aad, u8s pt, rust::Slice<uint8_t> out, size_t& out_len);
    int32_t open(u8s id, u8s aad, u8s sealed, rust::Slice<uint8_t> out, size_t& out_len);
    int32_t hkdf_derive(u8s base, u8s salt, u8s info, uint32_t out_ty, uint32_t out_flags,
                        rust::Slice<uint8_t> out_id);

private:
    std::unique_ptr<ccb::KeyStore> s_;
};

std::unique_ptr<CppStore> new_software_store();
std::unique_ptr<CppStore> new_pkcs11_store(rust::Str module, rust::Str label, u8s pin, int32_t& status);

// Primitive layer, for the Wycheproof harness.
bool prim_hmac_sha256(u8s key, u8s msg, rust::Slice<uint8_t> out);
bool prim_gcm_seal(u8s key, u8s nonce, u8s aad, u8s pt, rust::Vec<uint8_t>& out);
bool prim_gcm_open(u8s key, u8s nonce, u8s aad, u8s ct, rust::Vec<uint8_t>& out);
bool prim_hkdf_sha256(u8s ikm, u8s salt, u8s info, rust::Slice<uint8_t> okm);
bool prim_aes_kw_wrap(u8s kek, u8s key, rust::Vec<uint8_t>& out);
bool prim_aes_kw_unwrap(u8s kek, u8s blob, rust::Vec<uint8_t>& out);

}  // namespace ccb_rs
