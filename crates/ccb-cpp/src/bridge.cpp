#include "ccb-cpp/src/bridge.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace ccb_rs {
namespace {

ccb::View v(u8s s) { return {s.data(), s.size()}; }

// A key ID arriving from Rust is always 32 bytes (the Rust wrapper takes
// &[u8; 32]); copy it rather than reinterpret the pointer.
ccb::KeyId id_of(u8s s) {
    ccb::KeyId id{};
    std::memcpy(id.data(), s.data(), std::min(s.size(), id.size()));
    return id;
}

int32_t put_id(ccb::Status st, const ccb::KeyId& id, rust::Slice<uint8_t> out) {
    if (st == ccb::Status::Ok) std::memcpy(out.data(), id.data(), std::min(out.size(), id.size()));
    return static_cast<int32_t>(st);
}

// Outputs on the store path go into a buffer Rust has already sized: one
// memcpy. (The first version grew a rust::Vec with push_back, one call into
// Rust per byte: 16x slower than the C++ core itself at 16 KiB.)
int32_t copy_out(ccb::Status st, const ccb::Bytes& b, rust::Slice<uint8_t> out, size_t& out_len) {
    if (st != ccb::Status::Ok) return static_cast<int32_t>(st);
    if (b.size() > out.size()) return static_cast<int32_t>(ccb::Status::Internal);
    if (!b.empty()) std::memcpy(out.data(), b.data(), b.size());
    out_len = b.size();
    return 0;
}

// Primitive layer only (test path, not timed).
void to_vec(const ccb::Bytes& b, rust::Vec<uint8_t>& out) {
    out.clear();
    out.reserve(b.size());
    for (uint8_t x : b) out.push_back(x);
}

}  // namespace

int32_t CppStore::generate(uint32_t ty, uint32_t flags, rust::Slice<uint8_t> out_id) {
    ccb::KeyId id{};
    return put_id(s_->generate(ty, flags, id), id, out_id);
}
int32_t CppStore::import_key(uint32_t ty, u8s material, uint32_t flags, rust::Slice<uint8_t> out_id) {
    ccb::KeyId id{};
    return put_id(s_->import_key(ty, v(material), flags, id), id, out_id);
}
int32_t CppStore::destroy(u8s id) { return static_cast<int32_t>(s_->destroy(id_of(id))); }
int32_t CppStore::wrap(u8s kek, u8s target, rust::Slice<uint8_t> out, size_t& out_len) {
    ccb::Bytes b;
    return copy_out(s_->wrap(id_of(kek), id_of(target), b), b, out, out_len);
}
int32_t CppStore::unwrap(u8s kek, uint32_t ty, u8s blob, uint32_t flags, rust::Slice<uint8_t> out_id) {
    ccb::KeyId id{};
    return put_id(s_->unwrap(id_of(kek), ty, v(blob), flags, id), id, out_id);
}
int32_t CppStore::hmac_sign(u8s id, u8s msg, rust::Slice<uint8_t> out_tag) {
    ccb::Mac m{};
    auto st = s_->hmac_sign(id_of(id), v(msg), m);
    if (st == ccb::Status::Ok) std::memcpy(out_tag.data(), m.data(), std::min(out_tag.size(), m.size()));
    return static_cast<int32_t>(st);
}
int32_t CppStore::hmac_verify(u8s id, u8s msg, u8s tag) {
    return static_cast<int32_t>(s_->hmac_verify(id_of(id), v(msg), v(tag)));
}
int32_t CppStore::seal(u8s id, u8s nonce, u8s aad, u8s pt, rust::Slice<uint8_t> out, size_t& out_len) {
    ccb::Bytes b;
    // Empty nonce slice = "pick a random nonce" (the Rust side passes 0 or 12 bytes).
    auto st = s_->seal(id_of(id), nonce.empty() ? nullptr : nonce.data(), v(aad), v(pt), b);
    return copy_out(st, b, out, out_len);
}
int32_t CppStore::open(u8s id, u8s aad, u8s sealed, rust::Slice<uint8_t> out, size_t& out_len) {
    ccb::Bytes b;
    return copy_out(s_->open(id_of(id), v(aad), v(sealed), b), b, out, out_len);
}
int32_t CppStore::hkdf_derive(u8s base, u8s salt, u8s info, uint32_t out_ty, uint32_t out_flags,
                              rust::Slice<uint8_t> out_id) {
    ccb::KeyId id{};
    return put_id(s_->hkdf_derive(id_of(base), v(salt), v(info), out_ty, out_flags, id), id, out_id);
}

std::unique_ptr<CppStore> new_software_store() { return std::make_unique<CppStore>(ccb::make_software_store()); }

std::unique_ptr<CppStore> new_pkcs11_store(rust::Str module, rust::Str label, u8s pin, int32_t& status) {
    ccb::Status st{};
    auto s = ccb::make_pkcs11_store(std::string(module), std::string(label), v(pin), &st);
    status = static_cast<int32_t>(st);
    return s ? std::make_unique<CppStore>(std::move(s)) : nullptr;
}

bool prim_hmac_sha256(u8s key, u8s msg, rust::Slice<uint8_t> out) {
    ccb::Mac m{};
    if (!ccb::prim::hmac_sha256(v(key), v(msg), m)) return false;
    std::memcpy(out.data(), m.data(), std::min(out.size(), m.size()));
    return true;
}
bool prim_gcm_seal(u8s key, u8s nonce, u8s aad, u8s pt, rust::Vec<uint8_t>& out) {
    ccb::Bytes b;
    if (!ccb::prim::gcm_seal(v(key), v(nonce), v(aad), v(pt), b)) return false;
    to_vec(b, out);
    return true;
}
bool prim_gcm_open(u8s key, u8s nonce, u8s aad, u8s ct, rust::Vec<uint8_t>& out) {
    ccb::Bytes b;
    if (!ccb::prim::gcm_open(v(key), v(nonce), v(aad), v(ct), b)) return false;
    to_vec(b, out);
    return true;
}
bool prim_hkdf_sha256(u8s ikm, u8s salt, u8s info, rust::Slice<uint8_t> okm) {
    return ccb::prim::hkdf_sha256(v(ikm), v(salt), v(info), {okm.data(), okm.size()});
}
bool prim_aes_kw_wrap(u8s kek, u8s key, rust::Vec<uint8_t>& out) {
    ccb::Bytes b;
    if (!ccb::prim::aes_kw_wrap(v(kek), v(key), b)) return false;
    to_vec(b, out);
    return true;
}
bool prim_aes_kw_unwrap(u8s kek, u8s blob, rust::Vec<uint8_t>& out) {
    ccb::Secret s;
    if (!ccb::prim::aes_kw_unwrap(v(kek), v(blob), s)) return false;
    ccb::Bytes b(s.data(), s.data() + s.size());
    to_vec(b, out);
    return true;
}

}  // namespace ccb_rs
