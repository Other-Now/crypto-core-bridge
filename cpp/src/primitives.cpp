// OpenSSL 3 primitives. EVP / EVP_MAC / EVP_KDF only: no deprecated
// low-level AES_* or HMAC_* calls.
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>

#include "ccb/core.hpp"

namespace ccb {

// ---- Secret ---------------------------------------------------------------

Secret::Secret(View v) : p_(new uint8_t[v.size() ? v.size() : 1]), n_(v.size()) {
    if (n_) std::memcpy(p_.get(), v.data(), n_);
}
Secret::Secret(size_t n) : p_(new uint8_t[n ? n : 1]()), n_(n) {}
Secret::~Secret() { wipe(); }
Secret& Secret::operator=(Secret&& o) noexcept {
    if (this != &o) {
        wipe();
        p_ = std::move(o.p_);
        n_ = o.n_;
        o.n_ = 0;
    }
    return *this;
}
void Secret::wipe() {
    if (p_ && n_) OPENSSL_cleanse(p_.get(), n_);
}

namespace prim {
namespace {
struct CipherCtxFree { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
struct MacCtxFree { void operator()(EVP_MAC_CTX* c) const { EVP_MAC_CTX_free(c); } };
struct KdfCtxFree { void operator()(EVP_KDF_CTX* c) const { EVP_KDF_CTX_free(c); } };
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree>;

// Non-null pointer for zero-length inputs: some EVP calls reject nullptr even
// when the length is 0.
const unsigned char* nz(View v) {
    static const unsigned char empty = 0;
    return v.empty() ? &empty : v.data();
}

// Algorithms are fetched once and kept for the life of the process. A fetch
// is a provider lookup under a lock: 150-180 ns per fetch+free on the CI
// runner (bench "attrib" rows), paid on every call by the obvious way of
// writing EVP code. OpenSSL 3 documents this "explicit fetch, then reuse"
// pattern. The handles are intentionally never freed (still reachable).
EVP_MAC* hmac_alg() {
    static EVP_MAC* m = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    return m;
}
EVP_KDF* hkdf_alg() {
    static EVP_KDF* k = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    return k;
}
EVP_CIPHER* cipher_alg(const char* name) {
    static EVP_CIPHER* gcm[3] = {EVP_CIPHER_fetch(nullptr, "AES-128-GCM", nullptr),
                                 EVP_CIPHER_fetch(nullptr, "AES-192-GCM", nullptr),
                                 EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr)};
    static EVP_CIPHER* kw[3] = {EVP_CIPHER_fetch(nullptr, "AES-128-WRAP", nullptr),
                                EVP_CIPHER_fetch(nullptr, "AES-192-WRAP", nullptr),
                                EVP_CIPHER_fetch(nullptr, "AES-256-WRAP", nullptr)};
    static const char* names[6] = {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
                                   "AES-128-WRAP", "AES-192-WRAP", "AES-256-WRAP"};
    for (int i = 0; i < 6; ++i)
        if (names[i] == name) return i < 3 ? gcm[i] : kw[i - 3];
    return nullptr;
}

const char* gcm_name(size_t keylen) {
    switch (keylen) {
        case 16: return "AES-128-GCM";
        case 24: return "AES-192-GCM";
        case 32: return "AES-256-GCM";
        default: return nullptr;
    }
}
const char* kw_name(size_t keylen) {
    switch (keylen) {
        case 16: return "AES-128-WRAP";
        case 24: return "AES-192-WRAP";
        case 32: return "AES-256-WRAP";
        default: return nullptr;
    }
}
}  // namespace

bool hmac_sha256(View key, View msg, Mac& out) {
    EVP_MAC* mac = hmac_alg();
    if (!mac) return false;
    std::unique_ptr<EVP_MAC_CTX, MacCtxFree> ctx(EVP_MAC_CTX_new(mac));
    if (!ctx) return false;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                           OSSL_PARAM_construct_end()};
    size_t len = 0;
    return EVP_MAC_init(ctx.get(), nz(key), key.size(), params) == 1 &&
           EVP_MAC_update(ctx.get(), nz(msg), msg.size()) == 1 &&
           EVP_MAC_final(ctx.get(), out.data(), &len, out.size()) == 1 && len == out.size();
}

bool sha256(View msg, std::array<uint8_t, 32>& out) {
    unsigned int len = 0;
    return EVP_Digest(nz(msg), msg.size(), out.data(), &len, EVP_sha256(), nullptr) == 1 && len == 32;
}

bool gcm_seal(View key, View nonce, View aad, View pt, Bytes& out) {
    const char* name = gcm_name(key.size());
    if (!name || nonce.empty()) return false;
    EVP_CIPHER* cipher = cipher_alg(name);
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx) return false;
    out.assign(pt.size() + kTagLen, 0);
    int len = 0;
    size_t ivlen = nonce.size();
    OSSL_PARAM ivp[] = {OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen),
                        OSSL_PARAM_construct_end()};
    if (EVP_EncryptInit_ex2(ctx.get(), cipher, nullptr, nullptr, ivp) != 1 ||
        EVP_EncryptInit_ex2(ctx.get(), nullptr, key.data(), nonce.data(), nullptr) != 1)
        return false;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1)
        return false;
    int ctlen = 0;
    if (!pt.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, pt.data(), (int)pt.size()) != 1) return false;
        ctlen = len;
    }
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + ctlen, &len) != 1) return false;
    ctlen += len;
    if ((size_t)ctlen != pt.size()) return false;
    return EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, (int)kTagLen, out.data() + ctlen) == 1;
}

bool gcm_open(View key, View nonce, View aad, View in, Bytes& pt) {
    const char* name = gcm_name(key.size());
    if (!name || nonce.empty() || in.size() < kTagLen) return false;
    EVP_CIPHER* cipher = cipher_alg(name);
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx) return false;
    const size_t ctlen = in.size() - kTagLen;
    Bytes tmp(ctlen);
    int len = 0;
    size_t ivlen = nonce.size();
    OSSL_PARAM ivp[] = {OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen),
                        OSSL_PARAM_construct_end()};
    if (EVP_DecryptInit_ex2(ctx.get(), cipher, nullptr, nullptr, ivp) != 1 ||
        EVP_DecryptInit_ex2(ctx.get(), nullptr, key.data(), nonce.data(), nullptr) != 1)
        return false;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1)
        return false;
    int got = 0;
    if (ctlen) {
        if (EVP_DecryptUpdate(ctx.get(), tmp.data(), &len, in.data(), (int)ctlen) != 1) return false;
        got = len;
    }
    // The tag buffer is const in our API; OpenSSL takes void*, it does not write.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, (int)kTagLen,
                            const_cast<uint8_t*>(in.data() + ctlen)) != 1)
        return false;
    if (EVP_DecryptFinal_ex(ctx.get(), tmp.data() + got, &len) != 1) {
        OPENSSL_cleanse(tmp.data(), tmp.size());  // unauthenticated plaintext
        return false;
    }
    pt = std::move(tmp);
    return true;
}

bool hkdf_sha256(View ikm, View salt, View info, std::span<uint8_t> okm) {
    EVP_KDF* kdf = hkdf_alg();
    if (!kdf) return false;
    std::unique_ptr<EVP_KDF_CTX, KdfCtxFree> ctx(EVP_KDF_CTX_new(kdf));
    if (!ctx) return false;
    char digest[] = "SHA256";
    // OSSL_PARAM takes void* for octet strings; these buffers are only read.
    auto oct = [](const char* k, View v) {
        return OSSL_PARAM_construct_octet_string(k, const_cast<unsigned char*>(nz(v)), v.size());
    };
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
                           oct(OSSL_KDF_PARAM_KEY, ikm), oct(OSSL_KDF_PARAM_SALT, salt),
                           oct(OSSL_KDF_PARAM_INFO, info), OSSL_PARAM_construct_end()};
    return EVP_KDF_derive(ctx.get(), okm.data(), okm.size(), params) == 1;
}

bool aes_kw_wrap(View kek, View key, Bytes& out) {
    const char* name = kw_name(kek.size());
    if (!name || key.size() < 16 || key.size() % 8) return false;
    EVP_CIPHER* cipher = cipher_alg(name);
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx) return false;
    out.assign(key.size() + 8, 0);
    int len = 0, fin = 0;
    if (EVP_EncryptInit_ex2(ctx.get(), cipher, kek.data(), nullptr, nullptr) != 1 ||
        EVP_EncryptUpdate(ctx.get(), out.data(), &len, key.data(), (int)key.size()) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &fin) != 1)
        return false;
    return (size_t)(len + fin) == out.size();
}

bool aes_kw_unwrap(View kek, View blob, Secret& out) {
    const char* name = kw_name(kek.size());
    if (!name || blob.size() < 24 || blob.size() % 8) return false;
    EVP_CIPHER* cipher = cipher_alg(name);
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx) return false;
    Secret tmp(blob.size());  // KW output is 8 bytes shorter; spare room is harmless
    int len = 0, fin = 0;
    if (EVP_DecryptInit_ex2(ctx.get(), cipher, kek.data(), nullptr, nullptr) != 1 ||
        EVP_DecryptUpdate(ctx.get(), tmp.data(), &len, blob.data(), (int)blob.size()) <= 0 ||
        EVP_DecryptFinal_ex(ctx.get(), tmp.data() + len, &fin) != 1)
        return false;
    if ((size_t)(len + fin) != blob.size() - 8) return false;
    out = Secret(View(tmp.data(), blob.size() - 8));
    return true;
}

bool random_bytes(std::span<uint8_t> out) { return RAND_bytes(out.data(), (int)out.size()) == 1; }

bool ct_equal(View a, View b) {
    return a.size() == b.size() && CRYPTO_memcmp(nz(a), nz(b), a.size()) == 0;
}
}  // namespace prim

// ---- key IDs ----------------------------------------------------------------

bool is_reserved_nonce(View nonce) {
    return nonce.size() == kNonceLen && std::memcmp(nonce.data(), kKcvNonce.data(), kNonceLen) == 0;
}

static View label_view() {
    return {reinterpret_cast<const uint8_t*>(kKcvLabel.data()), kKcvLabel.size()};
}

bool kcv_software(KeyType t, View key, Bytes& kcv) {
    if (t == KeyType::HmacSha256) {
        Mac m;
        if (!prim::hmac_sha256(key, label_view(), m)) return false;
        kcv.assign(m.begin(), m.end());
        return true;
    }
    // AES: GCM tag over (aad = label, pt = empty) under the reserved nonce.
    // Not the classic KCV E_K(0^128): that value is GCM's hash subkey H.
    return prim::gcm_seal(key, kKcvNonce, label_view(), {}, kcv) && kcv.size() == kTagLen;
}

KeyId key_id_from_kcv(KeyType t, View kcv) {
    static constexpr std::string_view dom = "ccb-key-id-v1";
    Bytes buf(dom.begin(), dom.end());
    buf.push_back(static_cast<uint8_t>(t));
    buf.insert(buf.end(), kcv.begin(), kcv.end());
    KeyId id{};
    prim::sha256(buf, id);
    return id;
}

}  // namespace ccb
