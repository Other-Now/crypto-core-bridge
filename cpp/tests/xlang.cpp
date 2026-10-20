// Cross-language tests, C++ side: the C++ core and the Rust implementation
// (through include/ccb.h, the cbindgen header) in one process.
//
//  * the two status enums are the same contract (checked at compile time)
//  * Rust seals -> C++ opens, and the reverse; same for HMAC, AES-KW, HKDF
//  * one SoftHSM token shared by both: only the key ID crosses
//  * a Rust panic comes back as CCB_ERR_PANIC instead of unwinding into C++
//  * ABI edge cases: NULLs, short buffers, one context shared by 8 threads
#define CCB_TEST_HOOKS 1
#include "ccb.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "ccb/core.hpp"

using namespace ccb;

#define SAME(name, code) static_assert(static_cast<int32_t>(Status::name) == (code), #name)
SAME(Ok, CCB_OK);
SAME(NullArg, CCB_ERR_NULL_ARG);
SAME(BadArg, CCB_ERR_BAD_ARG);
SAME(BufferTooSmall, CCB_ERR_BUFFER_TOO_SMALL);
SAME(NoSuchKey, CCB_ERR_NO_SUCH_KEY);
SAME(WrongKeyType, CCB_ERR_WRONG_KEY_TYPE);
SAME(VerifyFailed, CCB_ERR_VERIFY_FAILED);
SAME(NotExtractable, CCB_ERR_NOT_EXTRACTABLE);
SAME(Unsupported, CCB_ERR_UNSUPPORTED);
SAME(Backend, CCB_ERR_BACKEND);
SAME(Panic, CCB_ERR_PANIC);
SAME(Internal, CCB_ERR_INTERNAL);
static_assert(sizeof(ccb_key_id) == sizeof(KeyId) && CCB_KEY_ID_LEN == 32);
static_assert(CCB_SEAL_OVERHEAD == kSealOverhead && CCB_WRAP_LEN == kWrapLen && CCB_MAC_LEN == kMacLen);
static_assert(CCB_KEY_AES256 == (uint32_t)KeyType::Aes256 && CCB_KEY_HMAC_SHA256 == (uint32_t)KeyType::HmacSha256);

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (cond) ++g_pass;                                                      \
        else {                                                                   \
            ++g_fail;                                                            \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)

static ccb_key_id to_c(const KeyId& id) {
    ccb_key_id k;
    std::memcpy(k.bytes, id.data(), 32);
    return k;
}
static KeyId from_c(const ccb_key_id& k) {
    KeyId id;
    std::memcpy(id.data(), k.bytes, 32);
    return id;
}

// Runs the round trips between a C++ store and a Rust context that hold the
// same keys.
static void round_trips(KeyStore& cpp, ccb_ctx* rs, bool hkdf) {
    static const uint8_t k_aes[32] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    static const uint8_t k_mac[32] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4,
                                      3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8};
    KeyId ca{}, cm{};
    ccb_key_id ra{}, rm{};
    CHECK(cpp.import_key(1, View(k_aes, 32), CCB_FLAG_EXPORTABLE, ca) == Status::Ok);
    CHECK(cpp.import_key(2, View(k_mac, 32), CCB_FLAG_EXPORTABLE, cm) == Status::Ok);
    CHECK(ccb_key_import(rs, CCB_KEY_AES256, k_aes, 32, CCB_FLAG_EXPORTABLE, &ra) == CCB_OK);
    CHECK(ccb_key_import(rs, CCB_KEY_HMAC_SHA256, k_mac, 32, CCB_FLAG_EXPORTABLE, &rm) == CCB_OK);
    CHECK(from_c(ra) == ca && from_c(rm) == cm);  // identical key IDs

    const std::string pt = "cross-language payload", aad = "v1";
    auto P = reinterpret_cast<const uint8_t*>(pt.data());
    auto A = reinterpret_cast<const uint8_t*>(aad.data());
    const uint8_t nonce[12] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5};

    // fixed nonce: byte-identical ciphertexts
    Bytes c_sealed;
    std::vector<uint8_t> r_sealed(pt.size() + CCB_SEAL_OVERHEAD);
    size_t n = 0;
    CHECK(cpp.seal(ca, nonce, View(A, aad.size()), View(P, pt.size()), c_sealed) == Status::Ok);
    CHECK(ccb_aead_seal(rs, &ra, nonce, A, aad.size(), P, pt.size(), r_sealed.data(), r_sealed.size(), &n) ==
          CCB_OK);
    CHECK(n == c_sealed.size() && std::memcmp(r_sealed.data(), c_sealed.data(), n) == 0);

    // Rust seals (random nonce) -> C++ opens
    CHECK(ccb_aead_seal(rs, &ra, nullptr, A, aad.size(), P, pt.size(), r_sealed.data(), r_sealed.size(), &n) ==
          CCB_OK);
    Bytes opened;
    CHECK(cpp.open(ca, View(A, aad.size()), View(r_sealed.data(), n), opened) == Status::Ok);
    CHECK(std::string(opened.begin(), opened.end()) == pt);

    // C++ seals (random nonce) -> Rust opens
    CHECK(cpp.seal(ca, nullptr, View(A, aad.size()), View(P, pt.size()), c_sealed) == Status::Ok);
    std::vector<uint8_t> r_opened(pt.size());
    CHECK(ccb_aead_open(rs, &ra, A, aad.size(), c_sealed.data(), c_sealed.size(), r_opened.data(), r_opened.size(),
                        &n) == CCB_OK);
    CHECK(n == pt.size() && std::memcmp(r_opened.data(), P, n) == 0);
    c_sealed.back() ^= 1;
    CHECK(ccb_aead_open(rs, &ra, A, aad.size(), c_sealed.data(), c_sealed.size(), r_opened.data(), r_opened.size(),
                        &n) == CCB_ERR_VERIFY_FAILED);

    // HMAC both ways
    Mac ct{};
    uint8_t rt[32];
    CHECK(cpp.hmac_sign(cm, View(P, pt.size()), ct) == Status::Ok);
    CHECK(ccb_hmac_sign(rs, &rm, P, pt.size(), rt) == CCB_OK);
    CHECK(std::memcmp(ct.data(), rt, 32) == 0);
    CHECK(ccb_hmac_verify(rs, &rm, P, pt.size(), ct.data(), 32) == CCB_OK);
    CHECK(cpp.hmac_verify(cm, View(P, pt.size()), View(rt, 32)) == Status::Ok);

    // wrap in one language, unwrap in the other
    KeyId c_kek{}, back{};
    ccb_key_id r_kek{}, r_back{};
    static const uint8_t k_kek[32] = {1};
    CHECK(cpp.import_key(1, View(k_kek, 32), 0, c_kek) == Status::Ok);
    CHECK(ccb_key_import(rs, 1, k_kek, 32, 0, &r_kek) == CCB_OK);
    Bytes c_blob;
    uint8_t r_blob[40];
    CHECK(cpp.wrap(c_kek, cm, c_blob) == Status::Ok);
    CHECK(ccb_key_wrap(rs, &r_kek, &rm, r_blob, sizeof r_blob, &n) == CCB_OK);
    CHECK(n == 40 && std::memcmp(r_blob, c_blob.data(), 40) == 0);  // AES-KW is deterministic
    CHECK(ccb_key_unwrap(rs, &r_kek, 2, c_blob.data(), c_blob.size(), 0, &r_back) == CCB_OK);
    CHECK(from_c(r_back) == cm);
    CHECK(cpp.unwrap(c_kek, 2, View(r_blob, 40), 0, back) == Status::Ok);
    CHECK(back == cm);

    // HKDF-derived keys get the same ID
    if (hkdf) {
        KeyId cd{};
        ccb_key_id rd{};
        const uint8_t salt[] = {1, 2, 3}, info[] = {4, 5};
        CHECK(cpp.hkdf_derive(cm, View(salt, 3), View(info, 2), 1, 0, cd) == Status::Ok);
        CHECK(ccb_hkdf_derive(rs, &rm, salt, 3, info, 2, 1, 0, &rd) == CCB_OK);
        CHECK(from_c(rd) == cd);
    }
    for (const KeyId& id : {ca, cm, c_kek}) {
        cpp.destroy(id);
        ccb_key_id k = to_c(id);
        ccb_key_destroy(rs, &k);
    }
}

static void abi_edges(ccb_ctx* rs) {
    ccb_key_id id{}, aes{};
    uint8_t buf[64];
    size_t n = 0;
    const uint8_t key[32] = {3};
    CHECK(ccb_key_generate(nullptr, 1, 0, &id) == CCB_ERR_NULL_ARG);
    CHECK(ccb_key_generate(rs, 1, 0, nullptr) == CCB_ERR_NULL_ARG);
    CHECK(ccb_key_import(rs, 1, nullptr, 32, 0, &id) == CCB_ERR_NULL_ARG);
    CHECK(ccb_key_import(rs, 1, nullptr, 0, 0, &id) == CCB_ERR_BAD_ARG);  // empty key: NULL ok, length wrong
    CHECK(ccb_key_import(rs, 1, key, 32, 0, &aes) == CCB_OK);
    // short output buffer: nothing written, *out_len = size needed
    std::memset(buf, 0xee, sizeof buf);
    CHECK(ccb_aead_seal(rs, &aes, nullptr, nullptr, 0, key, 32, buf, 59, &n) == CCB_ERR_BUFFER_TOO_SMALL);
    CHECK(n == 60 && buf[0] == 0xee);
    CHECK(ccb_aead_seal(rs, &aes, nullptr, nullptr, 0, key, 32, buf, 60, &n) == CCB_OK && n == 60);
    CHECK(ccb_aead_open(rs, &aes, nullptr, 0, buf, 60, nullptr, 0, &n) == CCB_ERR_BUFFER_TOO_SMALL && n == 32);
    CHECK(ccb_aead_open(rs, &aes, nullptr, 0, buf, 10, nullptr, 0, &n) == CCB_ERR_VERIFY_FAILED);
    CHECK(ccb_key_wrap(rs, &aes, &aes, buf, 8, &n) == CCB_ERR_BUFFER_TOO_SMALL && n == 40);
    CHECK(ccb_hmac_verify(rs, &aes, nullptr, 0, buf, 31) == CCB_ERR_BAD_ARG);
    CHECK(ccb_key_destroy(rs, nullptr) == CCB_ERR_NULL_ARG);
    CHECK(std::strcmp(ccb_status_str(CCB_ERR_PANIC), "panic caught at FFI boundary") == 0);
    CHECK(std::strcmp(ccb_status_str(12345), "unknown status") == 0);
    CHECK(ccb_abi_version() == CCB_ABI_VERSION);
    ccb_ctx_free(nullptr);  // no-op
    CHECK(ccb_key_destroy(rs, &aes) == CCB_OK);

    // A panic inside Rust is caught at the boundary.
    CHECK(ccb_test_panic() == CCB_ERR_PANIC);

    // One context, 8 threads: the context is Sync (internal mutex).
    ccb_key_id shared{};
    CHECK(ccb_key_generate(rs, 1, 0, &shared) == CCB_OK);
    std::vector<std::thread> ts;
    std::vector<int> bad(8, 0);
    for (int t = 0; t < 8; ++t)
        ts.emplace_back([&, t] {
            uint8_t sealed[44], out[16];
            uint8_t msg[16];
            std::memset(msg, t, sizeof msg);
            size_t m = 0;
            for (int i = 0; i < 2000; ++i) {
                if (ccb_aead_seal(rs, &shared, nullptr, nullptr, 0, msg, 16, sealed, 44, &m) != CCB_OK ||
                    ccb_aead_open(rs, &shared, nullptr, 0, sealed, 44, out, 16, &m) != CCB_OK ||
                    std::memcmp(out, msg, 16) != 0)
                    ++bad[t];
            }
        });
    for (auto& t : ts) t.join();
    int total_bad = 0;
    for (int b : bad) total_bad += b;
    CHECK(total_bad == 0);
    ccb_key_destroy(rs, &shared);
}

// Both implementations on one SoftHSM token, in one process. C++ creates a
// non-extractable key inside the token; Rust uses it knowing only its ID.
static void shared_token(const char* mod, const char* label, const std::string& pin) {
    Status st{};
    auto cpp = make_pkcs11_store(mod, label, View(reinterpret_cast<const uint8_t*>(pin.data()), pin.size()), &st);
    ccb_ctx* rs = nullptr;
    int rc = ccb_ctx_new_pkcs11(mod, label, reinterpret_cast<const uint8_t*>(pin.data()), pin.size(), &rs);
    CHECK(cpp && rc == CCB_OK);
    if (!cpp || rc != CCB_OK) {
        std::fprintf(stderr, "token open failed: cpp=%d rust=%d\n", (int)st, rc);
        ccb_ctx_free(rs);
        return;
    }
    round_trips(*cpp, rs, /*hkdf=*/false);

    KeyId secret{};
    CHECK(cpp->generate(1, 0, secret) == Status::Ok);  // never leaves the token
    ccb_key_id rid = to_c(secret);
    const uint8_t msg[] = "sealed by Rust with a key C++ generated in the HSM";
    std::vector<uint8_t> sealed(sizeof msg + CCB_SEAL_OVERHEAD);
    size_t n = 0;
    CHECK(ccb_aead_seal(rs, &rid, nullptr, nullptr, 0, msg, sizeof msg, sealed.data(), sealed.size(), &n) == CCB_OK);
    Bytes opened;
    CHECK(cpp->open(secret, {}, View(sealed.data(), n), opened) == Status::Ok);
    CHECK(opened.size() == sizeof msg && std::memcmp(opened.data(), msg, sizeof msg) == 0);
    uint8_t blob[40];
    CHECK(ccb_key_wrap(rs, &rid, &rid, blob, sizeof blob, &n) == CCB_ERR_NOT_EXTRACTABLE);
    uint8_t salt[1] = {0};
    ccb_key_id d{};
    CHECK(ccb_hkdf_derive(rs, &rid, salt, 1, nullptr, 0, 1, 0, &d) == CCB_ERR_UNSUPPORTED);
    CHECK(cpp->destroy(secret) == Status::Ok);
    CHECK(ccb_aead_seal(rs, &rid, nullptr, nullptr, 0, msg, sizeof msg, sealed.data(), sealed.size(), &n) ==
          CCB_ERR_NO_SUCH_KEY);
    ccb_ctx_free(rs);
}

int main() {
    ccb_ctx* rs = nullptr;
    CHECK(ccb_ctx_new_software(&rs) == CCB_OK);
    auto cpp = make_software_store();
    round_trips(*cpp, rs, /*hkdf=*/true);
    abi_edges(rs);
    ccb_ctx_free(rs);
    std::printf("software: done\n");

    if (const char* mod = std::getenv("CCB_P11_MODULE")) {
        const char* label = std::getenv("CCB_P11_TOKEN");
        const char* pin = std::getenv("CCB_P11_PIN");
        shared_token(mod, label ? label : "ccb", pin ? pin : "1234");
        std::printf("shared token: done\n");
    } else {
        std::printf("shared token: skipped (CCB_P11_MODULE unset)\n");
    }
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
