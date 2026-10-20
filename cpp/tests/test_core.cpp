// C++ core tests: one suite run against the software store and, when
// CCB_P11_MODULE is set, against the PKCS#11 store (SoftHSM2).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ccb/core.hpp"

using namespace ccb;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (cond) ++g_pass;                                                      \
        else {                                                                   \
            ++g_fail;                                                            \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)
#define CHECK_ST(expr, want) CHECK((expr) == Status::want)

static Bytes bytes(const char* s) { return Bytes(s, s + std::strlen(s)); }
static Bytes filled(size_t n, uint8_t v) { return Bytes(n, v); }

static void suite(KeyStore& ks, bool p11) {
    const Bytes k1 = filled(32, 0x11), k2 = filled(32, 0x22);
    const uint32_t A = (uint32_t)KeyType::Aes256, H = (uint32_t)KeyType::HmacSha256;
    KeyId aes{}, aes_again{}, mac{}, tmp{};

    // import: validation, determinism, idempotence
    CHECK_ST(ks.import_key(3, k1, 0, tmp), BadArg);
    CHECK_ST(ks.import_key(A, k1, 2, tmp), BadArg);
    CHECK_ST(ks.import_key(A, filled(31, 1), 0, tmp), BadArg);
    CHECK_ST(ks.import_key(A, k1, 0, aes), Ok);
    CHECK_ST(ks.import_key(A, k1, 0, aes_again), Ok);
    CHECK(aes == aes_again);
    CHECK_ST(ks.import_key(H, k1, 0, mac), Ok);
    CHECK(mac != aes);  // same bytes, different type, different ID

    // HMAC
    Mac tag{}, tag2{};
    const Bytes msg = bytes("attack at dawn");
    CHECK_ST(ks.hmac_sign(mac, msg, tag), Ok);
    CHECK_ST(ks.hmac_sign(mac, msg, tag2), Ok);
    CHECK(tag == tag2);
    Mac ref{};
    CHECK(prim::hmac_sha256(k1, msg, ref) && ref == tag);
    CHECK_ST(ks.hmac_verify(mac, msg, tag), Ok);
    tag[0] ^= 1;
    CHECK_ST(ks.hmac_verify(mac, msg, tag), VerifyFailed);
    CHECK_ST(ks.hmac_verify(mac, msg, View(tag).first(31)), BadArg);
    CHECK_ST(ks.hmac_sign(aes, msg, tag), WrongKeyType);

    // AEAD
    const uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const Bytes aad = bytes("hdr"), pt = bytes("hello, token");
    Bytes sealed, sealed2, opened;
    CHECK_ST(ks.seal(aes, nonce, aad, pt, sealed), Ok);
    CHECK(sealed.size() == pt.size() + kSealOverhead);
    CHECK_ST(ks.seal(aes, nonce, aad, pt, sealed2), Ok);
    CHECK(sealed == sealed2);  // fixed nonce => deterministic
    Bytes ref_ct;
    CHECK(prim::gcm_seal(k1, View(nonce, 12), aad, pt, ref_ct));
    CHECK(Bytes(sealed.begin() + 12, sealed.end()) == ref_ct);
    CHECK_ST(ks.open(aes, aad, sealed, opened), Ok);
    CHECK(opened == pt);
    CHECK_ST(ks.seal(aes, nullptr, aad, pt, sealed2), Ok);
    CHECK(sealed2 != sealed);  // random nonce
    CHECK_ST(ks.open(aes, aad, sealed2, opened), Ok);
    CHECK(opened == pt);
    sealed[20] ^= 0x80;
    CHECK_ST(ks.open(aes, aad, sealed, opened), VerifyFailed);
    CHECK_ST(ks.open(aes, aad, View(sealed).first(27), opened), VerifyFailed);
    CHECK_ST(ks.seal(aes, kKcvNonce.data(), aad, pt, sealed), BadArg);
    CHECK_ST(ks.seal(mac, nonce, aad, pt, sealed), WrongKeyType);
    CHECK_ST(ks.seal(aes, nonce, {}, {}, sealed), Ok);  // empty pt and aad
    CHECK_ST(ks.open(aes, {}, sealed, opened), Ok);
    CHECK(opened.empty());

    // The KCV itself, presented as a ciphertext, must not open.
    Bytes kcv;
    CHECK(kcv_software(KeyType::Aes256, k1, kcv));
    Bytes forged(kKcvNonce.begin(), kKcvNonce.end());
    forged.insert(forged.end(), kcv.begin(), kcv.end());
    CHECK_ST(ks.open(aes, View(reinterpret_cast<const uint8_t*>(kKcvLabel.data()), kKcvLabel.size()), forged,
                     opened),
             VerifyFailed);

    // wrap / unwrap
    KeyId kek{}, exp{}, unwrapped{};
    Bytes blob;
    CHECK_ST(ks.import_key(A, k2, 0, kek), Ok);
    CHECK_ST(ks.wrap(kek, aes, blob), NotExtractable);
    CHECK_ST(ks.import_key(H, filled(32, 0x33), kFlagExportable, exp), Ok);
    CHECK_ST(ks.wrap(mac, exp, blob), WrongKeyType);
    CHECK_ST(ks.wrap(kek, exp, blob), Ok);
    CHECK(blob.size() == kWrapLen);
    Bytes ref_blob;
    CHECK(prim::aes_kw_wrap(k2, filled(32, 0x33), ref_blob) && ref_blob == blob);
    CHECK_ST(ks.destroy(exp), Ok);
    CHECK_ST(ks.hmac_sign(exp, msg, tag), NoSuchKey);
    CHECK_ST(ks.unwrap(kek, H, blob, 0, unwrapped), Ok);
    CHECK(unwrapped == exp);  // same key => same ID, whichever path created it
    CHECK_ST(ks.unwrap(kek, H, View(blob).first(39), 0, tmp), BadArg);
    blob[5] ^= 1;
    CHECK_ST(ks.unwrap(kek, H, blob, 0, tmp), VerifyFailed);

    // HKDF
    KeyId derived{};
    if (p11) {
        CHECK_ST(ks.hkdf_derive(mac, bytes("salt"), bytes("info"), A, 0, derived), Unsupported);
    } else {
        CHECK_ST(ks.hkdf_derive(mac, bytes("salt"), bytes("info"), A, 0, derived), Ok);
        CHECK_ST(ks.hkdf_derive(aes, bytes("salt"), bytes("info"), A, 0, derived), WrongKeyType);
        uint8_t okm[32];
        Bytes okm_kcv;
        CHECK(prim::hkdf_sha256(k1, bytes("salt"), bytes("info"), okm));
        CHECK(kcv_software(KeyType::Aes256, View(okm, 32), okm_kcv));
        CHECK(derived == key_id_from_kcv(KeyType::Aes256, okm_kcv));
    }

    // generate
    KeyId g1{}, g2{};
    CHECK_ST(ks.generate(A, 0, g1), Ok);
    CHECK_ST(ks.generate(A, 0, g2), Ok);
    CHECK(g1 != g2);
    CHECK_ST(ks.seal(g1, nullptr, {}, pt, sealed), Ok);
    CHECK_ST(ks.open(g1, {}, sealed, opened), Ok);
    CHECK_ST(ks.open(g2, {}, sealed, opened), VerifyFailed);

    for (const KeyId& id : {aes, mac, kek, unwrapped, g1, g2}) CHECK_ST(ks.destroy(id), Ok);
    CHECK_ST(ks.destroy(aes), NoSuchKey);
    if (!p11) CHECK_ST(ks.destroy(derived), Ok);
}

// A key generated inside the token gets its ID from an in-token KCV. Wrap it
// out and unwrap into the software store, which computes the KCV from the raw
// bytes: the IDs must agree.
static void token_vs_software_ids(KeyStore& tok) {
    auto soft = make_software_store();
    const Bytes kek_bytes(32, 0x5a);
    KeyId kek_t{}, kek_s{}, gen{}, back{};
    Bytes blob;
    CHECK_ST(tok.import_key(1, kek_bytes, 0, kek_t), Ok);
    CHECK_ST(soft->import_key(1, kek_bytes, 0, kek_s), Ok);
    CHECK(kek_t == kek_s);
    for (uint32_t t : {1u, 2u}) {
        CHECK_ST(tok.generate(t, kFlagExportable, gen), Ok);
        CHECK_ST(tok.wrap(kek_t, gen, blob), Ok);
        CHECK_ST(soft->unwrap(kek_s, t, blob, 0, back), Ok);
        CHECK(back == gen);
        CHECK_ST(tok.destroy(gen), Ok);
    }
    CHECK_ST(tok.destroy(kek_t), Ok);
}

int main() {
    {
        auto soft = make_software_store();
        suite(*soft, false);
        std::printf("software store: done\n");
    }
    if (const char* mod = std::getenv("CCB_P11_MODULE")) {
        const char* label = std::getenv("CCB_P11_TOKEN");
        const char* pin = std::getenv("CCB_P11_PIN");
        std::string p = pin ? pin : "1234";
        Status st{};
        auto tok = make_pkcs11_store(mod, label ? label : "ccb",
                                     View(reinterpret_cast<const uint8_t*>(p.data()), p.size()), &st);
        CHECK(tok != nullptr);
        if (tok) {
            suite(*tok, true);
            token_vs_software_ids(*tok);
            std::printf("pkcs11 store: done\n");
        } else {
            std::fprintf(stderr, "pkcs11 open failed: %d\n", (int)st);
        }
    } else {
        std::printf("pkcs11 store: skipped (CCB_P11_MODULE unset)\n");
    }
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
