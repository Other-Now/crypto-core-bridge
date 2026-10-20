// Stretch goal: post-quantum primitives through OpenSSL 3.5, cross-checked
// against nanokem (my from-scratch FIPS 203 ML-KEM-768, vendored under
// third_party/nanokem) and against Wycheproof.
//
// ML-KEM-768, both implementations driven deterministically so that every
// output is compared byte for byte:
//   1. Wycheproof keygen-from-seed (d||z): both produce the expected ek;
//      OpenSSL also the expected dk.
//   2. Wycheproof encaps (ek, m): both produce the expected c and K; both
//      reject the ModulusOverflow encapsulation keys.
//   3. 1000 random seeds, cross-implementation: same ek, same (c, K) for the
//      same m, each decapsulates the other's ciphertext, and a tampered
//      ciphertext gives the SAME implicit-rejection key from both (same z).
// ML-DSA-65 (OpenSSL only; nanokem has no ML-DSA):
//   4. Wycheproof verify vectors, including context strings.
//   5. Keygen from seed, deterministic sign, verify, tamper -> reject.
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "nanokem/mlkem768.h"
}

using Bytes = std::vector<uint8_t>;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (cond) ++g_pass;                                    \
        else {                                                 \
            ++g_fail;                                          \
            std::fprintf(stderr, "FAIL %s:%d: %s ", __FILE__, __LINE__, #cond); \
            std::fprintf(stderr, __VA_ARGS__);                 \
            std::fprintf(stderr, "\n");                        \
        }                                                      \
    } while (0)

struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct CtxFree { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using Ctx = std::unique_ptr<EVP_PKEY_CTX, CtxFree>;

static Bytes unhex(const std::string& h) {
    Bytes b(h.size() / 2);
    for (size_t i = 0; i < b.size(); ++i) b[i] = (uint8_t)std::stoul(h.substr(2 * i, 2), nullptr, 16);
    return b;
}

static std::vector<std::map<std::string, std::string>> load(const std::string& path) {
    std::vector<std::map<std::string, std::string>> out;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::map<std::string, std::string> m;
        std::istringstream ss(line);
        std::string kv;
        while (ss >> kv) {
            auto eq = kv.find('=');
            m[kv.substr(0, eq)] = kv.substr(eq + 1);
        }
        out.push_back(std::move(m));
    }
    if (out.empty()) std::fprintf(stderr, "no vectors in %s\n", path.c_str());
    return out;
}

// ---- OpenSSL ML-KEM-768 ---------------------------------------------------------

static Pkey ossl_mlkem_from_seed(const uint8_t seed[64]) {
    Ctx c(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr));
    EVP_PKEY* p = nullptr;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, const_cast<uint8_t*>(seed), 64),
        OSSL_PARAM_construct_end()};
    if (!c || EVP_PKEY_keygen_init(c.get()) != 1 || EVP_PKEY_CTX_set_params(c.get(), params) != 1 ||
        EVP_PKEY_generate(c.get(), &p) != 1)
        return nullptr;
    return Pkey(p);
}

static Bytes ossl_octets(EVP_PKEY* p, const char* name) {
    size_t n = 0;
    if (EVP_PKEY_get_octet_string_param(p, name, nullptr, 0, &n) != 1) return {};
    Bytes b(n);
    if (EVP_PKEY_get_octet_string_param(p, name, b.data(), b.size(), &n) != 1) return {};
    return b;
}

static Pkey ossl_public(const char* alg, const Bytes& pub) {
    return Pkey(EVP_PKEY_new_raw_public_key_ex(nullptr, alg, nullptr, pub.data(), pub.size()));
}

// Deterministic encapsulation: "ikme" supplies the 32-byte m.
static bool ossl_encaps(EVP_PKEY* p, const uint8_t m[32], Bytes& ct, Bytes& ss) {
    Ctx c(EVP_PKEY_CTX_new_from_pkey(nullptr, p, nullptr));
    OSSL_PARAM params[] = {OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, const_cast<uint8_t*>(m), 32),
                           OSSL_PARAM_construct_end()};
    size_t ctlen = 0, sslen = 0;
    if (!c || EVP_PKEY_encapsulate_init(c.get(), params) != 1 ||
        EVP_PKEY_encapsulate(c.get(), nullptr, &ctlen, nullptr, &sslen) != 1)
        return false;
    ct.resize(ctlen);
    ss.resize(sslen);
    return EVP_PKEY_encapsulate(c.get(), ct.data(), &ctlen, ss.data(), &sslen) == 1;
}

static bool ossl_decaps(EVP_PKEY* p, const Bytes& ct, Bytes& ss) {
    Ctx c(EVP_PKEY_CTX_new_from_pkey(nullptr, p, nullptr));
    size_t sslen = 32;
    ss.resize(32);
    return c && EVP_PKEY_decapsulate_init(c.get(), nullptr) == 1 &&
           EVP_PKEY_decapsulate(c.get(), ss.data(), &sslen, ct.data(), ct.size()) == 1 && sslen == 32;
}

// ---- nanokem ----------------------------------------------------------------------

struct Nk {
    std::unique_ptr<nk_mlkem768_dk> dk = std::make_unique<nk_mlkem768_dk>();
    Bytes ek = Bytes(NK_MLKEM768_EK_LEN);
    explicit Nk(const uint8_t seed[64]) {
        nk_mlkem768_keygen(seed, seed + 32, dk.get());
        nk_mlkem768_ek_encode(&dk->ek, ek.data());
    }
};

static bool nk_encaps_bytes(const Bytes& ek, const uint8_t m[32], Bytes& ct, Bytes& ss) {
    auto parsed = std::make_unique<nk_mlkem768_ek>();
    if (ek.size() != NK_MLKEM768_EK_LEN || nk_mlkem768_ek_parse(ek.data(), parsed.get()) != NK_OK) return false;
    ct.resize(NK_MLKEM768_CT_LEN);
    ss.resize(NK_MLKEM768_SS_LEN);
    nk_mlkem768_encaps(parsed.get(), m, ct.data(), ss.data());
    return true;
}

// ---- tests ------------------------------------------------------------------------

static void mlkem_wycheproof(const std::string& dir) {
    int n = 0, nk_ok = 0, os_ek = 0, os_dk = 0;
    for (auto& t : load(dir + "/mlkem_768_keygen_seed_test.txt")) {
        Bytes seed = unhex(t["seed"]), ek = unhex(t["ek"]), dk = unhex(t["dk"]);
        Nk nk(seed.data());
        Pkey p = ossl_mlkem_from_seed(seed.data());
        ++n;
        nk_ok += nk.ek == ek;
        os_ek += p && ossl_octets(p.get(), OSSL_PKEY_PARAM_PUB_KEY) == ek;
        os_dk += p && ossl_octets(p.get(), OSSL_PKEY_PARAM_PRIV_KEY) == dk;
    }
    CHECK(nk_ok == n, "nanokem keygen: %d/%d", nk_ok, n);
    CHECK(os_ek == n && os_dk == n, "openssl keygen: ek %d/%d dk %d/%d", os_ek, n, os_dk, n);
    std::printf("ML-KEM-768 keygen from seed (Wycheproof, %d): nanokem ek %d/%d | OpenSSL ek %d/%d, dk %d/%d\n", n,
                nk_ok, n, os_ek, n, os_dk, n);

    int valid = 0, invalid = 0, nk_v = 0, os_v = 0, nk_r = 0, os_r = 0;
    for (auto& t : load(dir + "/mlkem_768_encaps_test.txt")) {
        Bytes m = unhex(t["m"]), ek = unhex(t["ek"]), c = unhex(t["c"]), K = unhex(t["K"]);
        Bytes nct, nss, oct, oss;
        bool nk_done = nk_encaps_bytes(ek, m.data(), nct, nss);
        Pkey p = ossl_public("ML-KEM-768", ek);
        bool os_done = p && ossl_encaps(p.get(), m.data(), oct, oss);
        if (t["result"] == "valid") {
            ++valid;
            nk_v += nk_done && nct == c && nss == K;
            os_v += os_done && oct == c && oss == K;
        } else {
            ++invalid;
            nk_r += !nk_done;
            os_r += !os_done;
        }
    }
    ERR_clear_error();
    CHECK(nk_v == valid && os_v == valid, "encaps valid: nanokem %d openssl %d of %d", nk_v, os_v, valid);
    CHECK(nk_r == invalid && os_r == invalid, "encaps invalid: nanokem %d openssl %d of %d", nk_r, os_r, invalid);
    std::printf(
        "ML-KEM-768 encaps (Wycheproof): valid (c,K) byte-exact nanokem %d/%d, OpenSSL %d/%d | invalid ek rejected "
        "nanokem %d/%d, OpenSSL %d/%d\n",
        nk_v, valid, os_v, valid, nk_r, invalid, os_r, invalid);
}

static void mlkem_cross(int rounds) {
    int same_ek = 0, same_enc = 0, cross_ok = 0, same_reject = 0;
    for (int i = 0; i < rounds; ++i) {
        uint8_t seed[64], m[32];
        RAND_bytes(seed, 64);
        RAND_bytes(m, 32);
        Nk nk(seed);
        Pkey p = ossl_mlkem_from_seed(seed);
        Bytes oek = p ? ossl_octets(p.get(), OSSL_PKEY_PARAM_PUB_KEY) : Bytes{};
        same_ek += oek == nk.ek;

        Bytes nct, nss, oct, oss;
        nk_encaps_bytes(nk.ek, m, nct, nss);
        if (p) ossl_encaps(p.get(), m, oct, oss);
        same_enc += nct == oct && nss == oss;

        // Each side decapsulates a ciphertext made by the other.
        Bytes ss1, ss2(32);
        bool a = p && ossl_decaps(p.get(), nct, ss1) && ss1 == nss;
        nk_mlkem768_decaps(nk.dk.get(), oct.data(), ss2.data());
        cross_ok += a && ss2 == oss;

        // Implicit rejection: a tampered ciphertext must not error, must not
        // give the real key, and (same z) must give the same key on both.
        Bytes bad = nct;
        bad[i % bad.size()] ^= 1;
        Bytes r1, r2(32);
        bool d = p && ossl_decaps(p.get(), bad, r1);
        nk_mlkem768_decaps(nk.dk.get(), bad.data(), r2.data());
        same_reject += d && r1 == r2 && r1 != nss;
    }
    CHECK(same_ek == rounds, "ek mismatches: %d", rounds - same_ek);
    CHECK(same_enc == rounds, "encaps mismatches: %d", rounds - same_enc);
    CHECK(cross_ok == rounds, "cross-decaps failures: %d", rounds - cross_ok);
    CHECK(same_reject == rounds, "implicit-rejection mismatches: %d", rounds - same_reject);
    std::printf(
        "ML-KEM-768 cross-implementation, %d random seeds: ek %d/%d, (ct,ss) %d/%d, cross-decaps %d/%d, "
        "implicit rejection %d/%d\n",
        rounds, same_ek, rounds, same_enc, rounds, cross_ok, rounds, same_reject, rounds);
}

static void mldsa_wycheproof(const std::string& dir) {
    int valid = 0, invalid = 0, agree = 0, total = 0;
    for (auto& t : load(dir + "/mldsa_65_verify_test.txt")) {
        ++total;
        Bytes pk = unhex(t["publicKey"]), msg = unhex(t["msg"]), sig = unhex(t["sig"]), ctx = unhex(t["ctx"]);
        bool ok = false;
        Pkey p = ossl_public("ML-DSA-65", pk);
        if (p) {
            Ctx c(EVP_PKEY_CTX_new_from_pkey(nullptr, p.get(), nullptr));
            EVP_SIGNATURE* alg = EVP_SIGNATURE_fetch(nullptr, "ML-DSA-65", nullptr);
            OSSL_PARAM params[2] = {OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()};
            if (t["has_ctx"] == "1")
                params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                              ctx.empty() ? (void*)"" : ctx.data(), ctx.size());
            ok = c && alg && EVP_PKEY_verify_message_init(c.get(), alg, params) == 1 &&
                 EVP_PKEY_verify(c.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
            EVP_SIGNATURE_free(alg);
        }
        bool want = t["result"] == "valid";
        (want ? valid : invalid) += 1;
        agree += ok == want;
        CHECK(ok == want, "ML-DSA-65 verify tc %s: got %d want %d", t["tc"].c_str(), ok, want);
    }
    ERR_clear_error();
    std::printf("ML-DSA-65 verify (Wycheproof): %d/%d as expected (%d valid, %d invalid)\n", agree, total, valid,
                invalid);
}

static void mldsa_roundtrip() {
    uint8_t seed[32];
    RAND_bytes(seed, 32);
    Ctx kc(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr));
    EVP_PKEY* raw = nullptr;
    OSSL_PARAM kp[] = {OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, seed, 32),
                       OSSL_PARAM_construct_end()};
    CHECK(kc && EVP_PKEY_keygen_init(kc.get()) == 1 && EVP_PKEY_CTX_set_params(kc.get(), kp) == 1 &&
              EVP_PKEY_generate(kc.get(), &raw) == 1,
          "ML-DSA keygen");
    Pkey key(raw);
    const char msg[] = "crypto-core-bridge";
    auto sign = [&](Bytes& sig) {
        Ctx c(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
        EVP_SIGNATURE* alg = EVP_SIGNATURE_fetch(nullptr, "ML-DSA-65", nullptr);
        int det = 1;
        OSSL_PARAM sp[] = {OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det),
                           OSSL_PARAM_construct_end()};
        size_t n = 0;
        bool ok = EVP_PKEY_sign_message_init(c.get(), alg, sp) == 1 &&
                  EVP_PKEY_sign(c.get(), nullptr, &n, (const uint8_t*)msg, sizeof msg) == 1;
        sig.resize(n);
        ok = ok && EVP_PKEY_sign(c.get(), sig.data(), &n, (const uint8_t*)msg, sizeof msg) == 1;
        sig.resize(n);
        EVP_SIGNATURE_free(alg);
        return ok;
    };
    auto verify = [&](const Bytes& sig) {
        Ctx c(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
        EVP_SIGNATURE* alg = EVP_SIGNATURE_fetch(nullptr, "ML-DSA-65", nullptr);
        bool ok = EVP_PKEY_verify_message_init(c.get(), alg, nullptr) == 1 &&
                  EVP_PKEY_verify(c.get(), sig.data(), sig.size(), (const uint8_t*)msg, sizeof msg) == 1;
        EVP_SIGNATURE_free(alg);
        return ok;
    };
    Bytes s1, s2;
    CHECK(sign(s1) && sign(s2), "sign");
    CHECK(s1 == s2 && s1.size() == 3309, "deterministic signature, %zu bytes", s1.size());
    CHECK(verify(s1), "verify");
    s1[100] ^= 1;
    CHECK(!verify(s1), "tampered signature verified");
    ERR_clear_error();
    std::printf("ML-DSA-65 seed keygen + deterministic sign/verify/tamper: ok (signature %zu bytes)\n", s2.size());
}

int main(int argc, char** argv) {
    std::string dir = argc > 1 ? argv[1] : "pq-vectors";
    std::printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
    mlkem_wycheproof(dir);
    mlkem_cross(argc > 2 ? std::atoi(argv[2]) : 1000);
    mldsa_wycheproof(dir);
    mldsa_roundtrip();
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
