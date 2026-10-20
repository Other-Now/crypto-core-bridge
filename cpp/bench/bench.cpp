// Per-operation cost, C++ side of the harness (the Rust side is
// crates/ccb-cpp/examples/bench.rs; both print the same CSV format).
//
//   cpp        C++ core called directly
//   rust-cabi  Rust implementation called from C++ through include/ccb.h
//   crossing   ccb_abi_version() through the C ABI vs a noinline C++ call
//   cpp-p11    C++ core, PKCS#11 backend (SoftHSM2), if CCB_P11_MODULE is set
//   rust-cabi-p11  Rust PKCS#11 backend through the C ABI
//
// Method: each case runs REPS repetitions of N calls (N calibrated so a
// repetition takes ~20 ms); prints median / min / max ns per call.
#include "ccb.h"

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "ccb/core.hpp"

using namespace ccb;
using Clock = std::chrono::steady_clock;

static int g_reps = 15;

template <class F>
static void run(const char* impl, const char* op, size_t size, F&& f) {
    // calibrate
    size_t n = 1;
    for (;;) {
        auto t0 = Clock::now();
        for (size_t i = 0; i < n; ++i) f();
        double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        if (ms > 20 || n >= (1u << 26)) break;
        n *= 2;
    }
    std::vector<double> ns;
    for (int r = 0; r < g_reps; ++r) {
        auto t0 = Clock::now();
        for (size_t i = 0; i < n; ++i) f();
        ns.push_back(std::chrono::duration<double, std::nano>(Clock::now() - t0).count() / (double)n);
    }
    std::sort(ns.begin(), ns.end());
    std::printf("%s,%s,%zu,%.1f,%.1f,%.1f\n", impl, op, size, ns[ns.size() / 2], ns.front(), ns.back());
    std::fflush(stdout);
}

__attribute__((noinline)) uint32_t cpp_noinline_version() {
    asm volatile("");
    return 1;
}

static void bench_cpp(KeyStore& ks, const char* impl, const std::vector<size_t>& sizes) {
    const std::vector<uint8_t> k(32, 0x42);
    KeyId aes{}, mac{};
    ks.import_key(1, k, 0, aes);
    ks.import_key(2, k, 0, mac);
    for (size_t sz : sizes) {
        std::vector<uint8_t> msg(sz, 0x61);
        Mac tag{};
        Bytes out, pt;
        run(impl, "hmac_sign", sz, [&] { ks.hmac_sign(mac, msg, tag); });
        run(impl, "seal", sz, [&] { ks.seal(aes, nullptr, {}, msg, out); });
        ks.seal(aes, nullptr, {}, msg, out);
        run(impl, "open", sz, [&] { ks.open(aes, {}, out, pt); });
    }
    if (std::strstr(impl, "p11") == nullptr) {
        KeyId d{};
        const uint8_t salt[4] = {1, 2, 3, 4};
        run(impl, "hkdf_derive", 32, [&] { ks.hkdf_derive(mac, View(salt, 4), {}, 1, 0, d); });
    }
}

static void bench_rust(ccb_ctx* ctx, const char* impl, const std::vector<size_t>& sizes) {
    const std::vector<uint8_t> k(32, 0x42);
    ccb_key_id aes{}, mac{};
    ccb_key_import(ctx, 1, k.data(), 32, 0, &aes);
    ccb_key_import(ctx, 2, k.data(), 32, 0, &mac);
    for (size_t sz : sizes) {
        std::vector<uint8_t> msg(sz, 0x61), out(sz + CCB_SEAL_OVERHEAD), pt(sz);
        uint8_t tag[32];
        size_t n = 0, m = 0;
        run(impl, "hmac_sign", sz, [&] { ccb_hmac_sign(ctx, &mac, msg.data(), sz, tag); });
        run(impl, "seal", sz,
            [&] { ccb_aead_seal(ctx, &aes, nullptr, nullptr, 0, msg.data(), sz, out.data(), out.size(), &n); });
        ccb_aead_seal(ctx, &aes, nullptr, nullptr, 0, msg.data(), sz, out.data(), out.size(), &n);
        run(impl, "open", sz, [&] { ccb_aead_open(ctx, &aes, nullptr, 0, out.data(), n, pt.data(), pt.size(), &m); });
    }
    if (std::strstr(impl, "p11") == nullptr) {
        ccb_key_id d{};
        const uint8_t salt[4] = {1, 2, 3, 4};
        run(impl, "hkdf_derive", 32, [&] { ccb_hkdf_derive(ctx, &mac, salt, 4, nullptr, 0, 1, 0, &d); });
    }
}

int main(int argc, char** argv) {
    if (argc > 1) g_reps = std::atoi(argv[1]);
    std::printf("impl,op,size,median_ns,min_ns,max_ns\n");
    volatile uint32_t sink = 0;
    run("crossing", "noinline_cpp_call", 0, [&] { sink = sink + cpp_noinline_version(); });
    run("crossing", "c_abi_call", 0, [&] { sink = sink + ccb_abi_version(); });

    // Attribution: OpenSSL 3 per-call costs that the Rust side does not pay.
    // The core fetches algorithms once (primitives.cpp); the context
    // allocation is still per call.
    run("attrib", "evp_mac_fetch_free", 0, [] { EVP_MAC_free(EVP_MAC_fetch(nullptr, "HMAC", nullptr)); });
    run("attrib", "evp_cipher_fetch_free", 0,
        [] { EVP_CIPHER_free(EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr)); });
    run("attrib", "evp_cipher_ctx_new_free", 0, [] { EVP_CIPHER_CTX_free(EVP_CIPHER_CTX_new()); });

    const std::vector<size_t> sizes = {64, 1024, 16384};
    {
        auto ks = make_software_store();
        bench_cpp(*ks, "cpp", sizes);
    }
    {
        ccb_ctx* ctx = nullptr;
        ccb_ctx_new_software(&ctx);
        bench_rust(ctx, "rust-cabi", sizes);
        ccb_ctx_free(ctx);
    }
    if (const char* mod = std::getenv("CCB_P11_MODULE")) {
        const char* label = std::getenv("CCB_P11_TOKEN");
        std::string pin = std::getenv("CCB_P11_PIN") ? std::getenv("CCB_P11_PIN") : "1234";
        label = label ? label : "ccb";
        g_reps = std::max(5, g_reps / 3);
        auto ks = make_pkcs11_store(mod, label, View(reinterpret_cast<const uint8_t*>(pin.data()), pin.size()));
        if (ks) bench_cpp(*ks, "cpp-p11", {64, 1024});
        ccb_ctx* ctx = nullptr;
        if (ccb_ctx_new_pkcs11(mod, label, reinterpret_cast<const uint8_t*>(pin.data()), pin.size(), &ctx) == CCB_OK) {
            bench_rust(ctx, "rust-cabi-p11", {64, 1024});
            ccb_ctx_free(ctx);
        }
    }
    return 0;
}
