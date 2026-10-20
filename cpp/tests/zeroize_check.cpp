// Zeroization check for the C++ core.
//
// Every heap block freed by OpenSSL (CRYPTO_set_mem_functions) or by C++
// (global operator new/delete) is scanned for the key bytes before it is
// released. A key that is still readable in freed memory was not wiped.
//
// The scan covers raw key bytes and the 32-bit-word byte-swapped form (how a
// table-based AES key schedule stores round keys 0-1 on little-endian).
// A positive control frees an unwiped copy on purpose and must be detected.
#include <openssl/crypto.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

#include "ccb/core.hpp"

namespace {

constexpr size_t kHdr = 16;  // size header in front of each tracked block
struct Pattern {
    uint8_t raw[32];
    uint8_t swapped[32];
};
Pattern g_patterns[4];
std::atomic<int> g_npatterns{0};
std::atomic<long> g_hits{0}, g_scanned{0};

bool contains(const uint8_t* p, size_t n, const uint8_t* pat, size_t m) {
    if (n < m) return false;
    for (size_t i = 0; i + m <= n; ++i)
        if (p[i] == pat[0] && std::memcmp(p + i, pat, m) == 0) return true;
    return false;
}

// 16-byte windows: half a key surviving is still a leak.
void scan(const uint8_t* p, size_t n) {
    g_scanned.fetch_add(1, std::memory_order_relaxed);
    for (int i = 0; i < g_npatterns.load(); ++i)
        for (size_t off : {size_t{0}, size_t{16}})
            if (contains(p, n, g_patterns[i].raw + off, 16) || contains(p, n, g_patterns[i].swapped + off, 16)) {
                g_hits.fetch_add(1);
                return;
            }
}

void* track_alloc(size_t n) {
    auto* b = static_cast<uint8_t*>(std::malloc(n + kHdr));
    if (!b) return nullptr;
    std::memcpy(b, &n, sizeof n);
    return b + kHdr;
}
void track_free(void* p) {
    if (!p) return;
    auto* b = static_cast<uint8_t*>(p) - kHdr;
    size_t n;
    std::memcpy(&n, b, sizeof n);
    scan(static_cast<uint8_t*>(p), n);
    std::free(b);
}
size_t track_size(void* p) {
    size_t n;
    std::memcpy(&n, static_cast<uint8_t*>(p) - kHdr, sizeof n);
    return n;
}

void* ossl_malloc(size_t n, const char*, int) { return track_alloc(n); }
void ossl_free(void* p, const char*, int) { track_free(p); }
void* ossl_realloc(void* p, size_t n, const char*, int) {
    // Always move, so a realloc that would have left key bytes behind in the
    // old block gets scanned like any other free.
    void* q = track_alloc(n);
    if (q && p) {
        size_t old = track_size(p);
        std::memcpy(q, p, old < n ? old : n);
    }
    if (q || n == 0) track_free(p);
    return q;
}

void add_pattern(const uint8_t key[32]) {
    Pattern& pt = g_patterns[g_npatterns.load()];
    std::memcpy(pt.raw, key, 32);
    for (int w = 0; w < 8; ++w)
        for (int b = 0; b < 4; ++b) pt.swapped[w * 4 + b] = key[w * 4 + 3 - b];
    g_npatterns.fetch_add(1);
}

}  // namespace

void* operator new(size_t n) {
    if (void* p = track_alloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { track_free(p); }
void operator delete[](void* p) noexcept { track_free(p); }
void operator delete(void* p, size_t) noexcept { track_free(p); }
void operator delete[](void* p, size_t) noexcept { track_free(p); }

int main() {
    if (!CRYPTO_set_mem_functions(ossl_malloc, ossl_realloc, ossl_free)) {
        std::fprintf(stderr, "CRYPTO_set_mem_functions failed (OpenSSL allocated already)\n");
        return 2;
    }
    using namespace ccb;
    // Keys live in static storage, so the test's own copies are never freed.
    static const uint8_t aes_key[32] = {'Z', 'E', 'R', 'O', '-', 'A', 'E', 'S', 0x91, 0x82, 0x73, 0x64, 0x55,
                                        0x46, 0x37, 0x28, 0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xb0,
                                        0xa1, 0x92, 0x83, 0x74, 0x65, 0x56, 0x47, 0x38};
    static const uint8_t mac_key[32] = {'Z', 'E', 'R', 'O', '-', 'M', 'A', 'C', 0x13, 0x24, 0x35, 0x46, 0x57,
                                        0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1, 0x02,
                                        0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8b};
    static const uint8_t salt[] = "salt", info[] = "info";
    static uint8_t derived[32];
    add_pattern(aes_key);
    add_pattern(mac_key);

    {
        auto ks = make_software_store();
        KeyId a{}, m{}, kek{}, d{}, back{};
        Mac tag{};
        Bytes sealed, opened, blob;
        const uint8_t msg[] = "the quick brown fox";
        ks->import_key(1, View(aes_key, 32), kFlagExportable, a);
        ks->import_key(2, View(mac_key, 32), kFlagExportable, m);
        ks->generate(1, 0, kek);
        for (int i = 0; i < 100; ++i) {
            ks->seal(a, nullptr, {}, View(msg, sizeof msg), sealed);
            ks->open(a, {}, sealed, opened);
            ks->hmac_sign(m, View(msg, sizeof msg), tag);
            ks->hmac_verify(m, View(msg, sizeof msg), tag);
        }
        ks->hkdf_derive(m, View(salt, 4), View(info, 4), 1, 0, d);
        ks->wrap(kek, a, blob);
        ks->unwrap(kek, 1, blob, 0, back);
        ks->wrap(kek, m, blob);
        ks->destroy(a);
        ks->destroy(m);
        // The derived key is only known after the fact; compute it on the
        // stack and add it before the store (and its copy) is freed.
        prim::hkdf_sha256(View(mac_key, 32), View(salt, 4), View(info, 4), derived);
        add_pattern(derived);
    }
    const long core_hits = g_hits.load(), scanned = g_scanned.load();

    // Positive control: an unwiped heap copy of a key must be caught.
    { std::vector<uint8_t> leak(aes_key, aes_key + 32); }
    const long control_hits = g_hits.load() - core_hits;

    std::printf("freed blocks scanned: %ld\ncore hits: %ld\ncontrol hits: %ld (must be >= 1)\n", scanned,
                core_hits, control_hits);
    return core_hits == 0 && control_hits >= 1 ? 0 : 1;
}
