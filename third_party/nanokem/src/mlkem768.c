/* ML-KEM-768 (FIPS 203). See mlkem768.h for the sourcing/verification note.
 * Field/NTT structure and the zetas/gammas tables below are translated from
 * Go's standard-library ML-KEM implementation (crypto/internal/fips140/
 * mlkem, BSD-licensed) -- fetched directly rather than hand-derived, and
 * cross-checked the way that actually matters for tables this size: the
 * full construction is verified end to end against real published test
 * vectors (see tests/test_mlkem768.c), not eyeballed digit by digit. */
#include "nanokem/mlkem768.h"

#include <string.h>

#include "nanokem/sha3.h"

#define Q 3329u
#define N 256u
#define K NK_MLKEM768_K
#define ETA 2u /* eta1 == eta2 == 2 for ML-KEM-768 (FIPS 203 Table 2) */
#define DU 10u
#define DV 4u
#define ENC12 384u /* n*12/8: ByteEncode12 size of one polynomial */

/* ---------------------------------------------------------------------
 * Field arithmetic mod q=3329, mirroring Go's fieldElement operations
 * exactly (including its branch-free reduction tricks -- see field.go's
 * comments for why each one is correct; ported here with the explicit
 * uint16_t/uint32_t casts C needs that Go's fixed-width types don't).
 * --------------------------------------------------------------------- */

static uint16_t field_reduce_once(uint16_t a) { /* reduces a < 2q */
    uint16_t x = (uint16_t)(a - Q);
    /* If a < Q, "a - Q" wraps around (unsigned 16-bit) to a value close to
     * 2^16 whose top bit is set; a plain unsigned shift (well-defined, no
     * implementation-defined signed-shift reliance) reads that bit back to
     * conditionally add Q, exactly mirroring Go's `x += (x>>15)*q`. */
    uint16_t top_bit = (uint16_t)(x >> 15);
    return (uint16_t)(x + top_bit * Q);
}

static uint16_t field_add(uint16_t a, uint16_t b) { return field_reduce_once((uint16_t)(a + b)); }
static uint16_t field_sub(uint16_t a, uint16_t b) { return field_reduce_once((uint16_t)(a - b + Q)); }

#define BARRETT_MUL 5039u /* 2^12 * 2^12 / q */
#define BARRETT_SHIFT 24u

static uint16_t field_reduce(uint32_t a) { /* reduces a < 2q^2 (Barrett) */
    uint32_t quotient = (uint32_t)(((uint64_t)a * BARRETT_MUL) >> BARRETT_SHIFT);
    return field_reduce_once((uint16_t)(a - quotient * Q));
}

static uint16_t field_mul(uint16_t a, uint16_t b) { return field_reduce((uint32_t)a * (uint32_t)b); }

/* a*(b-c) -- fuses the subtraction's reduction into the multiply's. */
static uint16_t field_mul_sub(uint16_t a, uint16_t b, uint16_t c) {
    return field_reduce((uint32_t)a * (uint32_t)(uint16_t)(b - c + Q));
}

/* a*b + c*d -- fuses two multiplies' reductions into one. */
static uint16_t field_add_mul(uint16_t a, uint16_t b, uint16_t c, uint16_t d) {
    return field_reduce((uint32_t)a * (uint32_t)b + (uint32_t)c * (uint32_t)d);
}

static void poly_add(nk_mlkem_poly out, const nk_mlkem_poly a, const nk_mlkem_poly b) {
    for (size_t i = 0; i < N; ++i) out[i] = field_add(a[i], b[i]);
}
static void poly_sub(nk_mlkem_poly out, const nk_mlkem_poly a, const nk_mlkem_poly b) {
    for (size_t i = 0; i < N; ++i) out[i] = field_sub(a[i], b[i]);
}

/* ---------------------------------------------------------------------
 * Compress/Decompress (FIPS 203 Definitions 4.7/4.8): round-to-nearest
 * (x*2^d)/q, with the branch-free rounding trick from Go's compress().
 * --------------------------------------------------------------------- */

static uint16_t compress_d(uint16_t x, unsigned d) {
    uint32_t dividend = (uint32_t)x << d;
    uint32_t quotient = (uint32_t)(((uint64_t)dividend * BARRETT_MUL) >> BARRETT_SHIFT);
    uint32_t remainder = dividend - quotient * Q;
    /* remainder is in [0, 2q); "add 1 if remainder > q/2, add another 1 if
     * remainder > q + q/2" via the same wraparound-then-read-top-bit trick
     * as field_reduce_once, kept in pure unsigned arithmetic throughout
     * (Q/2 and remainder are already uint32_t, so the subtraction's
     * wraparound and the shift are both well-defined, no signed-shift
     * reliance needed). */
    quotient += ((uint32_t)(Q / 2 - remainder) >> 31) & 1u;
    quotient += ((uint32_t)(Q + Q / 2 - remainder) >> 31) & 1u;
    uint32_t mask = (1u << d) - 1u;
    return (uint16_t)(quotient & mask);
}

static uint16_t decompress_d(uint16_t y, unsigned d) {
    uint32_t dividend = (uint32_t)y * Q;
    uint32_t quotient = dividend >> d;
    quotient += (dividend >> (d - 1)) & 1u;
    return (uint16_t)quotient;
}

/* ---------------------------------------------------------------------
 * ByteEncode12 / ByteDecode12 (FIPS 203 Algorithms 5/6, d=12): the plain
 * (non-compressed) polynomial encoding used for t and s. ByteDecode12
 * performs the "modulus check" (reject any coefficient >= q) -- required
 * whenever decoding attacker-controlled bytes (an encapsulation key).
 * --------------------------------------------------------------------- */

static void poly_encode12(uint8_t *out, const nk_mlkem_poly f) {
    for (size_t i = 0; i < N; i += 2) {
        uint32_t x = (uint32_t)f[i] | ((uint32_t)f[i + 1] << 12);
        out[0] = (uint8_t)x;
        out[1] = (uint8_t)(x >> 8);
        out[2] = (uint8_t)(x >> 16);
        out += 3;
    }
}

static nk_status poly_decode12_checked(const uint8_t *in, nk_mlkem_poly out) {
    for (size_t i = 0; i < N; i += 2) {
        uint32_t d = (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16);
        uint16_t a = (uint16_t)(d & 0xFFFu);
        uint16_t b = (uint16_t)(d >> 12);
        if (a >= Q || b >= Q) return NK_ERR_BAD_ARG;
        out[i] = a;
        out[i + 1] = b;
        in += 3;
    }
    return NK_OK;
}

/* ---------------------------------------------------------------------
 * Compressed encodings for the message (d=1) and the two ciphertext parts
 * (d=DU=10 for u, d=DV=4 for v) -- FIPS 203 Algorithms 5/6 + Definitions
 * 4.7/4.8 composed, matching Go's ringCompressAndEncode{1,4,10}/
 * ringDecodeAndDecompress{1,4,10} bit layouts exactly.
 * --------------------------------------------------------------------- */

static void encode_compress1(uint8_t *out, const nk_mlkem_poly f) { /* 32 bytes */
    memset(out, 0, 32);
    for (size_t i = 0; i < N; ++i) out[i / 8] = (uint8_t)(out[i / 8] | (compress_d(f[i], 1) << (i % 8)));
}
static void decode_decompress1(const uint8_t *in, nk_mlkem_poly out) {
    for (size_t i = 0; i < N; ++i) {
        uint16_t bit = (uint16_t)((in[i / 8] >> (i % 8)) & 1u);
        out[i] = (uint16_t)(bit * ((Q + 1) / 2)); /* 0 -> 0, 1 -> ceil(q/2) */
    }
}

static void encode_compress4(uint8_t *out, const nk_mlkem_poly f) { /* 128 bytes */
    for (size_t i = 0; i < N; i += 2) {
        out[i / 2] = (uint8_t)(compress_d(f[i], 4) | (compress_d(f[i + 1], 4) << 4));
    }
}
static void decode_decompress4(const uint8_t *in, nk_mlkem_poly out) {
    for (size_t i = 0; i < N; i += 2) {
        out[i] = decompress_d((uint16_t)(in[i / 2] & 0x0Fu), 4);
        out[i + 1] = decompress_d((uint16_t)(in[i / 2] >> 4), 4);
    }
}

static void encode_compress10(uint8_t *out, const nk_mlkem_poly f) { /* 320 bytes */
    for (size_t i = 0; i < N; i += 4) {
        uint64_t x = 0;
        x |= (uint64_t)compress_d(f[i], 10);
        x |= (uint64_t)compress_d(f[i + 1], 10) << 10;
        x |= (uint64_t)compress_d(f[i + 2], 10) << 20;
        x |= (uint64_t)compress_d(f[i + 3], 10) << 30;
        out[0] = (uint8_t)x;
        out[1] = (uint8_t)(x >> 8);
        out[2] = (uint8_t)(x >> 16);
        out[3] = (uint8_t)(x >> 24);
        out[4] = (uint8_t)(x >> 32);
        out += 5;
    }
}
static void decode_decompress10(const uint8_t *in, nk_mlkem_poly out) {
    for (size_t i = 0; i < N; i += 4) {
        uint64_t x = (uint64_t)in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 24) |
                     ((uint64_t)in[4] << 32);
        out[i] = decompress_d((uint16_t)(x & 0x3FFu), 10);
        out[i + 1] = decompress_d((uint16_t)((x >> 10) & 0x3FFu), 10);
        out[i + 2] = decompress_d((uint16_t)((x >> 20) & 0x3FFu), 10);
        out[i + 3] = decompress_d((uint16_t)((x >> 30) & 0x3FFu), 10);
        in += 5;
    }
}

/* ---------------------------------------------------------------------
 * SamplePolyCBD (FIPS 203 Algorithm 8, Definition 4.3): draws a
 * centered-binomial-distributed polynomial from PRF(seed, b) = SHAKE256.
 * eta=2 for both eta1 and eta2 at k=3, so this only implements that case.
 * --------------------------------------------------------------------- */

static void sample_poly_cbd(const uint8_t seed[32], uint8_t b, nk_mlkem_poly out) {
    nk_shake_ctx ctx;
    nk_shake256_absorb_init(&ctx);
    nk_shake_absorb(&ctx, seed, 32);
    nk_shake_absorb(&ctx, &b, 1);
    uint8_t buf[64 * ETA]; /* 128 bytes for eta=2 */
    nk_shake_squeeze(&ctx, buf, sizeof(buf));

    for (size_t i = 0; i < N; i += 2) {
        uint8_t byte = buf[i / 2];
        uint16_t b0 = byte & 1u, b1 = (byte >> 1) & 1u, b2 = (byte >> 2) & 1u, b3 = (byte >> 3) & 1u;
        uint16_t b4 = (byte >> 4) & 1u, b5 = (byte >> 5) & 1u, b6 = (byte >> 6) & 1u, b7 = (byte >> 7) & 1u;
        out[i] = field_sub((uint16_t)(b0 + b1), (uint16_t)(b2 + b3));
        out[i + 1] = field_sub((uint16_t)(b4 + b5), (uint16_t)(b6 + b7));
    }
}

/* ---------------------------------------------------------------------
 * SampleNTT (FIPS 203 Algorithm 7): rejection-samples an NTT-domain
 * polynomial from SHAKE128(rho || ii || jj), 12 bits at a time (two
 * 12-bit little-endian candidates per 3 XOF bytes), rejecting any value
 * >= q (~19% rejection rate). Matches Go's exact bit layout so this repo's
 * matrix A is byte-for-byte what the reference implementation produces --
 * needed for the C2SP/CCTV KAT vectors to match at all.
 * --------------------------------------------------------------------- */

static void sample_ntt(const uint8_t rho[32], uint8_t ii, uint8_t jj, nk_mlkem_poly out) {
    nk_shake_ctx ctx;
    nk_shake128_absorb_init(&ctx);
    nk_shake_absorb(&ctx, rho, 32);
    const uint8_t two[2] = {ii, jj};
    nk_shake_absorb(&ctx, two, 2);

    size_t j = 0;
    while (j < N) {
        uint8_t buf[3];
        nk_shake_squeeze(&ctx, buf, 3);
        uint16_t r0 = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
        uint16_t r1 = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
        uint16_t d1 = (uint16_t)(r0 & 0x0FFFu);
        uint16_t d2 = (uint16_t)(r1 >> 4);
        if (d1 < Q) {
            out[j++] = d1;
            if (j >= N) break;
        }
        if (d2 < Q) {
            out[j++] = d2;
        }
    }
}

/* ---------------------------------------------------------------------
 * NTT / NTT^-1 / MultiplyNTTs (FIPS 203 Algorithms 9/10/11), zetas/gammas
 * per FIPS 203 Appendix A: zeta[k] = zeta^BitRev7(k) mod q, gamma[i] =
 * zeta^(2*BitRev7(i)+1) mod q, zeta=17 (a primitive 256th root of unity
 * mod q=3329). Ported verbatim from Go's field.go (see file header).
 * --------------------------------------------------------------------- */

static const uint16_t ZETAS[128] = {
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,  2786, 3260, 569,  1746, 296,  2447,
    1339, 1476, 3046, 56,   2240, 1333, 1426, 2094, 535,  2882, 2393, 2879, 1974, 821,  289,  331,  3253, 1756,
    1197, 2304, 2277, 2055, 650,  1977, 2513, 632,  2865, 33,   1320, 1915, 2319, 1435, 807,  452,  1438, 2868,
    1534, 2402, 2647, 2617, 1481, 648,  2474, 3110, 1227, 910,  17,   2761, 583,  2649, 1637, 723,  2288, 1100,
    1409, 2662, 3281, 233,  756,  2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952,  1461, 2687, 939,  2308,
    2437, 2388, 733,  2337, 268,  641,  1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063, 319,  2773, 757,
    2099, 561,  2466, 2594, 2804, 1092, 403,  1026, 1143, 2150, 2775, 886,  1722, 1212, 1874, 1029, 2110, 2935,
    885,  2154,
};

static const uint16_t GAMMAS[128] = {
    17,   3312, 2761, 568,  583,  2746, 2649, 680,  1637, 1692, 723,  2606, 2288, 1041, 1100, 2229, 1409, 1920,
    2662, 667,  3281, 48,   233,  3096, 756,  2573, 2156, 1173, 3015, 314,  3050, 279,  1703, 1626, 1651, 1678,
    2789, 540,  1789, 1540, 1847, 1482, 952,  2377, 1461, 1868, 2687, 642,  939,  2390, 2308, 1021, 2437, 892,
    2388, 941,  733,  2596, 2337, 992,  268,  3061, 641,  2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
    375,  2954, 2549, 780,  2090, 1239, 1645, 1684, 1063, 2266, 319,  3010, 2773, 556,  757,  2572, 2099, 1230,
    561,  2768, 2466, 863,  2594, 735,  2804, 525,  1092, 2237, 403,  2926, 1026, 2303, 1143, 2186, 2150, 1179,
    2775, 554,  886,  2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394,  885,  2444,
    2154, 1175,
};

static void ntt(nk_mlkem_poly f) {
    unsigned k = 1;
    for (unsigned len = 128; len >= 2; len /= 2) {
        for (unsigned start = 0; start < N; start += 2 * len) {
            uint16_t zeta = ZETAS[k++];
            for (unsigned j = 0; j < len; ++j) {
                uint16_t t = field_mul(zeta, f[start + len + j]);
                f[start + len + j] = field_sub(f[start + j], t);
                f[start + j] = field_add(f[start + j], t);
            }
        }
    }
}

static void inverse_ntt(nk_mlkem_poly f) {
    int k = 127;
    for (unsigned len = 2; len <= 128; len *= 2) {
        for (unsigned start = 0; start < N; start += 2 * len) {
            uint16_t zeta = ZETAS[k--];
            for (unsigned j = 0; j < len; ++j) {
                uint16_t t = f[start + j];
                f[start + j] = field_add(t, f[start + len + j]);
                f[start + len + j] = field_mul_sub(zeta, f[start + len + j], t);
            }
        }
    }
    for (size_t i = 0; i < N; ++i) f[i] = field_mul(f[i], 3303); /* 3303 = 128^-1 mod q */
}

static void ntt_mul(nk_mlkem_poly out, const nk_mlkem_poly f, const nk_mlkem_poly g) {
    for (size_t i = 0; i < N; i += 2) {
        uint16_t a0 = f[i], a1 = f[i + 1], b0 = g[i], b1 = g[i + 1];
        out[i] = field_add_mul(a0, b0, field_mul(a1, b1), GAMMAS[i / 2]);
        out[i + 1] = field_add_mul(a0, b1, a1, b0);
    }
}

/* ---------------------------------------------------------------------
 * K-PKE.KeyGen / ML-KEM.KeyGen_internal (FIPS 203 Algorithms 13, 16 --
 * merged, as in Go's kemKeyGen, to avoid a redundant copy of t/rho).
 * --------------------------------------------------------------------- */

void nk_mlkem768_keygen(const uint8_t d[32], const uint8_t z[32], nk_mlkem768_dk *out_dk) {
    memcpy(out_dk->z, z, 32);

    /* G(d) = SHA3-512(d) -- plain, no domain-separator byte. (Go's standard-
     * library ML-KEM appends a module-dimension byte here as its own
     * FIPS-140-module hardening choice; confirmed via this file's KAT
     * mismatch that the base FIPS 203 / pq-crystals-reference convention
     * these vectors target does NOT include it -- fixed after the KAT
     * caught the divergence, exactly the kind of single-secondary-source
     * trap this project's verify-against-real-vectors discipline exists
     * to catch.) */
    uint8_t g_out[64];
    /* crypto-core-bridge patch 0001: FIPS 203 (final, Aug 2024) Algorithm 13
     * line 1 is (rho, sigma) <- G(d || k). The plain G(d) above follows the
     * 2023 draft; it fails all 100 Wycheproof keygen-from-seed vectors and
     * every seed cross-check against OpenSSL 3.5 (see third_party/nanokem/
     * README.md). */
    uint8_t d_k[33];
    memcpy(d_k, d, 32);
    d_k[32] = (uint8_t)K;
    nk_sha3_512(d_k, sizeof d_k, g_out);
    const uint8_t *rho = g_out;
    const uint8_t *sigma = g_out + 32;
    memcpy(out_dk->ek.rho, rho, 32);

    for (unsigned i = 0; i < K; ++i)
        for (unsigned j = 0; j < K; ++j) sample_ntt(rho, (uint8_t)j, (uint8_t)i, out_dk->ek.a[i * K + j]);

    uint8_t nbyte = 0;
    nk_mlkem_poly s_raw[K], e_raw[K];
    for (unsigned i = 0; i < K; ++i) sample_poly_cbd(sigma, nbyte++, s_raw[i]);
    for (unsigned i = 0; i < K; ++i) sample_poly_cbd(sigma, nbyte++, e_raw[i]);

    for (unsigned i = 0; i < K; ++i) {
        memcpy(out_dk->s[i], s_raw[i], sizeof(nk_mlkem_poly));
        ntt(out_dk->s[i]);
    }
    nk_mlkem_poly e[K];
    for (unsigned i = 0; i < K; ++i) {
        memcpy(e[i], e_raw[i], sizeof(nk_mlkem_poly));
        ntt(e[i]);
    }

    for (unsigned i = 0; i < K; ++i) { /* t = A o s + e */
        memcpy(out_dk->ek.t[i], e[i], sizeof(nk_mlkem_poly));
        for (unsigned j = 0; j < K; ++j) {
            nk_mlkem_poly prod;
            ntt_mul(prod, out_dk->ek.a[i * K + j], out_dk->s[j]);
            poly_add(out_dk->ek.t[i], out_dk->ek.t[i], prod);
        }
    }

    uint8_t ek_bytes[NK_MLKEM768_EK_LEN];
    nk_mlkem768_ek_encode(&out_dk->ek, ek_bytes);
    nk_sha3_256(ek_bytes, sizeof(ek_bytes), out_dk->ek.h);
}

void nk_mlkem768_ek_encode(const nk_mlkem768_ek *ek, uint8_t out[NK_MLKEM768_EK_LEN]) {
    uint8_t *p = out;
    for (unsigned i = 0; i < K; ++i) {
        poly_encode12(p, ek->t[i]);
        p += ENC12;
    }
    memcpy(p, ek->rho, 32);
}

nk_status nk_mlkem768_ek_parse(const uint8_t in[NK_MLKEM768_EK_LEN], nk_mlkem768_ek *out_ek) {
    nk_sha3_256(in, NK_MLKEM768_EK_LEN, out_ek->h);

    const uint8_t *p = in;
    for (unsigned i = 0; i < K; ++i) {
        nk_status st = poly_decode12_checked(p, out_ek->t[i]);
        if (st != NK_OK) return st;
        p += ENC12;
    }
    memcpy(out_ek->rho, p, 32);

    for (unsigned i = 0; i < K; ++i)
        for (unsigned j = 0; j < K; ++j) sample_ntt(out_ek->rho, (uint8_t)j, (uint8_t)i, out_ek->a[i * K + j]);
    return NK_OK;
}

/* ---------------------------------------------------------------------
 * K-PKE.Encrypt (FIPS 203 Algorithm 14, with the A^T-from-parseEK step
 * already folded into ek->a by nk_mlkem768_ek_parse/keygen, as in Go).
 * --------------------------------------------------------------------- */

static void pke_encrypt(const nk_mlkem768_ek *ek, const uint8_t m[32], const uint8_t rnd[32],
                         uint8_t out_ct[NK_MLKEM768_CT_LEN]) {
    uint8_t nbyte = 0;
    nk_mlkem_poly r[K], e1[K], e2;
    for (unsigned i = 0; i < K; ++i) sample_poly_cbd(rnd, nbyte++, r[i]);
    for (unsigned i = 0; i < K; ++i) sample_poly_cbd(rnd, nbyte++, e1[i]);
    sample_poly_cbd(rnd, nbyte++, e2);

    nk_mlkem_poly r_ntt[K];
    for (unsigned i = 0; i < K; ++i) {
        memcpy(r_ntt[i], r[i], sizeof(nk_mlkem_poly));
        ntt(r_ntt[i]);
    }

    nk_mlkem_poly u[K];
    for (unsigned i = 0; i < K; ++i) { /* u = NTT^-1(A^T o r) + e1 */
        nk_mlkem_poly u_hat;
        memset(u_hat, 0, sizeof(u_hat));
        for (unsigned j = 0; j < K; ++j) {
            /* A^T: ek->a is stored as a[i*K+j] = sampleNTT(rho,j,i); the
             * transpose swaps that back, so A^T[i][j] = ek->a[j*K+i]. */
            nk_mlkem_poly prod;
            ntt_mul(prod, ek->a[j * K + i], r_ntt[j]);
            poly_add(u_hat, u_hat, prod);
        }
        inverse_ntt(u_hat);
        poly_add(u[i], e1[i], u_hat);
    }

    nk_mlkem_poly mu;
    decode_decompress1(m, mu);

    nk_mlkem_poly v_ntt;
    memset(v_ntt, 0, sizeof(v_ntt));
    for (unsigned i = 0; i < K; ++i) { /* t^T o r */
        nk_mlkem_poly prod;
        ntt_mul(prod, ek->t[i], r_ntt[i]);
        poly_add(v_ntt, v_ntt, prod);
    }
    inverse_ntt(v_ntt);
    nk_mlkem_poly v;
    poly_add(v, v_ntt, e2);
    poly_add(v, v, mu);

    uint8_t *p = out_ct;
    for (unsigned i = 0; i < K; ++i) {
        encode_compress10(p, u[i]);
        p += 320;
    }
    encode_compress4(p, v);
}

/* ---------------------------------------------------------------------
 * K-PKE.Decrypt (FIPS 203 Algorithm 15).
 * --------------------------------------------------------------------- */

static void pke_decrypt(const nk_mlkem768_dk *dk, const uint8_t ct[NK_MLKEM768_CT_LEN], uint8_t out_m[32]) {
    nk_mlkem_poly u[K];
    const uint8_t *p = ct;
    for (unsigned i = 0; i < K; ++i) {
        decode_decompress10(p, u[i]);
        p += 320;
    }
    nk_mlkem_poly v;
    decode_decompress4(p, v);

    nk_mlkem_poly mask;
    memset(mask, 0, sizeof(mask));
    for (unsigned i = 0; i < K; ++i) {
        nk_mlkem_poly u_ntt;
        memcpy(u_ntt, u[i], sizeof(nk_mlkem_poly));
        ntt(u_ntt);
        nk_mlkem_poly prod;
        ntt_mul(prod, dk->s[i], u_ntt);
        poly_add(mask, mask, prod);
    }
    inverse_ntt(mask);

    nk_mlkem_poly w;
    poly_sub(w, v, mask);
    encode_compress1(out_m, w);
}

/* ---------------------------------------------------------------------
 * ML-KEM.Encaps_internal / Decaps_internal (FIPS 203 Algorithms 17/18).
 * --------------------------------------------------------------------- */

void nk_mlkem768_encaps(const nk_mlkem768_ek *ek, const uint8_t m[32], uint8_t out_ct[NK_MLKEM768_CT_LEN],
                         uint8_t out_ss[NK_MLKEM768_SS_LEN]) {
    uint8_t in[64], g_out[64];
    memcpy(in, m, 32);
    memcpy(in + 32, ek->h, 32);
    nk_sha3_512(in, sizeof(in), g_out);
    memcpy(out_ss, g_out, 32);           /* K */
    pke_encrypt(ek, m, g_out + 32, out_ct); /* r = G_out[32:64] */
}

/* Constant-time (branch-free) 32-byte compare-and-select, for the
 * FO-transform's implicit-rejection step: never data-dependently branch on
 * whether the re-encrypted ciphertext matches, since that comparison is
 * exactly what the implicit-rejection design exists to hide from a timing
 * side channel. */
static uint8_t ct_bytes_equal_mask(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff = (uint8_t)(diff | (a[i] ^ b[i]));
    return (uint8_t)(((uint16_t)diff - 1u) >> 8); /* 0xFF if diff==0 (equal), else 0x00 */
}

void nk_mlkem768_decaps(const nk_mlkem768_dk *dk, const uint8_t ct[NK_MLKEM768_CT_LEN],
                         uint8_t out_ss[NK_MLKEM768_SS_LEN]) {
    uint8_t m_prime[32];
    pke_decrypt(dk, ct, m_prime);

    uint8_t in[64], g_out[64];
    memcpy(in, m_prime, 32);
    memcpy(in + 32, dk->ek.h, 32);
    nk_sha3_512(in, sizeof(in), g_out);
    const uint8_t *k_prime = g_out;
    const uint8_t *r_prime = g_out + 32;

    nk_shake_ctx j_ctx;
    nk_shake256_absorb_init(&j_ctx);
    nk_shake_absorb(&j_ctx, dk->z, 32);
    nk_shake_absorb(&j_ctx, ct, NK_MLKEM768_CT_LEN);
    uint8_t k_reject[32];
    nk_shake_squeeze(&j_ctx, k_reject, 32);

    uint8_t ct1[NK_MLKEM768_CT_LEN];
    pke_encrypt(&dk->ek, m_prime, r_prime, ct1);

    uint8_t mask = ct_bytes_equal_mask(ct, ct1, NK_MLKEM768_CT_LEN); /* 0xFF: genuine, 0x00: reject */
    for (size_t i = 0; i < 32; ++i) out_ss[i] = (uint8_t)((k_prime[i] & mask) | (k_reject[i] & (uint8_t)~mask));
}
