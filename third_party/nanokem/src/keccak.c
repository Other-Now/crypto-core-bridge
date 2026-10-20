/* Keccak-f[1600] permutation + the sponge construction, producing SHA3-256,
 * SHA3-512, SHAKE128, and SHAKE256 (FIPS 202). One correct sponge
 * implementation (in the incremental nk_shake_ctx API below) backs every
 * one-shot wrapper too, rather than a second hand-duplicated one-shot code
 * path -- fewer places for the absorb/pad/squeeze logic to disagree with
 * itself. */
#include "nanokem/sha3.h"

#include <string.h>

/* Standard Keccak-f[1600] round constants (24 rounds) and rotation offsets
 * -- the same tables every SHA-3 implementation uses (Keccak reference code,
 * OpenSSL, BoringSSL, ...). Not hand-verified digit-by-digit here; instead
 * validated the way that actually matters for a table this size: the full
 * permutation built from it is checked end to end against real published
 * KATs (SHA3-256(""), SHA3-512(""), and 200-byte SHAKE128/256("") prefixes
 * fetched directly from the Keccak team's own XKCP test-vector repository --
 * see tests/test_sha3.c). A wrong constant here fails those loudly, not
 * silently. */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* r[x][y]: rotation offset for lane (x,y), x=column 0..4, y=row 0..4. */
static const int ROT[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};

static uint64_t rotl64(uint64_t x, int n) {
    n &= 63;
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

static void keccak_f1600(uint64_t A[25]) {
#define AT(x, y) A[(x) + 5 * (y)]
    for (int round = 0; round < 24; ++round) {
        /* theta */
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x) C[x] = AT(x, 0) ^ AT(x, 1) ^ AT(x, 2) ^ AT(x, 3) ^ AT(x, 4);
        for (int x = 0; x < 5; ++x) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) AT(x, y) ^= D[x];

        /* rho + pi: B[y, 2x+3y mod 5] = rotl(A[x,y], ROT[x][y]) */
        uint64_t B[25];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(AT(x, y), ROT[x][y]);

        /* chi */
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                AT(x, y) = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);

        /* iota */
        AT(0, 0) ^= RC[round];
    }
#undef AT
}

static void xor_bytes_into_state(uint64_t state[25], const uint8_t *block, size_t rate) {
    for (size_t i = 0; i < rate; i += 8) {
        uint64_t lane = 0;
        size_t n = rate - i < 8 ? rate - i : 8;
        for (size_t j = 0; j < n; ++j) lane |= (uint64_t)block[i + j] << (8 * j);
        state[i / 8] ^= lane;
    }
}

static void extract_bytes_from_state(const uint64_t state[25], uint8_t *block, size_t rate) {
    for (size_t i = 0; i < rate; i += 8) {
        uint64_t lane = state[i / 8];
        size_t n = rate - i < 8 ? rate - i : 8;
        for (size_t j = 0; j < n; ++j) block[i + j] = (uint8_t)(lane >> (8 * j));
    }
}

static void ctx_init(nk_shake_ctx *ctx, size_t rate) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->buf_len = 0;
    ctx->rate = rate;
    ctx->squeezing = 0;
}

void nk_shake128_absorb_init(nk_shake_ctx *ctx) { ctx_init(ctx, 168); } /* (1600-2*128)/8 */
void nk_shake256_absorb_init(nk_shake_ctx *ctx) { ctx_init(ctx, 136); } /* (1600-2*256)/8 */

static void sha3_init(nk_shake_ctx *ctx, size_t rate) { ctx_init(ctx, rate); }

void nk_shake_absorb(nk_shake_ctx *ctx, const uint8_t *data, size_t data_len) {
    while (data_len > 0) {
        size_t avail = ctx->rate - ctx->buf_len;
        size_t n = data_len < avail ? data_len : avail;
        memcpy(ctx->buf + ctx->buf_len, data, n);
        ctx->buf_len += n;
        data += n;
        data_len -= n;
        if (ctx->buf_len == ctx->rate) {
            xor_bytes_into_state(ctx->state, ctx->buf, ctx->rate);
            keccak_f1600(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

/* domain_sep: 0x1F for SHAKE128/256, 0x06 for SHA3-224/256/384/512 (FIPS 202
 * section 6.1/6.2's suffix bits, combined with the mandatory pad10*1 rule
 * into the single first padding byte). */
static void finalize_and_start_squeeze(nk_shake_ctx *ctx, uint8_t domain_sep) {
    uint8_t pad[168] = {0}; /* >= max rate (168); zero-init covers any rate <= that */
    memcpy(pad, ctx->buf, ctx->buf_len);
    pad[ctx->buf_len] ^= domain_sep;
    pad[ctx->rate - 1] ^= 0x80;
    xor_bytes_into_state(ctx->state, pad, ctx->rate);
    keccak_f1600(ctx->state);
    ctx->squeezing = 1;
    extract_bytes_from_state(ctx->state, ctx->buf, ctx->rate);
    ctx->buf_len = 0;
}

void nk_shake_squeeze(nk_shake_ctx *ctx, uint8_t *out, size_t out_len) {
    if (!ctx->squeezing) finalize_and_start_squeeze(ctx, 0x1F);
    while (out_len > 0) {
        if (ctx->buf_len == ctx->rate) {
            keccak_f1600(ctx->state);
            extract_bytes_from_state(ctx->state, ctx->buf, ctx->rate);
            ctx->buf_len = 0;
        }
        size_t avail = ctx->rate - ctx->buf_len;
        size_t n = out_len < avail ? out_len : avail;
        memcpy(out, ctx->buf + ctx->buf_len, n);
        ctx->buf_len += n;
        out += n;
        out_len -= n;
    }
}

/* SHA3's fixed-length squeeze reuses the identical machinery with
 * domain_sep=0x06 -- not exposed as a public incremental API (nothing in
 * this repo needs incremental SHA3, only incremental SHAKE, per how ML-KEM
 * actually calls these), but implemented once, here, and shared by both
 * one-shot SHA3 wrappers below. */
static void sha3_squeeze_once(nk_shake_ctx *ctx, uint8_t *out, size_t out_len) {
    finalize_and_start_squeeze(ctx, 0x06);
    nk_shake_squeeze(ctx, out, out_len); /* ctx->squeezing already 1: no double pad */
}

void nk_sha3_256(const uint8_t *data, size_t data_len, uint8_t out[32]) {
    nk_shake_ctx ctx;
    sha3_init(&ctx, 136); /* (1600-2*256)/8 */
    nk_shake_absorb(&ctx, data, data_len);
    sha3_squeeze_once(&ctx, out, 32);
}

void nk_sha3_512(const uint8_t *data, size_t data_len, uint8_t out[64]) {
    nk_shake_ctx ctx;
    sha3_init(&ctx, 72); /* (1600-2*512)/8 */
    nk_shake_absorb(&ctx, data, data_len);
    sha3_squeeze_once(&ctx, out, 64);
}

void nk_shake128(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len) {
    nk_shake_ctx ctx;
    nk_shake128_absorb_init(&ctx);
    nk_shake_absorb(&ctx, data, data_len);
    nk_shake_squeeze(&ctx, out, out_len);
}

void nk_shake256(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len) {
    nk_shake_ctx ctx;
    nk_shake256_absorb_init(&ctx);
    nk_shake_absorb(&ctx, data, data_len);
    nk_shake_squeeze(&ctx, out, out_len);
}
