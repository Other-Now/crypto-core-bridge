#ifndef NANOKEM_SHA3_H
#define NANOKEM_SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keccak-f[1600] / SHA-3 (FIPS 202) -- the one hash family nano-dtls didn't
 * need (it only ever used SHA-256) and ML-KEM-768 (FIPS 203) requires
 * throughout: SHA3-256 for `H`, SHA3-512 for `G`, SHAKE256 as both the `J`
 * (implicit-rejection) function and the CBD noise PRF, and SHAKE128 as the
 * XOF that expands a matrix seed into the public matrix A. Portable C11,
 * uint64_t lanes only -- no wide-multiply/__int128 need, same portability
 * bar as every other primitive in this repo.
 *
 * Verified against the XKCP (eXtended Keccak Code Package -- the Keccak
 * team's own reference vectors) short-message KAT files fetched directly
 * for this build, not hand-recalled: SHA3-256(""), SHA3-512(""), and a
 * 200-byte SHAKE128("")/SHAKE256("") prefix (long enough to cross a squeeze
 * rate boundary on both, so the multi-block squeeze path is exercised, not
 * just a single permutation call). See tests/test_sha3.c. */

/* SHA3-256: fixed 32-byte digest, one-shot. */
void nk_sha3_256(const uint8_t *data, size_t data_len, uint8_t out[32]);

/* SHA3-512: fixed 64-byte digest, one-shot. */
void nk_sha3_512(const uint8_t *data, size_t data_len, uint8_t out[64]);

/* SHAKE128/SHAKE256: extendable-output functions (XOFs) -- caller picks
 * out_len. One-shot (absorbs all of `data`, then squeezes out_len bytes);
 * ML-KEM never needs streaming/incremental absorption. */
void nk_shake128(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);
void nk_shake256(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/* Incremental SHAKE128, needed for ML-KEM's matrix-generation XOF (FIPS 203
 * Algorithm 7, XOF.Absorb(rho || i || j) then squeeze 3 bytes at a time
 * during rejection sampling) and the CBD PRF, where the input is built from
 * several pieces rather than one contiguous buffer. Call
 * nk_shake128_absorb_init, any number of nk_shake128_absorb, then
 * nk_shake128_squeeze any number of times (squeeze calls may be mixed with
 * further absorb calls only via a fresh init -- this is squeeze-only once
 * started, matching how ML-KEM actually uses it). */
typedef struct nk_shake_ctx {
    uint64_t state[25];
    uint8_t buf[168]; /* largest of the two rates (SHAKE128 rate) */
    size_t buf_len;
    size_t rate;
    int squeezing;
} nk_shake_ctx;

void nk_shake128_absorb_init(nk_shake_ctx *ctx);
void nk_shake256_absorb_init(nk_shake_ctx *ctx);
void nk_shake_absorb(nk_shake_ctx *ctx, const uint8_t *data, size_t data_len);
void nk_shake_squeeze(nk_shake_ctx *ctx, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* NANOKEM_SHA3_H */
