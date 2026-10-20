#ifndef NANOKEM_MLKEM768_H
#define NANOKEM_MLKEM768_H

#include <stddef.h>
#include <stdint.h>

#include "nanokem/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * ML-KEM-768 (NIST FIPS 203), built from scratch: the module-lattice-based
 * key-encapsulation mechanism nanokem's hybrid key exchange combines with
 * X25519 -- this is the whole point of this repo (see PLAN.md/README for
 * why nano-dtls, this project's sibling, scoped this out and this project
 * exists specifically to build it).
 *
 * Implemented from FIPS 203's algorithm structure as mirrored precisely in
 * Go's standard-library ML-KEM implementation (crypto/internal/fips140/
 * mlkem, BSD-licensed, written "to facilitate reviewing the implementation
 * against the NIST FIPS 203 document") -- fetched directly for this build
 * rather than reconstructed from memory, same discipline as every RFC this
 * repo (and nano-dtls before it) has implemented from. One real divergence
 * from that source, found via the external KAT below rather than assumed
 * away: Go's KeyGen hashes G(d || k) (a module-dimension domain-separator
 * byte appended as that codebase's own FIPS-140-module hardening choice),
 * while the base FIPS 203 / pq-crystals-reference convention these test
 * vectors target uses plain G(d) -- this module follows the latter, the
 * one that actually matches published external vectors.
 *
 * Verified two ways: self-consistency (KeyGen->Encaps->Decaps round-trips;
 * a tampered ciphertext still decapsulates to *some* pseudorandom key
 * rather than erroring -- ML-KEM's defining implicit-rejection property,
 * not AEAD-style failure -- see tests/test_mlkem768.c) and a real external
 * known-answer trace: the C2SP/CCTV project's ML-KEM/intermediate/
 * ML-KEM-768.txt, a fully worked KeyGen/Encaps/Decaps example from a
 * reference implementation -- this module's encapsulation key, ciphertext,
 * and shared secret (both Encaps's and Decaps's) all match it byte-exact
 * (see tests/test_mlkem768_kat.c).
 *
 * Parameters (FIPS 203 Table 2, k=3 row): n=256, q=3329, eta1=eta2=2,
 * du=10, dv=4. Encapsulation key 1184 bytes, ciphertext 1088 bytes, shared
 * secret 32 bytes.
 *
 * These are the "internal" (derandomized) algorithms (FIPS 203 Algorithms
 * 16-18): callers supply the randomness (d/z at keygen, m at encapsulation)
 * explicitly rather than this module drawing it from an RNG itself --
 * matching every other primitive in this repo (nk_x25519_scalarmult,
 * p256 verify, ...) and making the KAT-vector tests possible without a
 * separate derandomized code path to keep in sync. Real callers draw
 * d/z/m via nk_random_bytes (see random.h) before calling these -- see
 * src/handshake/hybrid_kex.c.
 * --------------------------------------------------------------------- */

#define NK_MLKEM768_K 3u
#define NK_MLKEM768_EK_LEN 1184u /* k*384 + 32 */
#define NK_MLKEM768_CT_LEN 1088u /* k*320 + 128 */
#define NK_MLKEM768_SS_LEN 32u

/* One polynomial: 256 coefficients mod q=3329, used both for a "ring"
 * element (coefficient domain) and an "NTT" element (NTT domain) -- same
 * representation, distinguished only by which functions produced/consume
 * it (matches how most from-scratch Kyber/ML-KEM C implementations do
 * this; a stronger compile-time type split isn't worth the duplication for
 * a single parameter set). */
typedef uint16_t nk_mlkem_poly[256];

/* The parsed/expanded form of an encapsulation key: t (NTT domain) and the
 * sampled public matrix A, both already expanded from rho so Encaps doesn't
 * redo that work, plus rho and h=SHA3-256(encoded ek) themselves (h feeds
 * both Encaps and Decaps' key derivation). */
typedef struct nk_mlkem768_ek {
    nk_mlkem_poly t[NK_MLKEM768_K];
    nk_mlkem_poly a[NK_MLKEM768_K * NK_MLKEM768_K]; /* a[i*K+j] */
    uint8_t rho[32];
    uint8_t h[32];
} nk_mlkem768_ek;

/* The parsed/expanded decapsulation key: the NTT-domain secret s, plus a
 * full copy of the matching encapsulation key (Decaps' FO-transform step
 * re-runs Encrypt, which needs t and A) and the implicit-rejection seed z. */
typedef struct nk_mlkem768_dk {
    nk_mlkem_poly s[NK_MLKEM768_K];
    nk_mlkem768_ek ek;
    uint8_t z[32];
} nk_mlkem768_dk;

/* ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16, merged with K-PKE.KeyGen /
 * Algorithm 13): d and z are independent 32-byte random seeds -- d seeds
 * the key material itself, z seeds implicit rejection at decapsulation
 * time. Populates out_dk (and, reachable via out_dk->ek, the encapsulation
 * key -- see nk_mlkem768_ek_encode to get the wire bytes to send a peer). */
void nk_mlkem768_keygen(const uint8_t d[32], const uint8_t z[32], nk_mlkem768_dk *out_dk);

/* Encodes ek into its NK_MLKEM768_EK_LEN-byte wire form (ByteEncode12(t) ||
 * rho, FIPS 203 Algorithm 14's key-parsing preamble run in reverse). */
void nk_mlkem768_ek_encode(const nk_mlkem768_ek *ek, uint8_t out[NK_MLKEM768_EK_LEN]);

/* Parses and validates a peer's encapsulation key from wire bytes,
 * expanding the public matrix A from the embedded rho. Performs the
 * "modulus check" FIPS 203 section 7.2 requires (every ByteDecode12'd
 * coefficient must be < q) -- returns NK_ERR_BAD_ARG if it fails, never
 * silently accepts an out-of-range encoding. */
nk_status nk_mlkem768_ek_parse(const uint8_t in[NK_MLKEM768_EK_LEN], nk_mlkem768_ek *out_ek);

/* ML-KEM.Encaps_internal (FIPS 203 Algorithm 17, calling K-PKE.Encrypt /
 * Algorithm 14 internally): m is the 32-byte message randomness. Produces
 * a fresh ciphertext and the shared secret it encapsulates. */
void nk_mlkem768_encaps(const nk_mlkem768_ek *ek, const uint8_t m[32], uint8_t out_ct[NK_MLKEM768_CT_LEN],
                         uint8_t out_ss[NK_MLKEM768_SS_LEN]);

/* ML-KEM.Decaps_internal (FIPS 203 Algorithm 18, calling K-PKE.Decrypt /
 * Algorithm 15 internally): recovers the shared secret from ct. Never
 * fails/errors -- FIPS 203's implicit-rejection design means a tampered or
 * malformed-but-right-length ciphertext still decapsulates to *some*
 * pseudorandom 32-byte value (derived from dk->z, unusable by an attacker
 * without dk), not an error code. That's a real, defining correctness
 * property of ML-KEM, not a formality -- see tests/test_mlkem768.c. */
void nk_mlkem768_decaps(const nk_mlkem768_dk *dk, const uint8_t ct[NK_MLKEM768_CT_LEN],
                         uint8_t out_ss[NK_MLKEM768_SS_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANOKEM_MLKEM768_H */
