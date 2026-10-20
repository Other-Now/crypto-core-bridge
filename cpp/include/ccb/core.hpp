// crypto-core-bridge: the C++ "Crypto Core".
//
// One KeyStore interface, two backends (software, PKCS#11). Keys are named by
// a 32-byte content-derived KeyId; raw key bytes never leave a store except as
// an AES-KW blob for keys created with kFlagExportable.
//
// The behaviour of every method (validation order, error codes, output
// formats) is the contract in docs/CONTRACT.md. The Rust implementation in
// crates/ccb must match it byte for byte; tests/differential.rs enforces that.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace ccb {

enum class Status : int32_t {
    Ok = 0,
    NullArg = -1,
    BadArg = -2,
    BufferTooSmall = -3,
    NoSuchKey = -4,
    WrongKeyType = -5,
    VerifyFailed = -6,
    NotExtractable = -7,
    Unsupported = -8,
    Backend = -9,
    Panic = -10,   // Rust side only: a panic was caught at the boundary
    Internal = -11,
};

enum class KeyType : uint32_t { Aes256 = 1, HmacSha256 = 2 };

inline constexpr uint32_t kFlagExportable = 1u;  // may be wrapped (never read in clear)
inline constexpr size_t kKeyLen = 32;
inline constexpr size_t kNonceLen = 12;
inline constexpr size_t kTagLen = 16;
inline constexpr size_t kMacLen = 32;
inline constexpr size_t kWrapLen = kKeyLen + 8;      // RFC 3394 AES-KW of a 32-byte key
inline constexpr size_t kSealOverhead = kNonceLen + kTagLen;

using KeyId = std::array<uint8_t, 32>;
using Mac = std::array<uint8_t, kMacLen>;
using Bytes = std::vector<uint8_t>;
using View = std::span<const uint8_t>;

// Owns secret bytes; the buffer never moves after construction and is wiped
// with OPENSSL_cleanse on destruction. Not copyable.
class Secret {
public:
    Secret() = default;
    explicit Secret(View v);
    explicit Secret(size_t n);
    ~Secret();
    Secret(Secret&& o) noexcept : p_(std::move(o.p_)), n_(o.n_) { o.n_ = 0; }
    Secret& operator=(Secret&& o) noexcept;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    uint8_t* data() { return p_.get(); }
    const uint8_t* data() const { return p_.get(); }
    size_t size() const { return n_; }
    View view() const { return {p_.get(), n_}; }

private:
    void wipe();
    std::unique_ptr<uint8_t[]> p_;
    size_t n_ = 0;
};

// Primitive layer (OpenSSL 3 EVP only). Used by the software store and by
// the Wycheproof harness. All return false on failure, never throw.
namespace prim {
bool hmac_sha256(View key, View msg, Mac& out);
bool sha256(View msg, std::array<uint8_t, 32>& out);
bool gcm_seal(View key, View nonce, View aad, View pt, Bytes& ct_and_tag);
bool gcm_open(View key, View nonce, View aad, View ct_and_tag, Bytes& pt);
bool hkdf_sha256(View ikm, View salt, View info, std::span<uint8_t> okm);
bool aes_kw_wrap(View kek, View key, Bytes& out);
bool aes_kw_unwrap(View kek, View blob, Secret& out);
bool random_bytes(std::span<uint8_t> out);
bool ct_equal(View a, View b);
}  // namespace prim

// Key-ID derivation, shared by both backends (see docs/CONTRACT.md §2).
inline constexpr std::array<uint8_t, 12> kKcvNonce = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
inline constexpr std::string_view kKcvLabel = "ccb-kcv-v1";
bool is_reserved_nonce(View nonce);
bool kcv_software(KeyType t, View key, Bytes& kcv);
KeyId key_id_from_kcv(KeyType t, View kcv);

class KeyStore {
public:
    virtual ~KeyStore() = default;
    virtual Status generate(uint32_t type, uint32_t flags, KeyId& out) = 0;
    virtual Status import_key(uint32_t type, View material, uint32_t flags, KeyId& out) = 0;
    virtual Status destroy(const KeyId& id) = 0;
    virtual Status wrap(const KeyId& kek, const KeyId& target, Bytes& out) = 0;
    virtual Status unwrap(const KeyId& kek, uint32_t type, View blob, uint32_t flags, KeyId& out) = 0;
    virtual Status hmac_sign(const KeyId& id, View msg, Mac& out) = 0;
    virtual Status hmac_verify(const KeyId& id, View msg, View tag) = 0;
    // nonce == nullptr: draw a random nonce. Output: nonce || ciphertext || tag.
    virtual Status seal(const KeyId& id, const uint8_t* nonce, View aad, View pt, Bytes& out) = 0;
    virtual Status open(const KeyId& id, View aad, View sealed, Bytes& out) = 0;
    virtual Status hkdf_derive(const KeyId& base, View salt, View info, uint32_t out_type,
                               uint32_t out_flags, KeyId& out) = 0;
};

std::unique_ptr<KeyStore> make_software_store();
// Logs into the token with the given label. On failure returns nullptr and
// sets *err (if non-null).
std::unique_ptr<KeyStore> make_pkcs11_store(const std::string& module_path,
                                            const std::string& token_label, View pin,
                                            Status* err = nullptr);

// Shared argument checks, so both backends validate in the same order.
inline bool valid_type(uint32_t t) { return t == 1 || t == 2; }
inline bool valid_flags(uint32_t f) { return (f & ~kFlagExportable) == 0; }

}  // namespace ccb
