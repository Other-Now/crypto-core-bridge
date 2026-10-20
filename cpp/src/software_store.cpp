// Software backend: keys live in process memory as ccb::Secret.
#include <map>
#include <mutex>

#include "ccb/core.hpp"

namespace ccb {
namespace {

struct Entry {
    KeyType type;
    uint32_t flags;
    Secret key;
};

class SoftwareStore final : public KeyStore {
public:
    Status generate(uint32_t type, uint32_t flags, KeyId& out) override {
        if (!valid_type(type) || !valid_flags(flags)) return Status::BadArg;
        Secret k(kKeyLen);
        if (!prim::random_bytes({k.data(), k.size()})) return Status::Internal;
        std::lock_guard g(mu_);
        return insert(static_cast<KeyType>(type), std::move(k), flags, out);
    }

    Status import_key(uint32_t type, View material, uint32_t flags, KeyId& out) override {
        if (!valid_type(type) || !valid_flags(flags) || material.size() != kKeyLen) return Status::BadArg;
        std::lock_guard g(mu_);
        return insert(static_cast<KeyType>(type), Secret(material), flags, out);
    }

    Status destroy(const KeyId& id) override {
        std::lock_guard g(mu_);
        return keys_.erase(id) ? Status::Ok : Status::NoSuchKey;
    }

    Status wrap(const KeyId& kek, const KeyId& target, Bytes& out) override {
        std::lock_guard g(mu_);
        const Entry* w = nullptr;
        if (Status s = find(kek, KeyType::Aes256, w); s != Status::Ok) return s;
        auto it = keys_.find(target);
        if (it == keys_.end()) return Status::NoSuchKey;
        if (!(it->second.flags & kFlagExportable)) return Status::NotExtractable;
        return prim::aes_kw_wrap(w->key.view(), it->second.key.view(), out) ? Status::Ok : Status::Internal;
    }

    Status unwrap(const KeyId& kek, uint32_t type, View blob, uint32_t flags, KeyId& out) override {
        if (!valid_type(type) || !valid_flags(flags) || blob.size() != kWrapLen) return Status::BadArg;
        std::lock_guard g(mu_);
        const Entry* w = nullptr;
        if (Status s = find(kek, KeyType::Aes256, w); s != Status::Ok) return s;
        Secret k;
        if (!prim::aes_kw_unwrap(w->key.view(), blob, k)) return Status::VerifyFailed;
        return insert(static_cast<KeyType>(type), std::move(k), flags, out);
    }

    Status hmac_sign(const KeyId& id, View msg, Mac& out) override {
        std::lock_guard g(mu_);
        const Entry* e = nullptr;
        if (Status s = find(id, KeyType::HmacSha256, e); s != Status::Ok) return s;
        return prim::hmac_sha256(e->key.view(), msg, out) ? Status::Ok : Status::Internal;
    }

    Status hmac_verify(const KeyId& id, View msg, View tag) override {
        if (tag.size() != kMacLen) return Status::BadArg;
        Mac m;
        if (Status s = hmac_sign(id, msg, m); s != Status::Ok) return s;
        return prim::ct_equal(m, tag) ? Status::Ok : Status::VerifyFailed;
    }

    Status seal(const KeyId& id, const uint8_t* nonce, View aad, View pt, Bytes& out) override {
        std::array<uint8_t, kNonceLen> n{};
        if (nonce) {
            if (is_reserved_nonce({nonce, kNonceLen})) return Status::BadArg;
            std::copy(nonce, nonce + kNonceLen, n.begin());
        }
        std::lock_guard g(mu_);
        const Entry* e = nullptr;
        if (Status s = find(id, KeyType::Aes256, e); s != Status::Ok) return s;
        if (!nonce) {
            // A random draw equal to the reserved nonce has probability 2^-96;
            // redraw anyway so the invariant is unconditional.
            do {
                if (!prim::random_bytes(n)) return Status::Internal;
            } while (is_reserved_nonce(n));
        }
        Bytes ct;
        if (!prim::gcm_seal(e->key.view(), n, aad, pt, ct)) return Status::Internal;
        out.clear();
        out.reserve(kNonceLen + ct.size());
        out.insert(out.end(), n.begin(), n.end());
        out.insert(out.end(), ct.begin(), ct.end());
        return Status::Ok;
    }

    Status open(const KeyId& id, View aad, View sealed, Bytes& out) override {
        std::lock_guard g(mu_);
        const Entry* e = nullptr;
        if (Status s = find(id, KeyType::Aes256, e); s != Status::Ok) return s;
        if (sealed.size() < kSealOverhead || is_reserved_nonce(sealed.first(kNonceLen)))
            return Status::VerifyFailed;
        return prim::gcm_open(e->key.view(), sealed.first(kNonceLen), aad, sealed.subspan(kNonceLen), out)
                   ? Status::Ok
                   : Status::VerifyFailed;
    }

    Status hkdf_derive(const KeyId& base, View salt, View info, uint32_t out_type, uint32_t out_flags,
                       KeyId& out) override {
        if (!valid_type(out_type) || !valid_flags(out_flags)) return Status::BadArg;
        std::lock_guard g(mu_);
        const Entry* b = nullptr;
        if (Status s = find(base, KeyType::HmacSha256, b); s != Status::Ok) return s;
        Secret okm(kKeyLen);
        if (!prim::hkdf_sha256(b->key.view(), salt, info, {okm.data(), okm.size()})) return Status::Internal;
        return insert(static_cast<KeyType>(out_type), std::move(okm), out_flags, out);
    }

private:
    Status find(const KeyId& id, KeyType want, const Entry*& out) const {
        auto it = keys_.find(id);
        if (it == keys_.end()) return Status::NoSuchKey;
        if (it->second.type != want) return Status::WrongKeyType;
        out = &it->second;
        return Status::Ok;
    }

    // Caller holds mu_. Importing an existing key is idempotent: same ID, the
    // stored flags are left unchanged.
    Status insert(KeyType t, Secret k, uint32_t flags, KeyId& out) {
        Bytes kcv;
        if (!kcv_software(t, k.view(), kcv)) return Status::Internal;
        out = key_id_from_kcv(t, kcv);
        if (!keys_.count(out)) keys_.emplace(out, Entry{t, flags, std::move(k)});
        return Status::Ok;
    }

    mutable std::mutex mu_;
    std::map<KeyId, Entry> keys_;  // node-based: entries never move once inserted
};

}  // namespace

std::unique_ptr<KeyStore> make_software_store() { return std::make_unique<SoftwareStore>(); }

}  // namespace ccb
