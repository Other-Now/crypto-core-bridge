// PKCS#11 backend (tested against SoftHSM2). Keys are token objects with
// CKA_SENSITIVE=true; CKA_EXTRACTABLE is true only for kFlagExportable, and
// even then the value can leave the token only via C_WrapKey. HMAC and
// AES-GCM run inside the token. Objects are located by CKA_ID = KeyId, so a
// key created by the Rust backend is usable here and vice versa.
#include <dlfcn.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>

#include "ccb/core.hpp"

#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv, name) rv name
#define CK_DECLARE_FUNCTION_POINTER(rv, name) rv(*name)
#define CK_CALLBACK_FUNCTION(rv, name) rv(*name)
#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif
#include "pkcs11.h"

namespace ccb {
namespace {

constexpr char kLabel[] = "ccb";

// PKCS#11 takes non-const pointers for read-only inputs, and some modules
// reject a null pointer even with length 0.
CK_BYTE_PTR in_ptr(View v) {
    static CK_BYTE empty = 0;
    return v.empty() ? &empty : const_cast<CK_BYTE_PTR>(v.data());
}

Status map_rv(CK_RV rv) {
    if (std::getenv("CCB_TRACE_RV") && rv != CKR_OK) std::fprintf(stderr, "CKR 0x%lx\n", (unsigned long)rv);
    switch (rv) {
        case CKR_OK: return Status::Ok;
        case CKR_SIGNATURE_INVALID:
        case CKR_SIGNATURE_LEN_RANGE:
        case CKR_ENCRYPTED_DATA_INVALID:
        case CKR_ENCRYPTED_DATA_LEN_RANGE:
        case CKR_WRAPPED_KEY_INVALID:
        case CKR_WRAPPED_KEY_LEN_RANGE: return Status::VerifyFailed;
        case CKR_KEY_UNEXTRACTABLE: return Status::NotExtractable;
        case CKR_MECHANISM_INVALID: return Status::Unsupported;
        default: return Status::Backend;
    }
}

// For C_Decrypt / C_UnwrapKey only: SoftHSM 2.6.1 reports a GCM tag mismatch
// and an AES-KW integrity failure as CKR_GENERAL_ERROR rather than
// CKR_ENCRYPTED_DATA_INVALID / CKR_WRAPPED_KEY_INVALID. Treating it as an
// authentication failure fails closed; the Rust backend does the same.
Status map_auth_rv(CK_RV rv) { return rv == CKR_GENERAL_ERROR ? Status::VerifyFailed : map_rv(rv); }

class Pkcs11Store final : public KeyStore {
public:
    ~Pkcs11Store() override {
        if (fl_) {
            if (session_) fl_->C_CloseSession(session_);
            // Another library in this process (the Rust backend) may share the
            // module; only finalize if we were the ones to initialize it.
            if (we_initialized_) fl_->C_Finalize(nullptr);
        }
        if (lib_) dlclose(lib_);
    }

    Status init(const std::string& module, const std::string& token_label, View pin) {
        lib_ = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!lib_) return Status::Backend;
        auto get = reinterpret_cast<CK_C_GetFunctionList>(dlsym(lib_, "C_GetFunctionList"));
        if (!get || get(&fl_) != CKR_OK) return Status::Backend;
        CK_C_INITIALIZE_ARGS args{};
        args.flags = CKF_OS_LOCKING_OK;
        CK_RV rv = fl_->C_Initialize(&args);
        if (rv == CKR_OK) we_initialized_ = true;
        else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) return map_rv(rv);

        CK_ULONG n = 0;
        if (fl_->C_GetSlotList(CK_TRUE, nullptr, &n) != CKR_OK || n == 0) return Status::Backend;
        std::vector<CK_SLOT_ID> slots(n);
        if (fl_->C_GetSlotList(CK_TRUE, slots.data(), &n) != CKR_OK) return Status::Backend;
        for (CK_ULONG i = 0; i < n; ++i) {
            CK_TOKEN_INFO ti{};
            if (fl_->C_GetTokenInfo(slots[i], &ti) != CKR_OK) continue;
            std::string label(reinterpret_cast<char*>(ti.label), sizeof ti.label);
            label.erase(label.find_last_not_of(' ') + 1);
            if (label != token_label) continue;
            if ((rv = fl_->C_OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                         &session_)) != CKR_OK)
                return map_rv(rv);
            rv = fl_->C_Login(session_, CKU_USER, const_cast<CK_UTF8CHAR_PTR>(pin.data()), pin.size());
            // A second session in the same process shares the login state.
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) return map_rv(rv);
            return Status::Ok;
        }
        return Status::Backend;
    }

    Status generate(uint32_t type, uint32_t flags, KeyId& out) override {
        if (!valid_type(type) || !valid_flags(flags)) return Status::BadArg;
        std::lock_guard g(mu_);
        auto t = static_cast<KeyType>(type);
        CK_MECHANISM mech{t == KeyType::Aes256 ? CKM_AES_KEY_GEN : CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0};
        Template tpl(t, flags);
        CK_ULONG len = kKeyLen;
        tpl.add(CKA_VALUE_LEN, &len, sizeof len);
        CK_OBJECT_HANDLE h = 0;
        CK_RV rv = fl_->C_GenerateKey(session_, &mech, tpl.data(), tpl.size(), &h);
        if (rv != CKR_OK) return map_rv(rv);
        return assign_id(t, h, out);
    }

    Status import_key(uint32_t type, View material, uint32_t flags, KeyId& out) override {
        if (!valid_type(type) || !valid_flags(flags) || material.size() != kKeyLen) return Status::BadArg;
        auto t = static_cast<KeyType>(type);
        // The bytes are in our hands anyway, so compute the ID on the host and
        // skip the create if the token already holds this key.
        Bytes kcv;
        if (!kcv_software(t, material, kcv)) return Status::Internal;
        KeyId id = key_id_from_kcv(t, kcv);
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE h = 0;
        if (lookup(id, h) == Status::Ok) {
            out = id;
            return Status::Ok;
        }
        Template tpl(t, flags);
        tpl.add(CKA_VALUE, const_cast<uint8_t*>(material.data()), material.size());
        tpl.add(CKA_ID, id.data(), id.size());
        CK_RV rv = fl_->C_CreateObject(session_, tpl.data(), tpl.size(), &h);
        if (rv != CKR_OK) return map_rv(rv);
        out = id;
        return Status::Ok;
    }

    Status destroy(const KeyId& id) override {
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE h = 0;
        CK_KEY_TYPE kt = 0;
        if (Status s = resolve(id, h, kt); s != Status::Ok) return s;
        cache_.erase(id);
        return map_rv(fl_->C_DestroyObject(session_, h));
    }

    Status wrap(const KeyId& kek, const KeyId& target, Bytes& out) override {
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE w = 0, k = 0;
        if (Status s = find(kek, KeyType::Aes256, w); s != Status::Ok) return s;
        CK_KEY_TYPE kt = 0;
        if (Status s = resolve(target, k, kt); s != Status::Ok) return s;
        CK_BBOOL extractable = CK_FALSE;
        CK_ATTRIBUTE a{CKA_EXTRACTABLE, &extractable, sizeof extractable};
        if (fl_->C_GetAttributeValue(session_, k, &a, 1) != CKR_OK) return Status::Backend;
        if (!extractable) return Status::NotExtractable;
        CK_MECHANISM mech{CKM_AES_KEY_WRAP, nullptr, 0};
        out.assign(kWrapLen, 0);
        CK_ULONG len = out.size();
        CK_RV rv = fl_->C_WrapKey(session_, &mech, w, k, out.data(), &len);
        if (rv != CKR_OK) return map_rv(rv);
        out.resize(len);
        return Status::Ok;
    }

    Status unwrap(const KeyId& kek, uint32_t type, View blob, uint32_t flags, KeyId& out) override {
        if (!valid_type(type) || !valid_flags(flags) || blob.size() != kWrapLen) return Status::BadArg;
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE w = 0, h = 0;
        if (Status s = find(kek, KeyType::Aes256, w); s != Status::Ok) return s;
        auto t = static_cast<KeyType>(type);
        CK_MECHANISM mech{CKM_AES_KEY_WRAP, nullptr, 0};
        Template tpl(t, flags);
        CK_RV rv = fl_->C_UnwrapKey(session_, &mech, w, in_ptr(blob), blob.size(),
                                    tpl.data(), tpl.size(), &h);
        if (rv != CKR_OK) return map_auth_rv(rv);
        return assign_id(t, h, out);
    }

    Status hmac_sign(const KeyId& id, View msg, Mac& out) override {
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE h = 0;
        if (Status s = find(id, KeyType::HmacSha256, h); s != Status::Ok) return s;
        return sign_raw(h, msg, out);
    }

    Status hmac_verify(const KeyId& id, View msg, View tag) override {
        if (tag.size() != kMacLen) return Status::BadArg;
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE h = 0;
        if (Status s = find(id, KeyType::HmacSha256, h); s != Status::Ok) return s;
        CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
        CK_RV rv = fl_->C_VerifyInit(session_, &mech, h);
        if (rv != CKR_OK) return map_rv(rv);
        rv = fl_->C_Verify(session_, in_ptr(msg), msg.size(), in_ptr(tag), tag.size());
        return map_rv(rv);
    }

    Status seal(const KeyId& id, const uint8_t* nonce, View aad, View pt, Bytes& out) override {
        std::array<uint8_t, kNonceLen> n{};
        if (nonce) {
            if (is_reserved_nonce({nonce, kNonceLen})) return Status::BadArg;
            std::copy(nonce, nonce + kNonceLen, n.begin());
        }
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE h = 0;
        if (Status s = find(id, KeyType::Aes256, h); s != Status::Ok) return s;
        if (!nonce) {
            do {
                if (!prim::random_bytes(n)) return Status::Internal;
            } while (is_reserved_nonce(n));
        }
        Bytes ct;
        if (Status s = gcm_raw(h, n, aad, pt, ct); s != Status::Ok) return s;
        out.clear();
        out.insert(out.end(), n.begin(), n.end());
        out.insert(out.end(), ct.begin(), ct.end());
        return Status::Ok;
    }

    Status open(const KeyId& id, View aad, View sealed, Bytes& out) override {
        std::lock_guard g(mu_);
        CK_OBJECT_HANDLE h = 0;
        if (Status s = find(id, KeyType::Aes256, h); s != Status::Ok) return s;
        if (sealed.size() < kSealOverhead || is_reserved_nonce(sealed.first(kNonceLen)))
            return Status::VerifyFailed;
        View nonce = sealed.first(kNonceLen), body = sealed.subspan(kNonceLen);
        CK_GCM_PARAMS p = gcm_params(nonce, aad);
        CK_MECHANISM mech{CKM_AES_GCM, &p, sizeof p};
        CK_RV rv = fl_->C_DecryptInit(session_, &mech, h);
        if (rv != CKR_OK) return map_rv(rv);
        Bytes tmp(body.size());
        CK_ULONG len = tmp.size();
        rv = fl_->C_Decrypt(session_, in_ptr(body), body.size(), tmp.data(), &len);
        if (rv != CKR_OK) return map_auth_rv(rv);
        tmp.resize(len);
        out = std::move(tmp);
        return Status::Ok;
    }

    Status hkdf_derive(const KeyId&, View, View, uint32_t out_type, uint32_t out_flags, KeyId&) override {
        if (!valid_type(out_type) || !valid_flags(out_flags)) return Status::BadArg;
        // SoftHSM 2.6 has no CKM_HKDF_DERIVE (a PKCS#11 3.0 mechanism), and
        // deriving on the host would pull the base key out of the token.
        return Status::Unsupported;
    }

private:
    // Attribute template shared by generate / import / unwrap.
    struct Template {
        Template(KeyType t, uint32_t flags) {
            cls = CKO_SECRET_KEY;
            kt = t == KeyType::Aes256 ? CKK_AES : CKK_GENERIC_SECRET;
            extractable = (flags & kFlagExportable) ? CK_TRUE : CK_FALSE;
            add(CKA_CLASS, &cls, sizeof cls);
            add(CKA_KEY_TYPE, &kt, sizeof kt);
            add(CKA_TOKEN, &yes, sizeof yes);
            add(CKA_PRIVATE, &yes, sizeof yes);
            add(CKA_SENSITIVE, &yes, sizeof yes);
            add(CKA_EXTRACTABLE, &extractable, sizeof extractable);
            add(CKA_LABEL, const_cast<char*>(kLabel), sizeof kLabel - 1);
            if (t == KeyType::Aes256) {
                add(CKA_ENCRYPT, &yes, sizeof yes);
                add(CKA_DECRYPT, &yes, sizeof yes);
                add(CKA_WRAP, &yes, sizeof yes);
                add(CKA_UNWRAP, &yes, sizeof yes);
            } else {
                add(CKA_SIGN, &yes, sizeof yes);
                add(CKA_VERIFY, &yes, sizeof yes);
            }
        }
        void add(CK_ATTRIBUTE_TYPE type, void* p, CK_ULONG n) { attrs.push_back({type, p, n}); }
        CK_ATTRIBUTE* data() { return attrs.data(); }
        CK_ULONG size() const { return attrs.size(); }
        Template(const Template&) = delete;

        CK_OBJECT_CLASS cls;
        CK_KEY_TYPE kt;
        CK_BBOOL yes = CK_TRUE, extractable;
        std::vector<CK_ATTRIBUTE> attrs;
    };

    static CK_GCM_PARAMS gcm_params(View nonce, View aad) {
        CK_GCM_PARAMS p{};
        p.pIv = const_cast<uint8_t*>(nonce.data());
        p.ulIvLen = nonce.size();
        p.ulIvBits = nonce.size() * 8;
        p.pAAD = aad.empty() ? nullptr : in_ptr(aad);
        p.ulAADLen = aad.size();
        p.ulTagBits = kTagLen * 8;
        return p;
    }

    Status gcm_raw(CK_OBJECT_HANDLE h, View nonce, View aad, View pt, Bytes& out) {
        CK_GCM_PARAMS p = gcm_params(nonce, aad);
        CK_MECHANISM mech{CKM_AES_GCM, &p, sizeof p};
        CK_RV rv = fl_->C_EncryptInit(session_, &mech, h);
        if (rv != CKR_OK) return map_rv(rv);
        out.assign(pt.size() + kTagLen, 0);
        CK_ULONG len = out.size();
        rv = fl_->C_Encrypt(session_, in_ptr(pt), pt.size(), out.data(), &len);
        if (rv != CKR_OK) return map_rv(rv);
        out.resize(len);
        return Status::Ok;
    }

    Status sign_raw(CK_OBJECT_HANDLE h, View msg, Mac& out) {
        CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
        CK_RV rv = fl_->C_SignInit(session_, &mech, h);
        if (rv != CKR_OK) return map_rv(rv);
        CK_ULONG len = out.size();
        rv = fl_->C_Sign(session_, in_ptr(msg), msg.size(), out.data(), &len);
        if (rv != CKR_OK) return map_rv(rv);
        return len == out.size() ? Status::Ok : Status::Backend;
    }

    // Computes the KCV inside the token, then stamps CKA_ID. If that key is
    // already present, the fresh object is dropped and the existing ID kept.
    Status assign_id(KeyType t, CK_OBJECT_HANDLE h, KeyId& out) {
        Bytes kcv;
        Status s;
        if (t == KeyType::HmacSha256) {
            Mac m;
            s = sign_raw(h, {reinterpret_cast<const uint8_t*>(kKcvLabel.data()), kKcvLabel.size()}, m);
            kcv.assign(m.begin(), m.end());
        } else {
            s = gcm_raw(h, kKcvNonce, {reinterpret_cast<const uint8_t*>(kKcvLabel.data()), kKcvLabel.size()},
                        {}, kcv);
        }
        if (s != Status::Ok) {
            fl_->C_DestroyObject(session_, h);
            return s;
        }
        KeyId id = key_id_from_kcv(t, kcv);
        CK_OBJECT_HANDLE existing = 0;
        if (lookup(id, existing) == Status::Ok) {
            fl_->C_DestroyObject(session_, h);
        } else {
            CK_ATTRIBUTE a{CKA_ID, id.data(), id.size()};
            CK_RV rv = fl_->C_SetAttributeValue(session_, h, &a, 1);
            if (rv != CKR_OK) {
                fl_->C_DestroyObject(session_, h);
                return map_rv(rv);
            }
        }
        out = id;
        return Status::Ok;
    }

    Status lookup(const KeyId& id, CK_OBJECT_HANDLE& h) {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_ATTRIBUTE q[] = {{CKA_CLASS, &cls, sizeof cls}, {CKA_ID, const_cast<uint8_t*>(id.data()), id.size()}};
        CK_RV rv = fl_->C_FindObjectsInit(session_, q, 2);
        if (rv != CKR_OK) return map_rv(rv);
        CK_ULONG n = 0;
        rv = fl_->C_FindObjects(session_, &h, 1, &n);
        fl_->C_FindObjectsFinal(session_);
        if (rv != CKR_OK) return map_rv(rv);
        return n == 1 ? Status::Ok : Status::NoSuchKey;
    }

    // KeyId -> handle, with a cache. C_FindObjects is the dominant cost on
    // SoftHSM (~0.5 ms against ~50 us for the HMAC itself), so it runs only on
    // a miss. A hit is re-validated (CKA_ID + key type, one call): the spec
    // does not promise handles are never reused, and a stale handle that now
    // names a different key must not be used. Another library or process
    // destroying the key shows up here as an invalid handle -> full lookup.
    Status resolve(const KeyId& id, CK_OBJECT_HANDLE& h, CK_KEY_TYPE& kt) {
        if (auto it = cache_.find(id); it != cache_.end()) {
            uint8_t got[32];
            CK_ATTRIBUTE a[2] = {{CKA_ID, got, sizeof got}, {CKA_KEY_TYPE, &kt, sizeof kt}};
            if (fl_->C_GetAttributeValue(session_, it->second, a, 2) == CKR_OK && a[0].ulValueLen == id.size() &&
                std::memcmp(got, id.data(), id.size()) == 0) {
                h = it->second;
                return Status::Ok;
            }
            cache_.erase(it);
        }
        if (Status s = lookup(id, h); s != Status::Ok) return s;
        CK_ATTRIBUTE a{CKA_KEY_TYPE, &kt, sizeof kt};
        if (fl_->C_GetAttributeValue(session_, h, &a, 1) != CKR_OK) return Status::Backend;
        cache_[id] = h;
        return Status::Ok;
    }

    Status find(const KeyId& id, KeyType want, CK_OBJECT_HANDLE& h) {
        CK_KEY_TYPE kt = 0;
        if (Status s = resolve(id, h, kt); s != Status::Ok) return s;
        CK_KEY_TYPE expect = want == KeyType::Aes256 ? CKK_AES : CKK_GENERIC_SECRET;
        return kt == expect ? Status::Ok : Status::WrongKeyType;
    }

    void* lib_ = nullptr;
    CK_FUNCTION_LIST_PTR fl_ = nullptr;
    CK_SESSION_HANDLE session_ = 0;
    bool we_initialized_ = false;
    std::map<KeyId, CK_OBJECT_HANDLE> cache_;
    std::mutex mu_;
};

}  // namespace

std::unique_ptr<KeyStore> make_pkcs11_store(const std::string& module_path, const std::string& token_label,
                                            View pin, Status* err) {
    auto s = std::make_unique<Pkcs11Store>();
    Status st = s->init(module_path, token_label, pin);
    if (err) *err = st;
    if (st != Status::Ok) return nullptr;
    return s;
}

}  // namespace ccb
