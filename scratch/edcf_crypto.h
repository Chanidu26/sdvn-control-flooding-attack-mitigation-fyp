// ============================================================================
//  edcf_crypto.h  —  EDCF-Shield category-5 cryptographic trust layer
// ----------------------------------------------------------------------------
//  Real, NIST post-quantum security category-5 primitives for the ns-3
//  SDVN simulation.  Replaces the simulated stubs in routing.cc
//  (HMAC-SHA-256/32-bit tag, djb2 "KDF", string "signatures").
//
//  Primitive            | Construction              | NIST cat. | Report eq.
//  ---------------------+---------------------------+-----------+-----------
//  Hash / Merkle        | SHA-512                   | 5         | 3.26
//  Message integrity    | HMAC-SHA-512, 256-bit tag | 5         | 3.21
//  Key derivation       | HKDF-SHA-512 (RFC 5869)   | 5         | 3.22
//  Key wrapping (LKH)   | AES-256-GCM               | 5         | 3.47/3.48
//  Threshold sharing    | Shamir 4-of-7 over F_p    | >5 (ITS)  | 3.3/3.4,3.42-3.44
//  PQ signatures        | FALCON-1024 (FN-DSA)      | 5         | 3.24/3.25
//                         -> see edcf_falcon.h
//
//  Backend: OpenSSL 3.x EVP (libcrypto).  Build: -lcrypto
// ============================================================================
#ifndef EDCF_CRYPTO_H
#define EDCF_CRYPTO_H

#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace edcf {

using Bytes = std::vector<uint8_t>;

// ---- security parameters (category 5) -------------------------------------
static constexpr size_t HMAC_KEY_LEN = 32;   // 256-bit key
static constexpr size_t HMAC_TAG_LEN = 32;   // 256-bit tag (full cat-5 width)
static constexpr size_t AES_KEY_LEN  = 32;   // AES-256
static constexpr size_t GCM_IV_LEN   = 12;   // 96-bit nonce (GCM standard)
static constexpr size_t GCM_TAG_LEN  = 16;   // 128-bit GCM auth tag
static constexpr int    DKG_T        = 4;    // reconstruction threshold
static constexpr int    DKG_N        = 7;    // designated DKG RSUs (one per grid zone)

// ---- utility ---------------------------------------------------------------
Bytes        random_bytes(size_t n);                       // CSPRNG (RAND_bytes)
std::string  to_hex(const Bytes& b);
Bytes        from_hex(const std::string& h);
inline Bytes to_bytes(const std::string& s){ return Bytes(s.begin(), s.end()); }

// ---- SHA-512  (Eq 3.26 ledger / Merkle hashing) ---------------------------
Bytes        sha512(const uint8_t* data, size_t len);
inline Bytes sha512(const Bytes& b){ return sha512(b.data(), b.size()); }
inline Bytes sha512(const std::string& s){ return sha512((const uint8_t*)s.data(), s.size()); }
std::string  sha512_hex(const std::string& s);

// ---- HMAC-SHA-512, 256-bit tag  (Eq 3.21  tau_i = HMAC_kg(m||ts||id)) ------
//  key MUST be 32 bytes (256-bit).  Returns a 32-byte (256-bit) tag.
Bytes        hmac_sha512_256(const Bytes& key32, const Bytes& msg);
std::string  hmac_sha512_256_hex(const Bytes& key32, const std::string& msg);
//  Constant-time verification (prevents timing oracles on the control plane).
bool         hmac_verify(const Bytes& key32, const Bytes& msg, const Bytes& tag);
bool         hmac_verify_hex(const Bytes& key32, const std::string& msg, const std::string& tag_hex);

// ---- HKDF-SHA-512  (Eq 3.22  k_g = KDF(k_root || "HMAC-AUTH")) -------------
Bytes        hkdf_sha512(const Bytes& ikm, const Bytes& salt,
                         const Bytes& info, size_t out_len);
//  Domain-separated group-key derivation used by lightweight-mode HMAC auth.
Bytes        derive_group_key(const Bytes& k_root);        // info = "EDCF-HMAC-AUTH"

// ---- AES-256-GCM  (LKH key wrapping, Eq 3.47/3.48) ------------------------
//  Output layout returned by wrap(): IV(12) || ciphertext || GCM_tag(16).
Bytes        aes256_gcm_wrap(const Bytes& key32, const Bytes& plaintext,
                             const Bytes& aad = {});
//  Returns true and fills out on success; false on auth-tag failure.
bool         aes256_gcm_unwrap(const Bytes& key32, const Bytes& wrapped,
                               Bytes& out, const Bytes& aad = {});

// ---- SHA-512 Merkle root  (Eq 3.26  MerkleRoot(t)=H(Tx1||...||TxN)) --------
//  Binary Merkle tree, duplicate-last-on-odd, leaf = SHA-512(tx_bytes).
Bytes        merkle_root_sha512(const std::vector<Bytes>& leaves);
std::string  merkle_root_hex(const std::vector<std::string>& tx_records);

// ---- Shamir threshold secret sharing  (Eq 3.3/3.4, DKG Eq 3.42-3.44) ------
//  Splits a 256-bit secret limb-wise over F_p (p = 2^61-1) into n shares,
//  any t of which reconstruct it.  Information-theoretically secure.
struct Share { int x; std::vector<uint64_t> y; };           // y = limbs at x
std::vector<Share> shamir_split(const Bytes& secret32, int t = DKG_T, int n = DKG_N);
Bytes              shamir_reconstruct(const std::vector<Share>& shares, size_t secret_len = 32);

} // namespace edcf  (forward declarations)

// ============================================================================
//  HEADER-ONLY IMPLEMENTATION (inline). Includes are deliberately OUTSIDE any
//  'namespace edcf' block -- nesting standard/OpenSSL headers inside a custom
//  namespace silently breaks libstdc++ (every std:: symbol resolves inside
//  edcf::std instead of the real ::std). This matches the sibling-header
//  pattern already used in routing.cc (e.g. ppmds_baseline.h).
// ============================================================================

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>

#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace edcf {

// ---------------------------------------------------------------------------
//  utilities
// ---------------------------------------------------------------------------
inline Bytes random_bytes(size_t n) {
    Bytes b(n);
    if (RAND_bytes(b.data(), (int)n) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return b;
}

inline std::string to_hex(const Bytes& b) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (uint8_t c : b) os << std::setw(2) << (int)c;
    return os.str();
}

inline Bytes from_hex(const std::string& h) {
    Bytes b;
    b.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        b.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
    return b;
}

// ---------------------------------------------------------------------------
//  SHA-512  (Eq 3.26)
// ---------------------------------------------------------------------------
inline Bytes sha512(const uint8_t* data, size_t len) {
    Bytes out(SHA512_DIGEST_LENGTH);            // 64
    unsigned int olen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("MD_CTX_new");
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, out.data(), &olen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("sha512 failed");
    }
    EVP_MD_CTX_free(ctx);
    out.resize(olen);
    return out;
}

inline std::string sha512_hex(const std::string& s) { return to_hex(sha512(s)); }

// ---------------------------------------------------------------------------
//  HMAC-SHA-512 truncated to a 256-bit tag  (Eq 3.21)
//
//  Forgery resistance = min(key 256, tag 256, SHA-512 internal) = 256-bit
//  -> NIST category 5.  The 64-byte HMAC-SHA-512 output is truncated to the
//  leftmost 32 bytes (NIST SP 800-107 §5.3.1 permits left-truncation; we keep
//  the full category-5 width of 256 bits rather than truncating further).
// ---------------------------------------------------------------------------
inline Bytes hmac_sha512_256(const Bytes& key32, const Bytes& msg) {
    if (key32.size() != HMAC_KEY_LEN)
        throw std::runtime_error("hmac: key must be 32 bytes (256-bit)");
    unsigned char full[EVP_MAX_MD_SIZE];
    unsigned int  flen = 0;
    if (!HMAC(EVP_sha512(), key32.data(), (int)key32.size(),
              msg.data(), msg.size(), full, &flen))
        throw std::runtime_error("HMAC failed");
    return Bytes(full, full + HMAC_TAG_LEN);    // leftmost 256 bits
}

inline std::string hmac_sha512_256_hex(const Bytes& key32, const std::string& msg) {
    return to_hex(hmac_sha512_256(key32, to_bytes(msg)));
}

inline bool hmac_verify(const Bytes& key32, const Bytes& msg, const Bytes& tag) {
    Bytes expect = hmac_sha512_256(key32, msg);
    if (tag.size() != expect.size()) return false;
    return CRYPTO_memcmp(expect.data(), tag.data(), expect.size()) == 0; // constant-time
}

inline bool hmac_verify_hex(const Bytes& key32, const std::string& msg, const std::string& tag_hex) {
    return hmac_verify(key32, to_bytes(msg), from_hex(tag_hex));
}

// ---------------------------------------------------------------------------
//  HKDF-SHA-512  (RFC 5869) — Eq 3.22
// ---------------------------------------------------------------------------
inline Bytes hkdf_sha512(const Bytes& ikm, const Bytes& salt,
                  const Bytes& info, size_t out_len) {
    Bytes out(out_len);
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) throw std::runtime_error("HKDF fetch");
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA512", 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    (void*)ikm.data(), ikm.size());
    if (!salt.empty())
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                        (void*)salt.data(), salt.size());
    if (!info.empty())
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                        (void*)info.data(), info.size());
    params[p] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out.data(), out_len, params) != 1) {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("HKDF derive failed");
    }
    EVP_KDF_CTX_free(kctx);
    return out;
}

inline Bytes derive_group_key(const Bytes& k_root) {
    // Eq 3.22: k_g = KDF(k_root || "HMAC-AUTH"); label as HKDF `info` field.
    static const std::string LABEL = "EDCF-HMAC-AUTH";
    return hkdf_sha512(k_root, /*salt=*/{}, to_bytes(LABEL), HMAC_KEY_LEN);
}

// ---------------------------------------------------------------------------
//  AES-256-GCM  (LKH key wrapping, Eq 3.47/3.48)
//  wrapped = IV(12) || ciphertext || tag(16)
// ---------------------------------------------------------------------------
inline Bytes aes256_gcm_wrap(const Bytes& key32, const Bytes& pt, const Bytes& aad) {
    if (key32.size() != AES_KEY_LEN)
        throw std::runtime_error("aes: key must be 32 bytes");
    Bytes iv = random_bytes(GCM_IV_LEN);
    Bytes ct(pt.size());
    Bytes tag(GCM_TAG_LEN);
    int len = 0, ctlen = 0;

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr);
    EVP_EncryptInit_ex(c, nullptr, nullptr, key32.data(), iv.data());
    if (!aad.empty())
        EVP_EncryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size());
    EVP_EncryptUpdate(c, ct.data(), &len, pt.data(), (int)pt.size());
    ctlen = len;
    EVP_EncryptFinal_ex(c, ct.data() + ctlen, &len);
    ctlen += len;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag.data());
    EVP_CIPHER_CTX_free(c);

    Bytes out;
    out.reserve(GCM_IV_LEN + ctlen + GCM_TAG_LEN);
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.begin() + ctlen);
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

inline bool aes256_gcm_unwrap(const Bytes& key32, const Bytes& wrapped, Bytes& out, const Bytes& aad) {
    if (key32.size() != AES_KEY_LEN) return false;
    if (wrapped.size() < GCM_IV_LEN + GCM_TAG_LEN) return false;
    const uint8_t* iv  = wrapped.data();
    const uint8_t* ct  = wrapped.data() + GCM_IV_LEN;
    size_t ctlen       = wrapped.size() - GCM_IV_LEN - GCM_TAG_LEN;
    const uint8_t* tag = wrapped.data() + GCM_IV_LEN + ctlen;

    out.assign(ctlen, 0);
    int len = 0;
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr);
    EVP_DecryptInit_ex(c, nullptr, nullptr, key32.data(), iv);
    if (!aad.empty())
        EVP_DecryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size());
    EVP_DecryptUpdate(c, out.data(), &len, ct, (int)ctlen);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag);
    int ok = EVP_DecryptFinal_ex(c, out.data() + len, &len);   // verifies tag
    EVP_CIPHER_CTX_free(c);
    if (ok != 1) { out.clear(); return false; }
    return true;
}

// ---------------------------------------------------------------------------
//  SHA-512 Merkle root  (Eq 3.26)
// ---------------------------------------------------------------------------
inline Bytes merkle_root_sha512(const std::vector<Bytes>& leaves) {
    if (leaves.empty()) return sha512(Bytes{});
    std::vector<Bytes> level;
    level.reserve(leaves.size());
    for (const auto& l : leaves) level.push_back(sha512(l));   // leaf = H(tx)
    while (level.size() > 1) {
        std::vector<Bytes> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            const Bytes& a = level[i];
            const Bytes& b = (i + 1 < level.size()) ? level[i + 1] : level[i]; // dup last
            Bytes cat = a; cat.insert(cat.end(), b.begin(), b.end());
            next.push_back(sha512(cat));
        }
        level.swap(next);
    }
    return level[0];
}

inline std::string merkle_root_hex(const std::vector<std::string>& tx_records) {
    std::vector<Bytes> leaves;
    leaves.reserve(tx_records.size());
    for (const auto& s : tx_records) leaves.push_back(to_bytes(s));
    return to_hex(merkle_root_sha512(leaves));
}

// ---------------------------------------------------------------------------
//  Shamir threshold secret sharing over F_p, p = 2^61 - 1  (Eq 3.3/3.4,3.42-3.44)
//  256-bit secret is split into 56-bit limbs (each < p) and shared limb-wise.
// ---------------------------------------------------------------------------
namespace {
constexpr uint64_t P = (1ULL << 61) - 1;       // Mersenne prime 2^61-1
constexpr int LIMB_BYTES = 7;                  // 56 bits < 61

inline uint64_t addm(uint64_t a, uint64_t b){ uint64_t s=a+b; return s>=P?s-P:s; }
inline uint64_t mulm(uint64_t a, uint64_t b){ return (uint64_t)(((__uint128_t)a*b)%P); }
uint64_t powm(uint64_t a, uint64_t e){ uint64_t r=1; a%=P; while(e){ if(e&1)r=mulm(r,a); a=mulm(a,a); e>>=1;} return r; }
inline uint64_t invm(uint64_t a){ return powm(a, P-2); }   // Fermat inverse

// Pads `s` on the right with zero bytes up to a multiple of LIMB_BYTES before
// splitting into big-endian limbs, so every limb (including the last) is
// exactly LIMB_BYTES wide. Reconstruction therefore always emits
// ceil(len/LIMB_BYTES)*LIMB_BYTES bytes, which the caller truncates back to
// secret_len. Right-padding the byte stream (not left-padding the limb
// value) keeps limb concatenation order-preserving on the way back.
std::vector<uint64_t> to_limbs(const Bytes& s){
    std::vector<uint64_t> limbs;
    for (size_t i=0;i<s.size();i+=LIMB_BYTES){
        uint64_t v=0;
        for (size_t j=0;j<(size_t)LIMB_BYTES;++j){
            uint8_t byte = (i+j<s.size()) ? s[i+j] : 0;   // zero-pad on the right
            v=(v<<8)|byte;
        }
        limbs.push_back(v % P);
    }
    return limbs;
}
} // namespace

inline std::vector<Share> shamir_split(const Bytes& secret32, int t, int n) {
    auto limbs = to_limbs(secret32);
    std::vector<Share> shares(n);
    for (int xi = 1; xi <= n; ++xi) { shares[xi-1].x = xi; shares[xi-1].y.resize(limbs.size()); }
    for (size_t li = 0; li < limbs.size(); ++li) {
        // random degree-(t-1) polynomial, constant term = secret limb (Eq 3.3/3.42)
        std::vector<uint64_t> coeff(t);
        coeff[0] = limbs[li];
        Bytes rnd = random_bytes(8 * (t-1));
        for (int k = 1; k < t; ++k) {
            uint64_t c=0; memcpy(&c, rnd.data()+8*(k-1), 8); coeff[k] = c % P;
        }
        for (int xi = 1; xi <= n; ++xi) {              // evaluate f(xi)
            uint64_t acc = 0, xp = 1;
            for (int k = 0; k < t; ++k) { acc = addm(acc, mulm(coeff[k], xp)); xp = mulm(xp, xi); }
            shares[xi-1].y[li] = acc;
        }
    }
    return shares;
}

inline Bytes shamir_reconstruct(const std::vector<Share>& shares, size_t secret_len) {
    if ((int)shares.size() < DKG_T) throw std::runtime_error("need >= t shares");
    size_t nlimbs = shares[0].y.size();
    std::vector<uint64_t> secret(nlimbs, 0);
    int t = DKG_T;
    for (size_t li = 0; li < nlimbs; ++li) {
        uint64_t acc = 0;
        for (int i = 0; i < t; ++i) {                  // Lagrange at x=0 (Eq 3.44)
            uint64_t num = 1, den = 1;
            for (int j = 0; j < t; ++j) {
                if (i == j) continue;
                num = mulm(num, (uint64_t)(P - (uint64_t)shares[j].x)); // (0 - x_j)
                uint64_t diff = (shares[i].x >= shares[j].x)
                              ? (uint64_t)(shares[i].x - shares[j].x)
                              : (uint64_t)(P - (shares[j].x - shares[i].x));
                den = mulm(den, diff);
            }
            uint64_t lag = mulm(num, invm(den));
            acc = addm(acc, mulm(shares[i].y[li], lag));
        }
        secret[li] = acc;
    }
    // limbs -> bytes
    Bytes out;
    for (size_t li = 0; li < nlimbs; ++li)
        for (int b = LIMB_BYTES - 1; b >= 0; --b)
            out.push_back((uint8_t)((secret[li] >> (8*b)) & 0xFF));
    out.resize(secret_len);
    return out;
}
} // namespace edcf
#endif // EDCF_CRYPTO_H