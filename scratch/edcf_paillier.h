// ============================================================================
//  edcf_paillier.h  —  Paillier additive homomorphic encryption (GMP-backed)
// ----------------------------------------------------------------------------
//  Implements Eq 3.53-3.56 of the methodology for the Variant-2 cascading
//  alert pre-detection mitigation pipeline (Section 3.5.1):
//
//    Keygen:   n = p*q,  g = n+1 (standard simplification, lambda = (p-1)(q-1))
//    Encrypt:  c_i = g^{v_i} * r_i^n  mod n^2                        (Eq 3.53)
//    Aggregate (no decryption):  C_j = prod_i c_i  mod n^2           (Eq 3.54)
//    Decrypt:  S_j = L(C_j^lambda mod n^2) / L(g^lambda mod n^2) mod n
//                    where L(x) = (x-1)/n                            (Eq 3.56)
//
//  This is the SAME Paillier instance used (per Section 4.2.1) to faithfully
//  reproduce the Gyawali et al. [19] baseline pipeline for fair comparison;
//  it is explicitly the one classical (pre-quantum) primitive retained in
//  the otherwise category-5 trust layer, exactly as stated in the report.
//
//  Backend: GMP (mpz_t). Build: -lgmp
// ============================================================================
#ifndef EDCF_PAILLIER_H
#define EDCF_PAILLIER_H

#include <gmp.h>
#include <random>
#include <stdexcept>
#include <vector>
#include <string>

namespace edcf {
namespace paillier {

// ---------------------------------------------------------------------------
//  Public/private key material.
// ---------------------------------------------------------------------------
struct PublicKey  { mpz_t n, n2, g; };
struct PrivateKey { mpz_t lambda, mu, n, n2; };   // mu = L(g^lambda mod n^2)^{-1} mod n

// A ciphertext is just an mpz_t under n^2; we expose it as a decimal string
// for easy logging/transport over the existing routing.cc/Go REST plumbing.
using Ciphertext = std::string;

namespace detail {

inline void mpz_rand_init(mpz_t out, gmp_randstate_t& st, const mpz_t bound) {
    mpz_urandomm(out, st, bound);
}

// L(x) = (x - 1) / n   (exact integer division, valid since n | (x-1) by
// construction of the Paillier ciphertext space).
inline void L_function(mpz_t out, const mpz_t x, const mpz_t n) {
    mpz_t tmp; mpz_init(tmp);
    mpz_sub_ui(tmp, x, 1);
    mpz_tdiv_q(out, tmp, n);
    mpz_clear(tmp);
}

} // namespace detail

// ---------------------------------------------------------------------------
//  Keygen — two random `bits`-bit safe-ish primes (GMP's probable-prime
//  generator; sufficient for simulation-scale evaluation). g = n+1, the
//  standard Paillier simplification that avoids an extra discrete-log check.
// ---------------------------------------------------------------------------
inline void keygen(PublicKey& pub, PrivateKey& priv, unsigned bits = 1024) {
    mpz_init(pub.n);  mpz_init(pub.n2);  mpz_init(pub.g);
    mpz_init(priv.lambda); mpz_init(priv.mu); mpz_init(priv.n); mpz_init(priv.n2);

    gmp_randstate_t st;
    gmp_randinit_default(st);
    std::random_device rd;
    gmp_randseed_ui(st, ((uint64_t)rd() << 32) ^ rd());

    mpz_t p, q, p1, q1, gcdv;
    mpz_inits(p, q, p1, q1, gcdv, nullptr);

    // Sample two distinct probable primes of bits/2 each.
    do {
        mpz_urandomb(p, st, bits / 2);
        mpz_setbit(p, bits/2 - 1);              // ensure full bit length
        mpz_nextprime(p, p);
        mpz_urandomb(q, st, bits / 2);
        mpz_setbit(q, bits/2 - 1);
        mpz_nextprime(q, q);
    } while (mpz_cmp(p, q) == 0);

    mpz_mul(pub.n, p, q);                       // n = p*q
    mpz_mul(pub.n2, pub.n, pub.n);               // n^2
    mpz_add_ui(pub.g, pub.n, 1);                 // g = n+1

    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_lcm(priv.lambda, p1, q1);                // lambda = lcm(p-1, q-1)  (Eq 3.56)

    mpz_set(priv.n, pub.n);
    mpz_set(priv.n2, pub.n2);

    // mu = L(g^lambda mod n^2)^{-1} mod n  (with g = n+1, this is simply
    // lambda^{-1} mod n, but we compute it generally to keep the code
    // correct if g is ever changed away from the n+1 simplification.)
    mpz_t glambda, Lg;
    mpz_inits(glambda, Lg, nullptr);
    mpz_powm(glambda, pub.g, priv.lambda, pub.n2);
    detail::L_function(Lg, glambda, pub.n);
    if (mpz_invert(priv.mu, Lg, pub.n) == 0)
        throw std::runtime_error("paillier keygen: mu not invertible (bad prime pair, retry)");

    mpz_clears(p, q, p1, q1, gcdv, glambda, Lg, nullptr);
    gmp_randclear(st);
}

inline void free_keys(PublicKey& pub, PrivateKey& priv) {
    mpz_clears(pub.n, pub.n2, pub.g, nullptr);
    mpz_clears(priv.lambda, priv.mu, priv.n, priv.n2, nullptr);
}

// ---------------------------------------------------------------------------
//  Encrypt a single bit/small integer vote v_i (Eq 3.53):
//    c_i = g^{v_i} * r_i^n mod n^2,   r_i in Z_n^*
// ---------------------------------------------------------------------------
inline Ciphertext encrypt(const PublicKey& pub, long v_i) {
    gmp_randstate_t st;
    gmp_randinit_default(st);
    std::random_device rd;
    gmp_randseed_ui(st, ((uint64_t)rd() << 32) ^ rd());

    mpz_t r, gv, rn, c;
    mpz_inits(r, gv, rn, c, nullptr);

    // Sample r in Z_n^* (retry on the (astronomically unlikely) non-unit case).
    do { mpz_urandomm(r, st, pub.n); } while (mpz_sgn(r) == 0);

    mpz_powm_ui(gv, pub.g, (unsigned long)v_i, pub.n2);   // g^{v_i} mod n^2
    mpz_powm(rn, r, pub.n, pub.n2);                       // r^n     mod n^2
    mpz_mul(c, gv, rn);
    mpz_mod(c, c, pub.n2);

    char* buf = mpz_get_str(nullptr, 10, c);
    std::string out(buf);
    free(buf);

    mpz_clears(r, gv, rn, c, nullptr);
    gmp_randclear(st);
    return out;
}

// ---------------------------------------------------------------------------
//  Homomorphic aggregation without decryption (Eq 3.54):
//    C_j = prod_i c_i  mod n^2  =  Enc( sum_i v_i )
// ---------------------------------------------------------------------------
inline Ciphertext aggregate(const PublicKey& pub, const std::vector<Ciphertext>& cts) {
    mpz_t acc, ci;
    mpz_inits(acc, ci, nullptr);
    mpz_set_ui(acc, 1);
    for (const auto& s : cts) {
        mpz_set_str(ci, s.c_str(), 10);
        mpz_mul(acc, acc, ci);
        mpz_mod(acc, acc, pub.n2);
    }
    char* buf = mpz_get_str(nullptr, 10, acc);
    std::string out(buf);
    free(buf);
    mpz_clears(acc, ci, nullptr);
    return out;
}

// ---------------------------------------------------------------------------
//  Decrypt the aggregate to recover the plaintext vote count S_j (Eq 3.56):
//    S_j = L(C_j^lambda mod n^2) * mu  mod n
//  Performed ONLY by the RSU holding the Paillier private key (Algorithm 3,
//  line 10), never by the SDN controller, consistent with the
//  controller-decoupled write architecture (Section 3.4.6).
// ---------------------------------------------------------------------------
inline long decrypt(const PublicKey& pub, const PrivateKey& priv, const Ciphertext& Cj) {
    mpz_t c, clam, Lc, s;
    mpz_inits(c, clam, Lc, s, nullptr);
    mpz_set_str(c, Cj.c_str(), 10);
    mpz_powm(clam, c, priv.lambda, pub.n2);
    detail::L_function(Lc, clam, pub.n);
    mpz_mul(s, Lc, priv.mu);
    mpz_mod(s, s, pub.n);
    long out = mpz_get_si(s);
    mpz_clears(c, clam, Lc, s, nullptr);
    return out;
}

} // namespace paillier
} // namespace edcf
#endif // EDCF_PAILLIER_H
