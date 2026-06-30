// ============================================================================
//  ppmds_elgamal.h  —  Gyawali et al. PPMDS modified-ElGamal cryptographic core
//  ("A Privacy-Preserving Misbehavior Detection System in Vehicular
//   Communication Networks", IEEE TVT 70(6):6147-6158, 2021).
//
//  Implements the paper's scheme with REAL arithmetic:
//    - Modified ElGamal encrypt / homomorphic-aggregate / decrypt  (Eq 8,13,16-18)
//      over a prime-order subgroup using GMP (mpz_t) — no toy primes.
//    - BLS-style signature + bilinear batch verification            (Eq 10-12)
//      using the PBC pairing library (real e(.,.) on a type-A curve).
//
//  Dependencies:  libgmp/libgmpxx  AND  libpbc  (Stanford PBC).
//  Build flags:   -lpbc -lgmp -lgmpxx
//
//  SDVN role mapping (your zero-trust EDCF-Shield topology):
//     Vehicle           -> Encrypt weighted feedback (public key)      Eq 8
//     Neighbourhood Aggr-> Homomorphic product, batch-verify sigs      Eq 12,13
//     RSU (Trust Plane) -> hold TA secret x; Decrypt aggregate         Eq 16-18
//     Controller        -> read-only (zero-trust); never holds x
// ============================================================================
#ifndef PPMDS_ELGAMAL_H
#define PPMDS_ELGAMAL_H

#include <gmpxx.h>
#include <pbc/pbc.h>          // PBC pairing library
#include <vector>
#include <string>
#include <chrono>
#include <cstdint>

// ----------------------------------------------------------------------------
//  Modified-ElGamal over Z_p^* prime-order-q subgroup (GMP).  Eq 8,13,16-18.
// ----------------------------------------------------------------------------
class PPMDS_ElGamal
{
public:
    mpz_class p, q, g;       // field prime p=2q+1, generator g of order q
    mpz_class x, gx;         // TA/RSU secret x ; public g^x  (Tpk)
    unsigned int p_bits = 512;
    bool initialised = false;
    gmp_randclass rng{gmp_randinit_default};

    struct CT { mpz_class F1, F2, F3; };   // Eq 8 ciphertext triple

    PPMDS_ElGamal() {}

    // ---- KeyGen at the RSU (Trust Authority). x is the private key. --------
    void KeyGen(unsigned int bits = 512, unsigned long seed = 0)
    {
        p_bits = bits;
        if (seed == 0) seed = (unsigned long) time(nullptr);
        rng.seed(seed);
        // safe prime p = 2q + 1
        mpz_class qc;
        do {
            mpz_class cand = rng.get_z_bits(bits - 1);
            mpz_nextprime(qc.get_mpz_t(), cand.get_mpz_t());
            p = 2*qc + 1;
        } while (!mpz_probab_prime_p(p.get_mpz_t(), 25));
        q = qc;
        // generator of order-q subgroup: h^2 mod p
        mpz_class h = rng.get_z_range(p - 3) + 2, g2;
        mpz_powm_ui(g2.get_mpz_t(), h.get_mpz_t(), 2, p.get_mpz_t());
        g = g2;
        x  = rng.get_z_range(q - 2) + 1;
        mpz_powm(gx.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
        initialised = true;
    }

    // ---- Encrypt weighted feedback at a VEHICLE (public key only). Eq 8 ----
    //   s in {+1 (malicious vote), -1 (benign vote)};  w = reputation weight.
    //   m = s*w ; M = g^m ; F = (k w g^r, k w g^{xr} M, g^{xr}).
    CT Encrypt(long s, long w, const mpz_class& k)
    {
        mpz_class r  = rng.get_z_range(q - 2) + 1;
        mpz_class gr, gxr;
        mpz_powm(gr.get_mpz_t(),  g.get_mpz_t(),  r.get_mpz_t(), p.get_mpz_t());
        mpz_powm(gxr.get_mpz_t(), gx.get_mpz_t(), r.get_mpz_t(), p.get_mpz_t());
        long m = s * w;
        mpz_class M = gpow_signed(m);
        mpz_class kw = (k * w) % p;
        CT c;
        c.F1 = (kw * gr) % p;
        c.F2 = (((kw * gxr) % p) * M) % p;
        c.F3 = gxr;
        return c;
    }

    // ---- Homomorphic aggregation at the AGGREGATOR (no secret key). Eq 13 --
    CT Aggregate(const std::vector<CT>& v) const
    {
        CT a; a.F1 = 1; a.F2 = 1; a.F3 = 1;
        for (const auto& c : v) {
            a.F1 = (a.F1 * c.F1) % p;
            a.F2 = (a.F2 * c.F2) % p;
            a.F3 = (a.F3 * c.F3) % p;
        }
        return a;
    }

    // ---- Decrypt aggregate at the RSU (needs x). Eq 16-18 ------------------
    //  D1=(P3)^{1/x}=g^{sum r};  D2=P1/D1=prod(k w);  Af=P2/(D2 P3)=g^{sum m}.
    //  Returns sum_m = sum(s_i w_i) by short discrete-log search.
    long DecryptSum(const CT& P, long lo = -400, long hi = 400) const
    {
        mpz_class xinv;  mpz_invert(xinv.get_mpz_t(), x.get_mpz_t(), q.get_mpz_t());
        mpz_class D1;    mpz_powm(D1.get_mpz_t(), P.F3.get_mpz_t(), xinv.get_mpz_t(), p.get_mpz_t());
        mpz_class D1inv; mpz_invert(D1inv.get_mpz_t(), D1.get_mpz_t(), p.get_mpz_t());
        mpz_class D2 = (P.F1 * D1inv) % p;                 // prod(k w)
        mpz_class D2inv; mpz_invert(D2inv.get_mpz_t(), D2.get_mpz_t(), p.get_mpz_t());
        mpz_class P3inv; mpz_invert(P3inv.get_mpz_t(), P.F3.get_mpz_t(), p.get_mpz_t());
        mpz_class Af = (((P.F2 * D2inv) % p) * P3inv) % p; // g^{sum m}
        for (long m = lo; m <= hi; m++)
            if (gpow_signed(m) == Af) return m;
        return -999999;                                   // out of search range
    }

    // serialised ciphertext size in bytes (3 group elements) for comm overhead
    size_t CipherBytes() const { return 3 * ((p_bits + 7) / 8); }

private:
    mpz_class gpow_signed(long m) const {
        mpz_class out;
        if (m >= 0) mpz_powm_ui(out.get_mpz_t(), g.get_mpz_t(), (unsigned long)m, p.get_mpz_t());
        else { mpz_class gm; mpz_powm_ui(gm.get_mpz_t(), g.get_mpz_t(), (unsigned long)(-m), p.get_mpz_t());
               mpz_invert(out.get_mpz_t(), gm.get_mpz_t(), p.get_mpz_t()); }
        return out;
    }
};

// ----------------------------------------------------------------------------
//  PBC pairing layer — BLS signature + bilinear batch verification (Eq 10-12).
//  Real e(.,.) on a type-A symmetric curve. One instance per simulation.
// ----------------------------------------------------------------------------
class PPMDS_Pairing
{
public:
    pairing_t pairing;
    element_t g_;                 // system generator in G
    bool ready = false;

    // Type-A pairing parameters (rbits=160, qbits=512) generated at init.
    // PBC can build these in-process via pbc_param_init_a_gen.
    void Init(int rbits = 160, int qbits = 512)
    {
        pbc_param_t par;
        pbc_param_init_a_gen(par, rbits, qbits);
        pairing_init_pbc_param(pairing, par);
        element_init_G1(g_, pairing);
        element_random(g_);
        pbc_param_clear(par);
        ready = true;
    }

    // Per-vehicle BLS keypair: sk in Zr, pk = g^sk in G.  (paper Vsk_i,Vpk_i)
    void KeyPair(element_t sk, element_t pk)
    {
        element_init_Zr(sk, pairing); element_random(sk);
        element_init_G1(pk, pairing); element_pow_zn(pk, g_, sk);
    }

    // Sign: sigma = H(m)^sk  (BLS).  H(m) hashed to G1.   Eq 10
    void Sign(element_t sigma, const std::string& msg, element_t sk)
    {
        element_t h; element_init_G1(h, pairing);
        element_from_hash(h, (void*)msg.data(), (int)msg.size());
        element_init_G1(sigma, pairing);
        element_pow_zn(sigma, h, sk);
        element_clear(h);
    }

    // Batch verify: e(prod sigma_i, g) == prod e(H(m_i), pk_i).   Eq 11-12
    // element_t is an array type, so pass raw arrays + count (PBC idiom).
    bool BatchVerify(const std::vector<std::string>& msgs,
                     element_t* sigs, element_t* pks, int cnt)
    {
        element_t lhs, rhs, prod_sig, tmp, h;
        element_init_GT(lhs, pairing); element_init_GT(rhs, pairing);
        element_init_GT(tmp, pairing); element_init_G1(prod_sig, pairing);
        element_init_G1(h, pairing);
        element_set1(prod_sig);
        for (int i=0;i<cnt;i++) element_mul(prod_sig, prod_sig, sigs[i]); // prod sigma_i
        pairing_apply(lhs, prod_sig, g_, pairing);                 // e(prod sig, g)
        element_set1(rhs);
        for (int i = 0; i < cnt; i++) {
            element_from_hash(h, (void*)msgs[i].data(), (int)msgs[i].size());
            pairing_apply(tmp, h, pks[i], pairing);                // e(H(m_i), pk_i)
            element_mul(rhs, rhs, tmp);
        }
        bool ok = !element_cmp(lhs, rhs);
        element_clear(lhs); element_clear(rhs); element_clear(tmp);
        element_clear(prod_sig); element_clear(h);
        return ok;
    }
};

#endif // PPMDS_ELGAMAL_H
