// ============================================================================
//  edcf_falcon.h  —  FALCON-1024 (FN-DSA, NIST cat-5) via liboqs, header-only
// ----------------------------------------------------------------------------
//  Used for the non-anonymous PQ signatures of the trust layer:
//    * RSU detection certifications        Tx_det   (Eq 3.24)
//    * controller-write authorizations     Tx_ctrl  (Eq 3.25 multi-sig)
//
//  FALCON-1024 = the FN-DSA scheme being standardized as FIPS 206.
//    public key  ~1793 B,  signature up to ~1462 B,  NIST security category 5.
//
//  This file is a NO-OP unless EDCF_HAVE_FALCON is defined at compile time
//  (e.g. -DEDCF_HAVE_FALCON), so including it unconditionally is always safe
//  even on machines without liboqs installed -- the build simply won't see
//  any of the falcon1024_* symbols, and any routing.cc code that calls them
//  must itself be guarded by #ifdef EDCF_HAVE_FALCON (see integration guide
//  Section 5.4).
//
//  Build dep when enabled: -loqs -I<liboqs_prefix>/include -L<liboqs_prefix>/lib
//  See guide Section 4.3 for building liboqs from source.
// ============================================================================
#ifndef EDCF_FALCON_H
#define EDCF_FALCON_H
#include "edcf_crypto.h"

#ifdef EDCF_HAVE_FALCON
#include <oqs/oqs.h>
#include <stdexcept>

namespace edcf {

struct FalconKeypair { Bytes pk; Bytes sk; };

inline OQS_SIG* edcf_falcon_new_sig() {
    OQS_SIG* s = OQS_SIG_new(OQS_SIG_alg_falcon_1024);
    if (!s) throw std::runtime_error("FALCON-1024 unavailable in this liboqs build");
    return s;
}

inline FalconKeypair falcon1024_keygen() {
    OQS_SIG* s = edcf_falcon_new_sig();
    FalconKeypair kp;
    kp.pk.resize(s->length_public_key);
    kp.sk.resize(s->length_secret_key);
    if (OQS_SIG_keypair(s, kp.pk.data(), kp.sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(s); throw std::runtime_error("FALCON keypair failed");
    }
    OQS_SIG_free(s);
    return kp;
}

inline Bytes falcon1024_sign(const Bytes& sk, const Bytes& msg) {
    OQS_SIG* s = edcf_falcon_new_sig();
    Bytes sig(s->length_signature);
    size_t siglen = 0;
    OQS_STATUS r = OQS_SIG_sign(s, sig.data(), &siglen, msg.data(), msg.size(), sk.data());
    OQS_SIG_free(s);
    if (r != OQS_SUCCESS) throw std::runtime_error("FALCON sign failed");
    sig.resize(siglen);
    return sig;
}

inline bool falcon1024_verify(const Bytes& pk, const Bytes& msg, const Bytes& sig) {
    OQS_SIG* s = edcf_falcon_new_sig();
    OQS_STATUS r = OQS_SIG_verify(s, msg.data(), msg.size(), sig.data(), sig.size(), pk.data());
    OQS_SIG_free(s);
    return r == OQS_SUCCESS;
}

inline size_t falcon1024_pk_len()      { OQS_SIG* s=edcf_falcon_new_sig(); size_t n=s->length_public_key; OQS_SIG_free(s); return n; }
inline size_t falcon1024_sig_max_len() { OQS_SIG* s=edcf_falcon_new_sig(); size_t n=s->length_signature;  OQS_SIG_free(s); return n; }

} // namespace edcf

#endif // EDCF_HAVE_FALCON
#endif // EDCF_FALCON_H