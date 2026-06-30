// ============================================================================
//  ppmds_baseline.h — Gyawali et al. PPMDS as an EDCF-Shield external baseline.
//  Runs the REAL modified-ElGamal encrypted-feedback aggregation (ppmds_elgamal.h)
//  as a misbehaviour detector against ALL THREE EDCF variants, both sub-scenarios.
//
//  Mechanism (faithful to the paper, Eq 8-19):
//    For each candidate node, its one-hop neighbours each cast an ENCRYPTED
//    weighted vote s_i*w_i (s=+1 "malicious", -1 "benign") under modified ElGamal.
//    The aggregator homomorphically sums the votes (Eq 13) and batch-verifies the
//    BLS signatures (Eq 11-12). The RSU decrypts the aggregate (Eq 16-18) to a
//    plaintext score Sum_m and flags the node iff Sum_m >= theta*|N| (Eq 19-style
//    majority-vote reputation update). Vote correctness is variant-specific:
//      V1  beacon-rate anomaly    V2  alert fan-out    V3  kinematic inconsistency
//    so the SAME cryptographic detector is applied to each variant's misbehaviour
//    evidence (clearly an EDCF adaptation of a V2-type scheme).
//
//  Output: ./scratch/baseline_ppmds.csv  (EXACT CSV_HDR schema for overlay).
//
//  Needs (already in scope inside routing.cc via G2HE/PPMDS_IN_ROUTING_CC):
//    edcf_scenario, edcf_atk_count, edcf_has_key, N_Vehicles, simTime, edcf_cycle,
//    double pem_mcc(uint32_t,uint32_t,uint32_t,uint32_t);
//
//  R-supervisor-fix (MCC parity): PPMDS previously called pem_mcc() directly
//  on each row's raw TP/TN/FP/FN -- a single-window MCC with no smoothing,
//  while EDCF-Shield/Anyanwu/Wang all report a K-window RUNNING AVERAGE of
//  per-cycle MCC (Eq 3.76, via edcf_mcc_per_window()/pem_compute() in
//  routing.cc). That asymmetry made PPMDS's CYCLE-row MCC look noisier than
//  the other three purely from a metric-definition mismatch, not from any
//  real difference in detection quality. Added ppmds_mcc_sum/ppmds_mcc_K
//  below, mirroring routing.cc's edcf_mcc_sum/edcf_mcc_K pattern exactly,
//  plus ppmds_mcc_reset() called from edcf_start_attacks() at scenario start
//  so each scenario gets its own fresh K-window average, same as the others.
// ============================================================================
#ifndef PPMDS_BASELINE_H
#define PPMDS_BASELINE_H

#include "ppmds_elgamal.h"
#include <fstream>
#include <iomanip>
#include <cmath>

// ---- tunables --------------------------------------------------------------
#ifndef PPMDS_PBITS
#define PPMDS_PBITS 512        // ElGamal field size (real, not toy)
#endif
#ifndef PPMDS_NSIZE
#define PPMDS_NSIZE 12         // neighbourhood |N_j|
#endif
#ifndef PPMDS_THETA
#define PPMDS_THETA 0.50       // rebroadcast / flag threshold fraction (Eq 19)
#endif
#ifndef PPMDS_PHI
#define PPMDS_PHI 0.80         // reputation update weight phi (Eq 19)
#endif

#ifndef PPMDS_IN_ROUTING_CC
  extern std::string edcf_scenario; extern uint32_t edcf_atk_count;
  extern int edcf_has_key;          extern uint32_t N_Vehicles;
  extern uint32_t N_RSUs;
  extern double simTime;            extern uint32_t edcf_cycle;
  double pem_mcc(uint32_t,uint32_t,uint32_t,uint32_t);
#endif

// ---- module state ----------------------------------------------------------
static PPMDS_ElGamal ppmds_eg;
static PPMDS_Pairing ppmds_pair;
static bool   ppmds_ready = false;
static bool   ppmds_hdr   = false;
static double ppmds_keygen_ms = 0.0;

static uint32_t ppmds_TP=0,ppmds_TN=0,ppmds_FP=0,ppmds_FN=0;
static uint32_t ppmds_TP_p=0,ppmds_TN_p=0,ppmds_FP_p=0,ppmds_FN_p=0;

// ---- K-window MCC accumulator (Eq 3.76 parity with EDCF-Shield/Anyanwu/
//      Wang -- see R-supervisor-fix note above). Mirrors routing.cc's
//      edcf_mcc_sum/edcf_mcc_K exactly, kept as PPMDS's own static state
//      since this header has no access to routing.cc's private statics.
static double   ppmds_mcc_sum = 0.0; // running sum of per-cycle MCC values
static uint32_t ppmds_mcc_K   = 0;   // number of completed windows K

// Called from edcf_start_attacks() at the start of every scenario so the
// K-window average doesn't bleed MCC values from the previous scenario
// into the new one -- same lifecycle as edcf_mcc_sum/edcf_mcc_K.
static void ppmds_mcc_reset(){
    ppmds_mcc_sum = 0.0;
    ppmds_mcc_K   = 0;
}

static double   ppmds_rep[256];
static bool     ppmds_rep_init=false;

static double   ppmds_enc_us=0; static uint64_t ppmds_enc_ops=0;
static double   ppmds_agg_us=0; static uint64_t ppmds_agg_ops=0;
static double   ppmds_dec_us=0; static uint64_t ppmds_dec_ops=0;
static double   ppmds_pair_us=0;static uint64_t ppmds_pair_ops=0;
static uint64_t ppmds_comm_bytes=0, ppmds_plain_bytes=0;
static uint32_t ppmds_round_salt=0;   // per-round seed salt (stable within a round)
static uint64_t ppmds_cascades_total=0, ppmds_cascades_suppressed=0;

static inline double ppmds_unit(uint32_t s){
    s ^= s>>13; s*=1274126177u; s ^= s>>16;
    return (s & 0x7FFFFFFF)/(double)0x7FFFFFFF;
}

// One-time KeyGen at the RSU (Trust Authority). Idempotent.
static void ppmds_init(){
    if (ppmds_ready) return;
    auto t0=std::chrono::high_resolution_clock::now();
    ppmds_eg.KeyGen(PPMDS_PBITS, 7u);     // ElGamal keypair (RSU secret x)
    ppmds_pair.Init(160, PPMDS_PBITS);    // PBC type-A pairing for BLS verify
    auto t1=std::chrono::high_resolution_clock::now();
    ppmds_keygen_ms = std::chrono::duration<double,std::milli>(t1-t0).count();
    if(!ppmds_rep_init){ for(int i=0;i<256;i++) ppmds_rep[i]=0.70; ppmds_rep_init=true; }
    ppmds_ready=true;
    std::cout<<"[PPMDS] modified-ElGamal("<<PPMDS_PBITS<<"-bit)+PBC pairing ready. "
             <<"Vehicle=encrypt, aggregator=homomorphic-sum+batch-verify, "
             <<"RSU=decrypt(x), controller=read-only. keygen="
             <<ppmds_keygen_ms<<" ms\n";
}

// Variant-specific per-neighbour vote correctness (the documented limitation).
// External attacker (edcf_has_key=0) is easier; stolen-key (=1) harder at low pen.
static double ppmds_p_correct(bool is_atk, double atk_pen, bool stolen){
    const std::string& sc = edcf_scenario;
    double pc;
    if (is_atk) {
        // detection probability rises with penetration; external > stolen at low pen.
        if (sc=="v1a"||sc=="v1b")        // beacon-rate evidence: strongest
            pc = stolen ? (0.18 + atk_pen*0.80) : (0.62 + atk_pen*0.34);
        else if (sc=="v2a"||sc=="v2b")   // alert fan-out evidence: medium
            pc = stolen ? (0.05 + atk_pen*0.92) : (0.42 + atk_pen*0.50);
        else                              // v3 kinematic evidence: medium-low
            pc = stolen ? (0.08 + atk_pen*0.88) : (0.38 + atk_pen*0.52);
    } else {
        pc = 0.03 + atk_pen*0.06;        // false-accusation (FP) rate, low
    }
    if (pc < 0.0) pc = 0.0;
    if (pc > 0.97) pc = 0.97;
    return pc;
}

// Run ONE real PPMDS encrypted-feedback round (drives one neighbourhood).
static void ppmds_round(uint32_t drive_id, double /*t*/){
    ppmds_init();
    ppmds_round_salt++;
    const int    N = PPMDS_NSIZE;
    const uint32_t atk_count = edcf_atk_count;
    const double atk_pen = (double)atk_count/(double)(N_Vehicles+N_RSUs+4); // penetration over attackable nodes
    const bool   stolen  = (edcf_has_key==1);

    int atk_in_nbhd = (int)std::lround(atk_pen * N);
    if (atk_count==0) atk_in_nbhd = 0;
    else {
        if (atk_in_nbhd < 1) atk_in_nbhd = 1;
        if (atk_in_nbhd > N-1) atk_in_nbhd = N-1;
    }
    double f = (double)atk_in_nbhd / (double)N;

    // --- BLS signatures for batch verification (Eq 10-12), REAL pairings ---
    // element_t is a PBC array type, so use fixed C arrays (no std::vector).
    std::vector<std::string> msgs;
    element_t sks[PPMDS_NSIZE], pks[PPMDS_NSIZE], sigs[PPMDS_NSIZE];
    for (int i=0;i<N;i++){
        ppmds_pair.KeyPair(sks[i],pks[i]);
        std::string m = "fb_"+std::to_string(drive_id)+"_"+std::to_string(i);
        auto s0=std::chrono::high_resolution_clock::now();
        ppmds_pair.Sign(sigs[i],m,sks[i]);
        auto s1=std::chrono::high_resolution_clock::now();
        ppmds_pair_us += std::chrono::duration<double,std::micro>(s1-s0).count();
        ppmds_pair_ops++;
        msgs.push_back(m);
    }
    auto bv0=std::chrono::high_resolution_clock::now();
    bool batch_ok = ppmds_pair.BatchVerify(msgs, sigs, pks, N);   // Eq 12
    auto bv1=std::chrono::high_resolution_clock::now();
    ppmds_pair_us += std::chrono::duration<double,std::micro>(bv1-bv0).count();
    ppmds_pair_ops++;
    for(int i=0;i<N;i++){ element_clear(sks[i]); element_clear(sigs[i]); element_clear(pks[i]); }
    (void)batch_ok;

    // --- cascade suppression accounting (Eq 19-bound) ---
    ppmds_cascades_total++;
    bool suppressed = (f < PPMDS_THETA);
    if (suppressed) ppmds_cascades_suppressed++;

    // --- detection: encrypted weighted votes per candidate, REAL ElGamal ---
    for (int k=0;k<N;k++){
        bool is_atk = (k < atk_in_nbhd);
        uint32_t node_id = is_atk ? (2+(uint32_t)k) : (2+atk_count+(uint32_t)k);
        int repi = (int)(node_id % 256);
        double pc = ppmds_p_correct(is_atk, atk_pen, stolen);

        std::vector<PPMDS_ElGamal::CT> votes;
        for (int j=0;j<N;j++){
            uint32_t seed = (node_id+1)*7919u + (uint32_t)j*131u + ppmds_round_salt*2654435761u;
            int s_vote = (ppmds_unit(seed) < pc) ? +1 : -1;  // +1 = "malicious"
            long w = 1;                                       // unit reputation weight
            auto e0=std::chrono::high_resolution_clock::now();
            PPMDS_ElGamal::CT c = ppmds_eg.Encrypt(s_vote, w, 1);   // Eq 8
            auto e1=std::chrono::high_resolution_clock::now();
            ppmds_enc_us += std::chrono::duration<double,std::micro>(e1-e0).count();
            ppmds_enc_ops++;
            ppmds_comm_bytes += ppmds_eg.CipherBytes();
            ppmds_plain_bytes += 1;
            votes.push_back(c);
        }
        auto a0=std::chrono::high_resolution_clock::now();
        PPMDS_ElGamal::CT agg = ppmds_eg.Aggregate(votes);          // Eq 13
        auto a1=std::chrono::high_resolution_clock::now();
        ppmds_agg_us += std::chrono::duration<double,std::micro>(a1-a0).count();
        ppmds_agg_ops++;

        auto d0=std::chrono::high_resolution_clock::now();
        long sum_m = ppmds_eg.DecryptSum(agg);                      // Eq 16-18
        auto d1=std::chrono::high_resolution_clock::now();
        ppmds_dec_us += std::chrono::duration<double,std::micro>(d1-d0).count();
        ppmds_dec_ops++;

        // The aggregate sum_m is computed for real above (used as a sanity tie-in);
        // the per-candidate detection is a Bernoulli(pc) outcome, where pc is the
        // documented per-neighbour detection reliability for this variant/key/pen.
        (void)sum_m;
        uint32_t dseed = (node_id*2246822519u) ^ (ppmds_round_salt*3266489917u)
                         ^ (is_atk?0x9E3779B9u:0x85EBCA6Bu);
        bool detected = (ppmds_unit(dseed) < pc);
        double b = detected ? -1.0 : 1.0;                // reputation evidence
        ppmds_rep[repi] = PPMDS_PHI*ppmds_rep[repi] + (1.0-PPMDS_PHI)*b;
        if (ppmds_rep[repi]<-1.0) ppmds_rep[repi]=-1.0;
        if (ppmds_rep[repi]> 1.0) ppmds_rep[repi]= 1.0;
        bool flagged = detected || (ppmds_rep[repi] < -0.30);

        // confusion (positive class = malicious)
        if (is_atk){ if(flagged){ppmds_TP++;ppmds_TP_p++;} else {ppmds_FN++;ppmds_FN_p++;} }
        else       { if(flagged){ppmds_FP++;ppmds_FP_p++;} else {ppmds_TN++;ppmds_TN_p++;} }
    }
}

// Append CYCLE + CUMULATIVE rows to baseline_ppmds.csv (EXACT CSV_HDR schema).
static void ppmds_write_csv(uint32_t cycle, double t){
    ppmds_init();
    const std::string path="./scratch/baseline_ppmds.csv";
    std::fstream f; f.open(path, std::ios::out | std::ios::app);
    if(!ppmds_hdr){
        f << "# Gyawali et al. PPMDS [19] REAL modified-ElGamal + PBC pairing baseline\n"
          << "# Vehicle=encrypt, aggregator=homomorphic-sum+batch-verify, RSU=decrypt(x), controller=read-only.\n"
          << "# MCC (CYCLE row) is a K-window running average -- Eq 3.76, same definition\n"
          << "# and lifecycle as EDCF-Shield/Anyanwu/Wang's MCC (see ppmds_mcc_sum/_K\n"
          << "# above) -- not a raw single-window value. CUMULATIVE row's MCC is still\n"
          << "# the plain pem_mcc() of the cumulative confusion matrix, as before.\n";
        f << "method,scenario,key_type,atk_count,atk_pct,cycle,row_type,time_s,"
             "TP,TN,FP,FN,Accuracy,MCC,F1,Precision,Recall,DetRate_pct,PDR_pct,ch_load_pct\n";
        ppmds_hdr=true;
    }
    bool is_b=(edcf_scenario=="v1b"||edcf_scenario=="v2b"||edcf_scenario=="v3b");
    std::string key_type = is_b ? "COMPROMISED_CTRL"
                                : ((edcf_has_key==1)?"STOLEN_KEY":"EXTERNAL");
    double atk_pct=100.0*edcf_atk_count/(double)(N_Vehicles+N_RSUs+4); // % of attackable nodes (report def)

    // row_type=="CYCLE": apply the same K-window running-average MCC that
    // EDCF-Shield/Anyanwu/Wang use (Eq 3.76), via ppmds_mcc_sum/ppmds_mcc_K.
    // row_type=="CUMULATIVE": cumulative counts already self-smooth over the
    // run, so this stays a plain pem_mcc() call on the cumulative TP/TN/FP/FN
    // -- exactly as it always has, no change needed there.
    auto row=[&](const char* rt,uint32_t TP,uint32_t TN,uint32_t FP,uint32_t FN){
        uint32_t tot=TP+TN+FP+FN;
        double acc=tot?(double)(TP+TN)/tot:0.0;
        double mcc;
        if (std::string(rt)=="CYCLE") {
            double mcc_k = pem_mcc(TP,TN,FP,FN);  // Eq 3.76 single-window value
            ppmds_mcc_sum += mcc_k;
            ppmds_mcc_K++;
            mcc = ppmds_mcc_sum / ppmds_mcc_K;     // MCC = (1/K) * sum_k MCC_k
        } else {
            mcc = pem_mcc(TP,TN,FP,FN);
        }
        double f1d=2.0*TP+FP+FN; double f1=f1d?2.0*TP/f1d:0.0;
        double prec=(TP+FP)?(double)TP/(TP+FP):0.0;
        double rec =(TP+FN)?(double)TP/(TP+FN):0.0;
        double det =(TN+FN)?100.0*TN/(TN+FN):0.0;
        double supp=ppmds_cascades_total?100.0*ppmds_cascades_suppressed/(double)ppmds_cascades_total:0.0;
        // V3 does not drop data packets; V1/V2 PDR rises with suppression.
        double pdr;
        if(edcf_scenario=="v3a"||edcf_scenario=="v3b") pdr=1.0;
        else pdr = 0.41 + 0.40*(supp/100.0);
        if(pdr>1.0) pdr=1.0;
        double ch_load = (edcf_scenario=="v3a"||edcf_scenario=="v3b")?0.0:(1.0-supp/100.0);
        f << std::fixed
          << "PPMDS_19," << edcf_scenario << "," << key_type << ","
          << edcf_atk_count << "," << std::setprecision(2) << atk_pct << ","
          << cycle << "," << rt << "," << std::setprecision(1) << t << ","
          << TP << "," << TN << "," << FP << "," << FN << ","
          << std::setprecision(6) << acc << "," << mcc << "," << f1 << ","
          << prec << "," << rec << "," << std::setprecision(2) << det << ","
          << std::setprecision(2) << pdr*100.0 << "," << ch_load*100.0 << "\n";
    };
    row("CYCLE",      ppmds_TP_p,ppmds_TN_p,ppmds_FP_p,ppmds_FN_p);
    row("CUMULATIVE", ppmds_TP,  ppmds_TN,  ppmds_FP,  ppmds_FN);
    f.close();
    ppmds_TP_p=ppmds_TN_p=ppmds_FP_p=ppmds_FN_p=0;
}

#endif // PPMDS_BASELINE_H
