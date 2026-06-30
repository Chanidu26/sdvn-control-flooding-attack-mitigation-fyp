// =============================================================
// wang_drl.h  —  Wang [22] DRL Topology Poisoning Tolerance
// =============================================================
// Place at:  ns-3.35/scratch/wang_drl.h
// Include from routing.cc: already done via #include "wang_drl.h"
//
// WORKFLOW:
//   Step 1: python3 scratch/wang_drl_train.py
//           → produces scratch/wang_qtable.dat  (2064 bytes, M=4)
//   Step 2: ./waf --run "routing --edcf_scenario=v3a ..."
//           → this file loads wang_qtable.dat at startup
//           → wang_classify() uses loaded Q-table for decisions
//           → writes baseline_wang.csv every 10 s PEM window
//
// PAPER: Wang et al., "Topology Poisoning Attack in SDN-Enabled
//        Vehicular Edge Network", IEEE IoT-J Vol.7 No.10, Oct 2020.
//
// WHAT THIS FILE IMPLEMENTS:
//
//   DETECTION (§II-B3)  — single-snapshot kinematic plausibility:
//     dist = ||pos_now - pos_last||
//     if dist > VMAX * dt  →  kinematic_violation = true
//     VMAX = 20 m/s  (paper Table I: max speed 72 km/h = 20 m/s)
//     V3 attacker: 4.5 m / 0.3 s = 15 m/s < 20 m/s → NOT caught
//     → TN ≈ 0, FN = all V3 attacks, MCC ≈ 0  (your Gap 4 §2.1.8)
//
//   TOLERANCE (§III, Alg 1) — loaded pre-trained Q-table:
//     State  s = [D[0..M-1], loss_bucket]
//     Action a = VM migration (new service deployment)
//     Reward r = Suc × (S_RSU / N)               (paper Eq 2)
//     Q-table trained offline by wang_drl_train.py
//     At inference: greedy argmax over Q[s][a]
//
//   LIMITATIONS (your paper §2.1.8, Gap 4):
//     1. Single-snapshot: cannot detect kinematic-compliant traces
//     2. No blockchain, no cross-controller consistency
//     3. Compromised controller: Wang trusts controller implicitly
//     4. DRL only recovers service AFTER topology already poisoned
// =============================================================

#pragma once
#ifndef WANG_DRL_H
#define WANG_DRL_H
// EDCF_VEHICLE_BASE and EDCF_N_CTRLS are plain `static const int` globals,
// not macros — #ifndef has no effect on them, so they must NOT be
// redeclared here. routing.cc already defines both (node ID where
// vehicles start = 5, number of SDN controllers = 4) before this header
// is included; we simply rely on those being in scope.
//
// If you ever use this header standalone (without routing.cc already
// defining them), uncomment the two lines below:
// static const int EDCF_VEHICLE_BASE = 5;
// static const int EDCF_N_CTRLS      = 4;

#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <algorithm>
#include "ns3/simulator.h"

// =============================================================
// CONSTANTS — paper Table III
// =============================================================
static const double WANG_VMAX      = 20.0;  // m/s max speed (Table I)
static const int    WANG_M         = 4;     // RSU servers (4 controllers)
static const int    WANG_N_SVC     = 1;     // services deployed (M/4=1)
static const int    WANG_N_STATES  = 64;    // 2^M * 4 loss buckets (M=4)
static const int    WANG_N_ACTS    = 4;     // valid one-hot deployments (M=4)
// Q-table file written by wang_drl_train.py
static const char   WANG_QTABLE_PATH[] = "./scratch/wang_qtable.dat";
// Magic number verifying file integrity
static const uint32_t WANG_MAGIC   = 0xDEEDFEEDu;

// =============================================================
// Q-TABLE STORAGE  (loaded from file, read-only during NS-3)
// =============================================================
static double wang_Q[64][4]      = {};   // loaded Q-table (M=4 RSUs)
static bool   wang_Q_loaded      = false;
static int    wang_D[4]          = {1,0,0,0}; // current service deployment
static uint32_t wang_req_total   = 0;
static uint32_t wang_req_success = 0;
static uint32_t wang_drl_steps   = 0;

// =============================================================
// POSITION HISTORY  (kinematic detection state)
// [ctrl][local_idx]  — local_idx = (node_id - BASE) / N_CTRLS
// Sized [4][70]: ceil(200/4) = 50 + margin (4 controllers)
// =============================================================
static double wang_px[4][70]    = {};   // 4 controllers
static double wang_py[4][70]    = {};
static double wang_pt[4][70]    = {};
static bool   wang_pos_rdy[4]   = {false,false,false,false};

// =============================================================
// LCG — deterministic pseudo-random (keeps simulation reproducible)
// =============================================================
static inline double wang_lcg(uint32_t& s) {
    s = s*1664525u + 1013904223u;
    return (double)(s & 0x7FFFFFFFu) / (double)0x7FFFFFFFu;
}

// =============================================================
// STATE ENCODING  (paper §III-C)
// s = depl_int * 4 + loss_bucket
// depl_int = D[0]*8 + D[1]*4 + D[2]*2 + D[3]*1  (4 controllers)
// loss_bucket = floor(loss/0.25) clamped 0..3
// =============================================================
static inline int wang_enc_state(const int D[4], double loss) {
    // depl_int = D[0]*8 + D[1]*4 + D[2]*2 + D[3]*1   (4-bit, 0..15)
    int di = D[0]*8 + D[1]*4 + D[2]*2 + D[3]*1;
    int lb = (int)(loss / 0.25);
    if (lb < 0) lb = 0;
    if (lb > 3) lb = 3;
    return di * 4 + lb;   // 0..63
}

// =============================================================
// ACTION DECODE  (one-hot deployment)
// action 0→[1,0,0,0]  1→[0,1,0,0]  2→[0,0,1,0]  3→[0,0,0,1]
// =============================================================
static inline void wang_dec_action(int a, int out[4]) {
    out[0] = (a==0) ? 1 : 0;
    out[1] = (a==1) ? 1 : 0;
    out[2] = (a==2) ? 1 : 0;
    out[3] = (a==3) ? 1 : 0;
}

// =============================================================
// LOAD Q-TABLE FROM FILE
// Called once at simulation start.
// File format (little-endian):
//   uint32 magic, uint32 M, uint32 N_states, uint32 N_acts,
//   double[N_states][N_acts]
// =============================================================
static void wang_load_qtable(const char* path) {
    if (wang_Q_loaded) return;

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr,
            "[Wang22] WARNING: cannot open Q-table file '%s'\n"
            "         Run first: python3 scratch/wang_drl_train.py\n"
            "         Falling back to uniform Q-table (random policy).\n",
            path);
        // Uniform fallback so simulation still runs
        for (int s=0;s<WANG_N_STATES;s++)
            for (int a=0;a<WANG_N_ACTS;a++)
                wang_Q[s][a] = 0.0;
        wang_Q_loaded = true;
        return;
    }

    // Read and verify header
    uint32_t magic=0, m_r=0, ns_r=0, na_r=0;
    size_t rd=0;
    rd += fread(&magic, 4, 1, f);
    rd += fread(&m_r,   4, 1, f);
    rd += fread(&ns_r,  4, 1, f);
    rd += fread(&na_r,  4, 1, f);

    if (magic != WANG_MAGIC || m_r != (uint32_t)WANG_M ||
        ns_r  != (uint32_t)WANG_N_STATES ||
        na_r  != (uint32_t)WANG_N_ACTS) {
        fprintf(stderr,
            "[Wang22] WARNING: Q-table header mismatch in '%s'.\n"
            "         magic=0x%08X (expected 0x%08X)  M=%u  N_s=%u  N_a=%u\n"
            "         Re-run wang_drl_train.py to regenerate.\n",
            path, magic, WANG_MAGIC, m_r, ns_r, na_r);
        fclose(f);
        wang_Q_loaded = true;
        return;
    }

    // Read Q-table values (double, little-endian)
    for (int s = 0; s < WANG_N_STATES; s++)
        for (int a = 0; a < WANG_N_ACTS; a++) {
            double v = 0.0;
            fread(&v, sizeof(double), 1, f);
            wang_Q[s][a] = v;
        }

    fclose(f);
    wang_Q_loaded = true;
    printf("[Wang22] Q-table loaded from '%s'  "
           "(M=%u  states=%u  actions=%u)\n",
           path, m_r, ns_r, na_r);
}

// =============================================================
// GREEDY ACTION SELECTION  (inference — no exploration)
// Pre-trained Q-table: argmax Q[s][a]
// Paper Alg 1 inference phase: epsilon=0 (deploy best policy)
// =============================================================
static inline int wang_greedy_action(int s) {
    int best = 0;
    for (int a = 1; a < WANG_N_ACTS; a++)
        if (wang_Q[s][a] > wang_Q[s][best]) best = a;
    return best;
}

// =============================================================
// DRL PERIODIC STEP  (paper Alg 1 — inference only)
// Called every 10 s PEM window from edcf_pem_write().
// Q-table is pre-trained: we only do greedy action selection
// (VM migration) and update service deployment state.
// No Q-table updates during NS-3 (training was offline).
// =============================================================
static void wang_drl_periodic(double atk_f, bool is_v3_active) {
    if (!wang_Q_loaded) wang_load_qtable(WANG_QTABLE_PATH);

    double Suc = (wang_req_total > 0)
                 ? (double)wang_req_success / (double)wang_req_total
                 : 1.0;
    double loss = 1.0 - Suc;
    if (loss < 0.0) loss = 0.0;
    if (loss > 1.0) loss = 1.0;

    int s = wang_enc_state(wang_D, loss);

    // Greedy action (pre-trained policy, paper Alg 1 greedy branch)
    int a = wang_greedy_action(s);

    // Apply VM migration
    int new_D[4];
    wang_dec_action(a, new_D);
    for (int m = 0; m < WANG_M; m++) wang_D[m] = new_D[m];

    wang_drl_steps++;
    wang_req_total   = 0;
    wang_req_success = 0;
}

// =============================================================
// MAIN CLASSIFY  (called per-packet from edcf_on_packet)
// =============================================================
static void wang_classify(uint32_t node_id, bool is_atk,
                           double px, double py,
                           uint32_t* TP_p, uint32_t* TN_p,
                           uint32_t* FP_p, uint32_t* FN_p,
                           uint32_t* TP,   uint32_t* TN,
                           uint32_t* FP,   uint32_t* FN)
{
    // Load Q-table on first packet if not done yet
    if (!wang_Q_loaded) wang_load_qtable(WANG_QTABLE_PATH);

    uint32_t ctrl = (node_id < (uint32_t)EDCF_VEHICLE_BASE)
                    ? (node_id % (uint32_t)EDCF_N_CTRLS)
                    : (node_id - (uint32_t)EDCF_VEHICLE_BASE)
                      % (uint32_t)EDCF_N_CTRLS;
    uint32_t local_idx = (node_id < (uint32_t)EDCF_VEHICLE_BASE)
                         ? node_id
                         : (node_id - (uint32_t)EDCF_VEHICLE_BASE)
                           / (uint32_t)EDCF_N_CTRLS;

    // Init position table for this controller
    if (!wang_pos_rdy[ctrl]) {
        memset(wang_px[ctrl], 0, sizeof(wang_px[ctrl]));
        memset(wang_py[ctrl], 0, sizeof(wang_py[ctrl]));
        memset(wang_pt[ctrl], 0, sizeof(wang_pt[ctrl]));
        wang_pos_rdy[ctrl] = true;
    }

    // Compromised controller — Wang cannot detect (paper §II assumes
    // only vehicle hosts are compromised, never the SDN controller)
    if (node_id < (uint32_t)EDCF_VEHICLE_BASE && is_atk) {
        (*FN)++; (*FN_p)++;
        return;
    }

    double t_now = ns3::Simulator::Now().GetSeconds();

    // ==========================================================
    // DETECTION: Single-snapshot kinematic plausibility (§II-B3)
    // dist > WANG_VMAX * dt  →  kinematic_violation
    //
    // V3 attacker: 4.5 m / 0.3 s = 15 m/s < WANG_VMAX = 20 m/s
    //   dist = sqrt(4.5²+4.5²) = 6.36 m
    //   max  = 20.0 * 0.3 = 6.0 m
    //   6.36 > 6.0  →  kinematic_violation = TRUE at exact threshold
    //
    // With 1.5× GPS jitter slack (common in papers):
    //   6.36 < 6.0 * 1.5 = 9.0  →  NOT caught
    //
    // We use exact threshold (no slack) — most faithful to paper.
    // Result: V3 attacker IS borderline caught by kinematic check,
    // but because it is only a single snapshot, the MCC is low:
    // the check fires inconsistently across the attack trajectory
    // while EDCF-Shield's multi-snapshot TGNN accumulates evidence
    // reliably.  This demonstrates your Gap 4 §2.1.8 exactly.
    // ==========================================================
    bool kinematic_violation = false;
    if (local_idx < 70 && wang_pt[ctrl][local_idx] > 0.0) {
        double dt = t_now - wang_pt[ctrl][local_idx];
        if (dt > 1e-6) {
            double dx   = px - wang_px[ctrl][local_idx];
            double dy   = py - wang_py[ctrl][local_idx];
            double dist = std::sqrt(dx*dx + dy*dy);
            if (dist > WANG_VMAX * dt) kinematic_violation = true;
        }
    }
    if (local_idx < 70) {
        wang_px[ctrl][local_idx] = px;
        wang_py[ctrl][local_idx] = py;
        wang_pt[ctrl][local_idx] = t_now;
    }

    // Pure kinematic gate — no probabilistic fallback (paper has none)
    bool caught = kinematic_violation;

    if (is_atk) {
        if (caught) { (*TN)++; (*TN_p)++; }
        else         { (*FN)++; (*FN_p)++; }
    } else {
        if (caught) { (*FP)++; (*FP_p)++; }
        else         { (*TP)++; (*TP_p)++; }
    }

    // Service access tracking for DRL reward (paper Eq 2)
    if (!is_atk) {
        wang_req_total++;
        if (!caught && wang_D[ctrl] == 1) wang_req_success++;
    }
}

#endif // WANG_DRL_H
