// ============================================================
// edcf_pem_metrics.h  —  EDCF-Shield Metrics 2-10 Extension
//
// PURPOSE: Provides accumulators, record helpers, and
//          pem_compute_ext_row() so that every NEW metric
//          value gets appended as COLUMNS to the EXISTING
//          per-method CSVs:
//              edcf_pem_v1.csv / v2.csv / v3.csv
//              baseline_anyanwu.csv
//              baseline_ppmds.csv
//              baseline_wang.csv
//
//          NO separate CSV files are generated here.
//          All output goes through write_csv_row() only.
//
// INCLUSION SITE in routing.cc:
//   Search for:   //    END PEM block
//   Replace with: //    END PEM block
//                 #include "edcf_pem_metrics.h"
//
// All pem_* and edcf_* globals defined earlier in routing.cc
// are in scope at that point (same translation unit).
// ============================================================

#pragma once
#include <cmath>
#include <string>
#include <algorithm>

// ── Routing.cc globals referenced here ──────────────────────
// EDCF-Shield confusion matrix (cumulative, not per-cycle)

// ============================================================
// NEW GLOBAL ACCUMULATORS  (one block per metric)
// ============================================================

// ── M2 CFSR: uses e_TN + pem_flowmod_total at compute time ──
//    No extra accumulators needed.

// ── M3 PAIR: unmitigated proxy values ───────────────────────
static uint32_t pem_v2_unmitig_alerts = 0; // V2: alerts before HE suppression
static uint32_t pem_v3_unmitig_topo   = 0; // V3: topo errors before detection

// ── M4 CDR: legitimate ctrl-plane sent vs delivered ─────────
static uint32_t pem_cdr_leg_sent      = 0;
static uint32_t pem_cdr_leg_delivered = 0;

// ── M5 EML: three enforcement-path latency accumulators ──────
static double   pem_eml_trusted_sum = 0.0; uint32_t pem_eml_trusted_cnt = 0;
static double   pem_eml_bypass_sum  = 0.0; uint32_t pem_eml_bypass_cnt  = 0;
static double   pem_eml_safe_sum    = 0.0; uint32_t pem_eml_safe_cnt    = 0;

// ── M6 SO: O_comm constants (architectural, crypto-layer derived) ──
//   O_comm^{V2I}    = HMAC-SHA-512(64B) + ts(8B) + node_id(4B) = 76 B
//   O_comm^{RSU→BC} = FALCON-1024 sig(1280B) + Paillier-1024 ct(128B)
//                   + Tx hdr (node_id 4B + window_id 4B + hash 32B) = 1448 B
static constexpr uint32_t SO_V2I_BYTES    = 76u;
static constexpr uint32_t SO_RSU2BC_BYTES = 1448u;

// ── M7 MCR: MCC bucketed by concealment ratio η_c ────────────
//   η_c = edcf_wifi_flood / (edcf_wifi_flood + edcf_wifi_legit)
//   5 bins: [0,0.2) [0.2,0.4) [0.4,0.6) [0.6,0.8) [0.8,1.0]
static double   mcr_mcc_sum[5] = {0,0,0,0,0};
static uint32_t mcr_mcc_cnt[5] = {0,0,0,0,0};

// ── M8 CCR: controller-compromise resilience [ablation] ──────
static uint32_t ccr_gt_isolate        = 0;
static uint32_t ccr_isolated_within_T = 0;
static double   pem_t_failover_sum    = 0.0;
static uint32_t pem_t_failover_cnt    = 0;

// ── M9 BLP: blockchain ledger performance [ablation] ─────────
static uint32_t blp_tx_committed     = 0;
static double   blp_window_start_t   = 0.0;
static double   blp_merkle_lat_sum   = 0.0; uint32_t blp_merkle_lat_cnt   = 0;
static double   blp_multisig_lat_sum = 0.0; uint32_t blp_multisig_lat_cnt = 0;
static uint32_t blp_active_peers     = 0;

// ── M10 KRP: key-management & recovery [ablation] ────────────
static double   krp_rekey_lat_sum  = 0.0; uint32_t krp_rekey_lat_cnt  = 0;
static uint32_t krp_rekey_grp_size = 0;
static double   krp_demote_lat_sum = 0.0; uint32_t krp_demote_lat_cnt = 0;

// ============================================================
// RECORD HELPERS  — call from simulation event handlers
// ============================================================

// ── M3 ────────────────────────────────────────────────────────
// Call for every V2 alert packet BEFORE homomorphic suppression
inline void pem_record_v2_unmitig_alert() { pem_v2_unmitig_alerts++; }
// Call for every V3 WRONG_TOPO packet BEFORE position check
inline void pem_record_v3_unmitig_topo()  { pem_v3_unmitig_topo++;   }

// ── M4 ────────────────────────────────────────────────────────
// cls: "BEACON" | "OBS_TX" | "DET_TX" | "V2_ALERT"
inline void pem_record_leg_ctrl_msg(bool delivered)
{
    pem_cdr_leg_sent++;
    if (delivered) pem_cdr_leg_delivered++;
}

// ── M5 ────────────────────────────────────────────────────────
// path: "TRUSTED" | "BYPASS" | "SAFE"
inline void pem_record_mitigation_ext(double t_detect_s, double t_install_s,
                                      const char* path)
{
    double lat = (t_install_s > t_detect_s) ? (t_install_s - t_detect_s) : 0.0;
    if      (path[0] == 'T') { pem_eml_trusted_sum += lat; pem_eml_trusted_cnt++; }
    else if (path[0] == 'B') { pem_eml_bypass_sum  += lat; pem_eml_bypass_cnt++;  }
    else                     { pem_eml_safe_sum    += lat; pem_eml_safe_cnt++;     }
}

// ── M7 ────────────────────────────────────────────────────────
// Call once per PEM cycle with current cumulative MCC value
inline void pem_record_mcr_from_counters(double mcc_val)
{
    double total = (double)(edcf_wifi_flood + edcf_wifi_legit);
    double eta_c = (total > 0.0) ? (double)edcf_wifi_flood / total : 0.0;
    eta_c = std::min(eta_c, 0.9999);
    int bin = (int)(eta_c / 0.2);
    if (bin > 4) bin = 4;
    mcr_mcc_sum[bin] += mcc_val;
    mcr_mcc_cnt[bin]++;
}

// ── M8 ────────────────────────────────────────────────────────
inline void pem_record_ccr_attempt() { ccr_gt_isolate++; }
inline void pem_record_ccr_success() { ccr_isolated_within_T++; }
inline void pem_record_failover(double t_iso, double t_hand)
{
    double lat = (t_hand > t_iso) ? (t_hand - t_iso) : 0.0;
    pem_t_failover_sum += lat; pem_t_failover_cnt++;
}

// ── M9 ────────────────────────────────────────────────────────
inline void pem_record_blp_tx_commit() { blp_tx_committed++; }
inline void pem_record_blp_merkle(double lat_s)
{
    blp_merkle_lat_sum += lat_s; blp_merkle_lat_cnt++;
}
inline void pem_record_blp_multisig(double lat_s, uint32_t peers)
{
    blp_multisig_lat_sum += lat_s; blp_multisig_lat_cnt++;
    blp_active_peers = peers;
}

// ── M10 ───────────────────────────────────────────────────────
inline void pem_record_krp_rekey(double t_iso, double t_del, uint32_t grp)
{
    double lat = (t_del > t_iso) ? (t_del - t_iso) : 0.0;
    krp_rekey_lat_sum += lat; krp_rekey_lat_cnt++;
    krp_rekey_grp_size = grp;
}
inline void pem_record_krp_demote(double t_dem, double t_rem)
{
    double lat = (t_rem > t_dem) ? (t_rem - t_dem) : 0.0;
    krp_demote_lat_sum += lat; krp_demote_lat_cnt++;
}

// ============================================================
// pem_compute_ext_row()
// Returns all new metric values ready for write_csv_row().
// Called once per row write — cheap (no I/O).
// ============================================================
struct PemExtRow {
    // M2
    double cfsr;
    // M3
    double pair;
    // M4
    double cdr;
    // M5
    double eml_trusted_ms, eml_bypass_ms, eml_safe_ms;
    // M6
    uint32_t so_v2i_bytes, so_rsu2bc_bytes;
    // M7
    double mcr;
    // M8
    double ccr;
    // M9
    double blp_tput, blp_merkle_ms, blp_multisig_ms;
    // M10
    double krp_rekey_ms, krp_demote_ms;
};

inline PemExtRow pem_compute_ext_row(double sim_t)
{
    PemExtRow r{};

    // ── M2 CFSR ──────────────────────────────────────────────
    // L_ctrl_unmitig = attacks that WOULD have hit ctrl without mitigation
    //                = pem_flowmod_total (reached ctrl) + e_TN (blocked by EDCF)
    // CFSR = e_TN / (pem_flowmod_total + e_TN)
    {
        uint32_t sup    = e_TN;
        uint32_t L_un   = pem_flowmod_total + sup;
        r.cfsr = (L_un > 0) ? (double)sup / L_un : 0.0;
    }

    // ── M3 PAIR ──────────────────────────────────────────────
    // PAIR^(v) = (M_unmitig - M_mitig) / (M_unmitig - M_benign)
    {
        double win_s = sim_t - pem_table_miss_window_start;
        if (edcf_scenario == "v1a" || edcf_scenario == "v1b") {
            // Proxy: table-miss rate
            double tm_mit = (win_s > 0) ? (double)pem_table_miss_count / win_s : 0.0;
            double tm_un  = (win_s > 0) ? (double)(pem_flowmod_total + e_TN) / win_s : tm_mit;
            double M_ben  = pem_baseline_tm_rate;
            double denom  = tm_un - M_ben;
            r.pair = (denom > 1e-9) ? std::min(1.0, std::max(0.0, (tm_un - tm_mit) / denom)) : 0.0;
        } else if (edcf_scenario == "v2a" || edcf_scenario == "v2b") {
            // Proxy: broadcast amplification ratio Γ
            double gm = (pem_alert_injections > 0)
                        ? (double)pem_total_alert_msgs / pem_alert_injections : 1.0;
            double gu = (pem_alert_injections > 0 && pem_v2_unmitig_alerts > 0)
                        ? (double)pem_v2_unmitig_alerts / pem_alert_injections : gm;
            double denom = gu - 1.0; // M_benign=1.0
            r.pair = (denom > 1e-9) ? std::min(1.0, std::max(0.0, (gu - gm) / denom)) : 0.0;
        } else {
            // V3 proxy: topology error rate ε_topo
            double em = (pem_topo_total > 0)
                        ? (double)pem_topo_mismatched / pem_topo_total : 0.0;
            double eu = (pem_topo_total > 0 && pem_v3_unmitig_topo > 0)
                        ? (double)pem_v3_unmitig_topo / pem_topo_total : em;
            r.pair = (eu > 1e-9) ? std::min(1.0, std::max(0.0, (eu - em) / eu)) : 0.0;
        }
    }

    // ── M4 CDR ───────────────────────────────────────────────
    r.cdr = (pem_cdr_leg_sent > 0)
            ? (double)pem_cdr_leg_delivered / pem_cdr_leg_sent : 1.0;

    // ── M5 EML ───────────────────────────────────────────────
    r.eml_trusted_ms = (pem_eml_trusted_cnt > 0)
                       ? 1000.0 * pem_eml_trusted_sum / pem_eml_trusted_cnt : 0.0;
    r.eml_bypass_ms  = (pem_eml_bypass_cnt  > 0)
                       ? 1000.0 * pem_eml_bypass_sum  / pem_eml_bypass_cnt  : 0.0;
    r.eml_safe_ms    = (pem_eml_safe_cnt    > 0)
                       ? 1000.0 * pem_eml_safe_sum    / pem_eml_safe_cnt    : 0.0;

    // ── M6 SO ────────────────────────────────────────────────
    r.so_v2i_bytes    = SO_V2I_BYTES;
    r.so_rsu2bc_bytes = SO_RSU2BC_BYTES;

    // ── M7 MCR ───────────────────────────────────────────────
    // Report MCC averaged across the η_c bin containing current η_c
    {
        double total = (double)(edcf_wifi_flood + edcf_wifi_legit);
        double eta_c = (total > 0) ? (double)edcf_wifi_flood / total : 0.0;
        eta_c = std::min(eta_c, 0.9999);
        int bin = (int)(eta_c / 0.2);
        if (bin > 4) bin = 4;
        r.mcr = (mcr_mcc_cnt[bin] > 0) ? mcr_mcc_sum[bin] / mcr_mcc_cnt[bin] : 0.0;
    }

    // ── M8 CCR ───────────────────────────────────────────────
    r.ccr = (ccr_gt_isolate > 0)
            ? (double)ccr_isolated_within_T / ccr_gt_isolate : 1.0;

    // ── M9 BLP ───────────────────────────────────────────────
    {
        double win = sim_t - blp_window_start_t;
        r.blp_tput       = (win > 0) ? (double)blp_tx_committed / win : 0.0;
        r.blp_merkle_ms  = (blp_merkle_lat_cnt  > 0)
                           ? 1000.0 * blp_merkle_lat_sum  / blp_merkle_lat_cnt  : 0.0;
        r.blp_multisig_ms= (blp_multisig_lat_cnt > 0)
                           ? 1000.0 * blp_multisig_lat_sum / blp_multisig_lat_cnt : 0.0;
    }

    // ── M10 KRP ──────────────────────────────────────────────
    r.krp_rekey_ms  = (krp_rekey_lat_cnt  > 0)
                      ? 1000.0 * krp_rekey_lat_sum  / krp_rekey_lat_cnt  : 0.0;
    r.krp_demote_ms = (krp_demote_lat_cnt > 0)
                      ? 1000.0 * krp_demote_lat_sum / krp_demote_lat_cnt : 0.0;

    return r;
}
