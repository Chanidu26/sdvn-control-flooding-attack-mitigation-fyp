"""
pem.py  –  Performance Evaluation Metrics (PEM) for EDCF-Shield
================================================================
Group 14 | Control Plane Flooding Project | Task 01

Implements ALL metrics from the project proposal (Section 3.5.2):

Group 1 – Detection Performance
  • MCC  (Matthews Correlation Coefficient)   – primary metric
  • Detection Accuracy
  • False Positive Rate (FPR)
  • Per-Variant F1-Score  (V1, V2, V3)

Group 2 – Per-Variant Attack Impact
  • V1: Control-Plane Packet-In surge  Δλ_TM  (eq. 3.60)
  • V2: Alert propagation depth + broadcast amplification ratio Γ  (eq. 3.61)
  • V3: Topology error rate ε_topo  (eq. 3.62)  + unnecessary FlowMod rate

Group 3 – System-Level Mitigation Effectiveness
  • Packet Delivery Ratio (PDR)
  • End-to-End Mitigation Latency T_mitig
  • Computational Overhead (CPU %, memory MB)

All metrics are saved to CSV files periodically (configurable interval).
The module is designed to be imported from routing.cc via:
    system("python3 scratch/pem.py record ...")
or driven standalone via:
    python3 pem.py demo

Usage summary
-------------
import pem
tracker = pem.PEMTracker(output_dir="./scratch/pem_results", save_interval_s=30)

# Feed events every simulation tick
tracker.record_packet(sent=True, delivered=True, node_id=5, variant=None)
tracker.record_detection(true_label="V1", predicted_label="V1", variant="V1")
tracker.record_control_plane_event(event_type="table_miss")
tracker.record_alert(source_id=3, hop_count=2, forwarded_count=5)
tracker.record_topology_snapshot(reported_positions, true_positions, delta_pos=5.0)
tracker.record_flowmod(triggered_by_attack=False)
tracker.record_mitigation_event(attack_onset_time=10.5, rule_installed_time=10.7)

# Save immediately (also called automatically every save_interval_s)
tracker.save_all()
"""

import csv
import os
import sys
import time
import math
import psutil
import argparse
import json
from datetime import datetime
from collections import defaultdict, deque
from typing import Optional, List, Dict, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Constants matching the proposal notation
# ─────────────────────────────────────────────────────────────────────────────
VARIANTS = ["V1", "V2", "V3", "benign"]

# ─────────────────────────────────────────────────────────────────────────────
# Helper: MCC
# ─────────────────────────────────────────────────────────────────────────────
def compute_mcc(tp: int, tn: int, fp: int, fn: int) -> float:
    """Matthews Correlation Coefficient (eq. 3.59 in proposal)."""
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denom == 0:
        return 0.0
    return (tp * tn - fp * fn) / denom


def compute_f1(tp: int, fp: int, fn: int) -> float:
    denom = 2 * tp + fp + fn
    if denom == 0:
        return 0.0
    return 2 * tp / denom


# ─────────────────────────────────────────────────────────────────────────────
# Main tracker class
# ─────────────────────────────────────────────────────────────────────────────
class PEMTracker:
    """
    Central tracker for all Performance Evaluation Metrics.

    Parameters
    ----------
    output_dir     : directory where CSV files are written
    save_interval_s: auto-save every N wall-clock seconds (0 = manual only)
    baseline_table_miss_rate : benign λ̄_TM from warm-up phase (packets/s)
    baseline_flowmod_rate    : benign λ̄_FM from warm-up phase (mods/s)
    baseline_cp_load         : benign λ̄_CP from warm-up phase (msgs/s)
    delta_pos_threshold      : position error threshold δ_pos (metres)
    """

    def __init__(
        self,
        output_dir: str = "./scratch/pem_results",
        save_interval_s: float = 30.0,
        baseline_table_miss_rate: float = 1.0,
        baseline_flowmod_rate: float = 1.0,
        baseline_cp_load: float = 1.0,
        delta_pos_threshold: float = 5.0,
    ):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.save_interval_s = save_interval_s
        self._last_save_wall = time.time()

        # Baselines (can be updated via set_baselines())
        self.baseline_tm = baseline_table_miss_rate
        self.baseline_fm = baseline_flowmod_rate
        self.baseline_cp = baseline_cp_load
        self.delta_pos = delta_pos_threshold

        # ── Group 1: Detection confusion matrices ──────────────────────────
        # Per-variant binary confusion matrix (attack vs. benign)
        self._cm: Dict[str, Dict[str, int]] = {
            v: {"tp": 0, "tn": 0, "fp": 0, "fn": 0} for v in VARIANTS
        }
        # Global (any-variant) detection counters
        self._global_tp = 0
        self._global_tn = 0
        self._global_fp = 0
        self._global_fn = 0

        # ── Group 2a: V1 – table-miss rate ────────────────────────────────
        self._tm_events: deque = deque()          # (wall_time,) tuples
        self._tm_rate_history: List[Tuple] = []  # (sim_time, rate, delta%)

        # ── Group 2b: V2 – alert propagation ──────────────────────────────
        # Each alert injection: (source_id, hop_count, forwarded_count)
        self._alert_records: List[Dict] = []
        self._alert_depth_history: List[Tuple] = []
        self._gamma_history: List[Tuple] = []    # (sim_time, Gamma)

        # ── Group 2c: V3 – topology error / FlowMod ───────────────────────
        self._topo_error_history: List[Tuple] = []   # (sim_time, eps_topo)
        self._flowmod_total = 0
        self._flowmod_attack = 0
        self._flowmod_history: List[Tuple] = []

        # ── Group 3: PDR ───────────────────────────────────────────────────
        self._packets_sent = 0
        self._packets_delivered = 0
        self._pdr_history: List[Tuple] = []

        # ── Group 3: Mitigation latency ────────────────────────────────────
        self._mitigation_latencies: List[float] = []   # seconds
        self._latency_history: List[Tuple] = []

        # ── Group 3: CPU / memory ──────────────────────────────────────────
        self._overhead_history: List[Tuple] = []
        self._process = psutil.Process(os.getpid())

        # ── Periodic snapshot index ────────────────────────────────────────
        self._snapshot_index = 0

        # ── Simulation time tracking ───────────────────────────────────────
        self._sim_time: float = 0.0    # updated by caller

    # ─────────────────────────────────────────────────────────────────────
    # Public: update simulation clock
    # ─────────────────────────────────────────────────────────────────────
    def tick(self, sim_time_seconds: float):
        """Call this each simulation step to advance the internal clock."""
        self._sim_time = sim_time_seconds
        self._auto_save()

    # ─────────────────────────────────────────────────────────────────────
    # Public: baselines
    # ─────────────────────────────────────────────────────────────────────
    def set_baselines(
        self,
        table_miss_rate: float,
        flowmod_rate: float,
        cp_load: float,
    ):
        """Update baseline rates (call after warm-up phase)."""
        self.baseline_tm = max(table_miss_rate, 1e-9)
        self.baseline_fm = max(flowmod_rate, 1e-9)
        self.baseline_cp = max(cp_load, 1e-9)

    # ─────────────────────────────────────────────────────────────────────
    # Group 1: Detection events
    # ─────────────────────────────────────────────────────────────────────
    def record_detection(
        self,
        true_label: str,
        predicted_label: str,
        variant: Optional[str] = None,
    ):
        """
        Feed one classification decision.

        Parameters
        ----------
        true_label      : ground-truth label  ("V1" | "V2" | "V3" | "benign")
        predicted_label : model prediction    ("V1" | "V2" | "V3" | "benign")
        variant         : if provided, update per-variant counters only for
                          that variant; otherwise inferred from true_label
        """
        is_attack_true = true_label != "benign"
        is_attack_pred = predicted_label != "benign"

        # ── global counters ────────────────────────────────────────────────
        if is_attack_true and is_attack_pred:
            self._global_tp += 1
        elif not is_attack_true and not is_attack_pred:
            self._global_tn += 1
        elif not is_attack_true and is_attack_pred:
            self._global_fp += 1
        else:
            self._global_fn += 1

        # ── per-variant counters ───────────────────────────────────────────
        v = variant if variant else true_label
        if v not in self._cm:
            return
        cm = self._cm[v]
        is_v_true = true_label == v
        is_v_pred = predicted_label == v
        if is_v_true and is_v_pred:
            cm["tp"] += 1
        elif not is_v_true and not is_v_pred:
            cm["tn"] += 1
        elif not is_v_true and is_v_pred:
            cm["fp"] += 1
        else:
            cm["fn"] += 1

    # ─────────────────────────────────────────────────────────────────────
    # Group 2a: V1 – Control-Plane Packet-In / table-miss
    # ─────────────────────────────────────────────────────────────────────
    def record_control_plane_event(
        self,
        event_type: str = "table_miss",
        sim_time: Optional[float] = None,
    ):
        """
        Record a control-plane event (table-miss / Packet-In).
        Call this every time the SDN controller receives a Packet-In.
        """
        t = sim_time if sim_time is not None else self._sim_time
        if event_type == "table_miss":
            self._tm_events.append(t)

    def compute_table_miss_rate(self, window_s: float = 1.0) -> float:
        """λ_TM(t): table-miss rate over a sliding window (events / s)."""
        now = self._sim_time
        cutoff = now - window_s
        # Remove old events
        while self._tm_events and self._tm_events[0] < cutoff:
            self._tm_events.popleft()
        return len(self._tm_events) / max(window_s, 1e-9)

    def snapshot_v1(self, window_s: float = 1.0):
        """Take a V1 metric snapshot and append to history."""
        rate = self.compute_table_miss_rate(window_s)
        delta_pct = (rate - self.baseline_tm) / self.baseline_tm * 100.0
        self._tm_rate_history.append((self._sim_time, rate, delta_pct))
        return rate, delta_pct

    # ─────────────────────────────────────────────────────────────────────
    # Group 2b: V2 – Alert propagation
    # ─────────────────────────────────────────────────────────────────────
    def record_alert(
        self,
        source_id: int,
        hop_count: int,
        forwarded_count: int,
        received_count: int = 1,
        sim_time: Optional[float] = None,
    ):
        """
        Record one alert injection event.

        Parameters
        ----------
        source_id       : originating node ID
        hop_count       : how many hops this alert reached (d_prop)
        forwarded_count : Aout_i – messages forwarded by this source
        received_count  : Ain_i  – messages received before forwarding
        """
        t = sim_time if sim_time is not None else self._sim_time
        self._alert_records.append(
            {
                "sim_time": t,
                "source_id": source_id,
                "hop_count": hop_count,
                "forwarded": forwarded_count,
                "received": received_count,
            }
        )

    def snapshot_v2(self) -> Tuple[float, float]:
        """
        Compute broadcast amplification ratio Γ (eq. 3.61) and
        maximum alert propagation depth d_prop.
        Returns (Gamma, d_prop_max).
        """
        if not self._alert_records:
            return 1.0, 0

        total_alerts = sum(r["forwarded"] for r in self._alert_records)
        n_injections = len(
            set(r["source_id"] for r in self._alert_records)
        )
        gamma = total_alerts / max(n_injections, 1)
        d_prop_max = max(r["hop_count"] for r in self._alert_records)

        self._gamma_history.append((self._sim_time, gamma))
        self._alert_depth_history.append((self._sim_time, d_prop_max))
        return gamma, d_prop_max

    # ─────────────────────────────────────────────────────────────────────
    # Group 2c: V3 – Topology error + FlowMod
    # ─────────────────────────────────────────────────────────────────────
    def record_topology_snapshot(
        self,
        reported_positions: Dict[int, Tuple[float, float]],
        true_positions: Dict[int, Tuple[float, float]],
        delta_pos: Optional[float] = None,
        sim_time: Optional[float] = None,
    ):
        """
        Compute topology error rate ε_topo (eq. 3.62).

        reported_positions : {node_id: (x, y)} from the SDN controller
        true_positions     : {node_id: (x, y)} ground truth
        delta_pos          : positional error threshold (metres); uses
                             self.delta_pos if None
        """
        t = sim_time if sim_time is not None else self._sim_time
        threshold = delta_pos if delta_pos is not None else self.delta_pos
        mismatched = 0
        total = len(true_positions)
        if total == 0:
            return 0.0

        for nid, (tx, ty) in true_positions.items():
            if nid in reported_positions:
                rx, ry = reported_positions[nid]
                err = math.sqrt((rx - tx) ** 2 + (ry - ty) ** 2)
                if err > threshold:
                    mismatched += 1
            else:
                mismatched += 1  # node absent from controller view

        eps_topo = mismatched / total
        self._topo_error_history.append((t, eps_topo, mismatched, total))
        return eps_topo

    def record_flowmod(
        self,
        triggered_by_attack: bool = False,
        sim_time: Optional[float] = None,
    ):
        """Record one FlowMod event. Set triggered_by_attack=True for
        FlowMods caused by falsified mobility traces."""
        t = sim_time if sim_time is not None else self._sim_time
        self._flowmod_total += 1
        if triggered_by_attack:
            self._flowmod_attack += 1
        self._flowmod_history.append((t, self._flowmod_total,
                                       self._flowmod_attack,
                                       triggered_by_attack))

    def compute_excess_flowmod_rate(self, window_s: float = 1.0) -> float:
        """λ_FM_excess: rate of attack-induced FlowMods in window."""
        now = self._sim_time
        cutoff = now - window_s
        excess = sum(
            1 for (t, _, _, atk) in self._flowmod_history
            if atk and t >= cutoff
        )
        return excess / max(window_s, 1e-9)

    # ─────────────────────────────────────────────────────────────────────
    # Group 3: PDR
    # ─────────────────────────────────────────────────────────────────────
    def record_packet(
        self,
        sent: bool,
        delivered: bool,
        node_id: Optional[int] = None,
        variant: Optional[str] = None,
        sim_time: Optional[float] = None,
    ):
        """
        Record one V2X packet.

        sent      : True if the packet was injected into the network
        delivered : True if it was received by the destination
        """
        if sent:
            self._packets_sent += 1
        if delivered:
            self._packets_delivered += 1

    def snapshot_pdr(self) -> float:
        """Packet Delivery Ratio = delivered / sent."""
        if self._packets_sent == 0:
            return 1.0
        pdr = self._packets_delivered / self._packets_sent
        self._pdr_history.append((self._sim_time, pdr,
                                   self._packets_delivered,
                                   self._packets_sent))
        return pdr

    # ─────────────────────────────────────────────────────────────────────
    # Group 3: Mitigation latency
    # ─────────────────────────────────────────────────────────────────────
    def record_mitigation_event(
        self,
        attack_onset_time: float,
        rule_installed_time: float,
        mode: str = "full",
        variant: Optional[str] = None,
    ):
        """
        Record one mitigation event.

        attack_onset_time  : simulation time when attack began (s)
        rule_installed_time: simulation time when flow rule was installed (s)
        mode               : "lightweight" | "full"
        variant            : "V1" | "V2" | "V3"
        """
        latency = rule_installed_time - attack_onset_time
        self._mitigation_latencies.append(latency)
        self._latency_history.append(
            (self._sim_time, latency, mode, variant or "unknown")
        )
        return latency

    # ─────────────────────────────────────────────────────────────────────
    # Group 3: CPU / memory overhead
    # ─────────────────────────────────────────────────────────────────────
    def snapshot_overhead(self) -> Tuple[float, float]:
        """Sample CPU % and memory (MB) of the current process."""
        cpu = self._process.cpu_percent(interval=0.1)
        mem_mb = self._process.memory_info().rss / (1024 ** 2)
        self._overhead_history.append((self._sim_time, cpu, mem_mb))
        return cpu, mem_mb

    # ─────────────────────────────────────────────────────────────────────
    # Compute all Group 1 metrics
    # ─────────────────────────────────────────────────────────────────────
    def compute_detection_metrics(self) -> Dict:
        """Return a dict with all Group 1 metrics."""
        tp, tn, fp, fn = (
            self._global_tp, self._global_tn,
            self._global_fp, self._global_fn,
        )
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        mcc = compute_mcc(tp, tn, fp, fn)

        per_variant = {}
        for v in ["V1", "V2", "V3"]:
            cm = self._cm[v]
            per_variant[v] = {
                "f1": compute_f1(cm["tp"], cm["fp"], cm["fn"]),
                "tp": cm["tp"], "fp": cm["fp"],
                "tn": cm["tn"], "fn": cm["fn"],
            }

        return {
            "global_tp": tp, "global_tn": tn,
            "global_fp": fp, "global_fn": fn,
            "accuracy": accuracy,
            "fpr": fpr,
            "mcc": mcc,
            "per_variant": per_variant,
        }

    # ─────────────────────────────────────────────────────────────────────
    # Save all metrics to CSV
    # ─────────────────────────────────────────────────────────────────────
    def save_all(self, sim_time: Optional[float] = None):
        """Write all current metrics to CSV files."""
        if sim_time is not None:
            self._sim_time = sim_time

        idx = self._snapshot_index
        self._snapshot_index += 1
        ts_wall = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Snapshot V1 ───────────────────────────────────────────────────
        self.snapshot_v1()

        # ── Snapshot V2 ───────────────────────────────────────────────────
        self.snapshot_v2()

        # ── Snapshot PDR ──────────────────────────────────────────────────
        self.snapshot_pdr()

        # ── Snapshot overhead ─────────────────────────────────────────────
        self.snapshot_overhead()

        # ── Compute detection metrics ─────────────────────────────────────
        dm = self.compute_detection_metrics()

        # 1. Summary CSV (one row per save call)
        self._write_summary_row(idx, ts_wall, dm)

        # 2. Per-variant detection CSV
        self._write_detection_csv()

        # 3. V1 history CSV
        self._write_v1_csv()

        # 4. V2 alert CSV
        self._write_v2_csv()

        # 5. V3 topology / FlowMod CSV
        self._write_v3_csv()

        # 6. PDR CSV
        self._write_pdr_csv()

        # 7. Mitigation latency CSV
        self._write_latency_csv()

        # 8. Overhead CSV
        self._write_overhead_csv()

        # 9. Raw alert records CSV
        self._write_alert_records_csv()

        self._last_save_wall = time.time()

    # ─────────────────────────────────────────────────────────────────────
    # CSV writers
    # ─────────────────────────────────────────────────────────────────────
    def _csv_path(self, name: str) -> str:
        return os.path.join(self.output_dir, name)

    def _write_summary_row(self, idx: int, ts_wall: str, dm: Dict):
        path = self._csv_path("pem_summary.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "snapshot_index", "wall_time", "sim_time_s",
                    "global_tp", "global_tn", "global_fp", "global_fn",
                    "accuracy", "fpr", "mcc",
                    "f1_v1", "f1_v2", "f1_v3",
                    "pdr",
                    "tm_rate", "tm_delta_pct",
                    "gamma", "d_prop_max",
                    "eps_topo",
                    "flowmod_excess_rate",
                    "avg_latency_s",
                    "cpu_pct", "mem_mb",
                ])
            pdr = (self._packets_delivered / self._packets_sent
                   if self._packets_sent > 0 else 1.0)
            tm_rate, tm_delta = (
                (self._tm_rate_history[-1][1], self._tm_rate_history[-1][2])
                if self._tm_rate_history else (0.0, 0.0)
            )
            gamma = (self._gamma_history[-1][1]
                     if self._gamma_history else 1.0)
            d_prop = (self._alert_depth_history[-1][1]
                      if self._alert_depth_history else 0)
            eps_topo = (self._topo_error_history[-1][1]
                        if self._topo_error_history else 0.0)
            fm_excess = self.compute_excess_flowmod_rate()
            avg_lat = (
                sum(self._mitigation_latencies) /
                len(self._mitigation_latencies)
                if self._mitigation_latencies else 0.0
            )
            cpu, mem = (
                (self._overhead_history[-1][1],
                 self._overhead_history[-1][2])
                if self._overhead_history else (0.0, 0.0)
            )
            w.writerow([
                idx, ts_wall, round(self._sim_time, 4),
                dm["global_tp"], dm["global_tn"],
                dm["global_fp"], dm["global_fn"],
                round(dm["accuracy"], 6),
                round(dm["fpr"], 6),
                round(dm["mcc"], 6),
                round(dm["per_variant"]["V1"]["f1"], 6),
                round(dm["per_variant"]["V2"]["f1"], 6),
                round(dm["per_variant"]["V3"]["f1"], 6),
                round(pdr, 6),
                round(tm_rate, 4), round(tm_delta, 2),
                round(gamma, 4), d_prop,
                round(eps_topo, 6),
                round(fm_excess, 4),
                round(avg_lat, 6),
                round(cpu, 2), round(mem, 2),
            ])

    def _write_detection_csv(self):
        path = self._csv_path("pem_detection.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "variant", "tp", "tn", "fp", "fn",
                "accuracy", "fpr", "precision", "recall", "f1", "mcc",
            ])
            for v in ["V1", "V2", "V3"]:
                cm = self._cm[v]
                tp, tn = cm["tp"], cm["tn"]
                fp, fn = cm["fp"], cm["fn"]
                total = tp + tn + fp + fn
                acc = (tp + tn) / total if total > 0 else 0.0
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1 = compute_f1(tp, fp, fn)
                mcc = compute_mcc(tp, tn, fp, fn)
                w.writerow([v, tp, tn, fp, fn,
                             round(acc, 6), round(fpr, 6),
                             round(prec, 6), round(rec, 6),
                             round(f1, 6), round(mcc, 6)])
            # Global row
            tp, tn = self._global_tp, self._global_tn
            fp, fn = self._global_fp, self._global_fn
            total = tp + tn + fp + fn
            acc = (tp + tn) / total if total > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = compute_f1(tp, fp, fn)
            mcc = compute_mcc(tp, tn, fp, fn)
            w.writerow(["GLOBAL", tp, tn, fp, fn,
                         round(acc, 6), round(fpr, 6),
                         round(prec, 6), round(rec, 6),
                         round(f1, 6), round(mcc, 6)])

    def _write_v1_csv(self):
        path = self._csv_path("pem_v1_table_miss.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "tm_rate_per_s",
                    "delta_tm_pct",   # eq. 3.60
                    "baseline_tm_rate",
                ])
            for row in self._tm_rate_history:
                w.writerow([round(row[0], 4),
                             round(row[1], 4),
                             round(row[2], 2),
                             round(self.baseline_tm, 4)])
        # Clear so we don't re-append duplicates
        self._tm_rate_history.clear()

    def _write_v2_csv(self):
        path = self._csv_path("pem_v2_alert_propagation.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "broadcast_amplification_ratio_gamma",
                    "alert_propagation_depth_max",
                ])
            for (t, g), (t2, d) in zip(
                self._gamma_history, self._alert_depth_history
            ):
                w.writerow([round(t, 4), round(g, 4), d])
        self._gamma_history.clear()
        self._alert_depth_history.clear()

    def _write_v3_csv(self):
        # Topology error
        path = self._csv_path("pem_v3_topology_error.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "eps_topo",
                    "mismatched_nodes", "total_nodes",
                    "delta_pos_threshold_m",
                ])
            for row in self._topo_error_history:
                w.writerow([round(row[0], 4), round(row[1], 6),
                             row[2], row[3],
                             round(self.delta_pos, 2)])
        self._topo_error_history.clear()

        # FlowMod
        path2 = self._csv_path("pem_v3_flowmod.csv")
        write_header2 = not os.path.exists(path2)
        with open(path2, "a", newline="") as f:
            w = csv.writer(f)
            if write_header2:
                w.writerow([
                    "sim_time_s", "flowmod_cumulative",
                    "flowmod_attack_cumulative",
                    "triggered_by_attack",
                ])
            for row in self._flowmod_history:
                w.writerow([round(row[0], 4), row[1], row[2], row[3]])
        self._flowmod_history.clear()

    def _write_pdr_csv(self):
        path = self._csv_path("pem_pdr.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "pdr",
                    "packets_delivered", "packets_sent",
                ])
            for row in self._pdr_history:
                w.writerow([round(row[0], 4), round(row[1], 6),
                             row[2], row[3]])
        self._pdr_history.clear()

    def _write_latency_csv(self):
        path = self._csv_path("pem_mitigation_latency.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "mitigation_latency_s",
                    "mode", "variant",
                ])
            for row in self._latency_history:
                w.writerow([round(row[0], 4), round(row[1], 6),
                             row[2], row[3]])
        self._latency_history.clear()

    def _write_overhead_csv(self):
        path = self._csv_path("pem_overhead.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "cpu_percent", "memory_mb",
                ])
            for row in self._overhead_history:
                w.writerow([round(row[0], 4),
                             round(row[1], 2), round(row[2], 2)])
        self._overhead_history.clear()

    def _write_alert_records_csv(self):
        if not self._alert_records:
            return
        path = self._csv_path("pem_alert_records.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow([
                    "sim_time_s", "source_id",
                    "hop_count", "forwarded", "received",
                    "fan_out_ratio",
                ])
            for r in self._alert_records:
                fan_out = r["forwarded"] / max(r["received"], 1)
                w.writerow([round(r["sim_time"], 4),
                             r["source_id"],
                             r["hop_count"],
                             r["forwarded"],
                             r["received"],
                             round(fan_out, 4)])
        self._alert_records.clear()

    # ─────────────────────────────────────────────────────────────────────
    # Internal: auto-save on wall-clock tick
    # ─────────────────────────────────────────────────────────────────────
    def _auto_save(self):
        if self.save_interval_s <= 0:
            return
        if time.time() - self._last_save_wall >= self.save_interval_s:
            self.save_all()


# ─────────────────────────────────────────────────────────────────────────────
# Standalone CLI – called from routing.cc via system() or used for testing
# ─────────────────────────────────────────────────────────────────────────────
def _cli_record(args):
    """
    Record a single event from the NS-3 simulation.
    Called by routing.cc:
        system("python3 scratch/pem.py record --event table_miss --sim_time 12.5 ...")
    State is persisted in a JSON checkpoint between calls.
    """
    checkpoint = args.state_file
    if os.path.exists(checkpoint):
        with open(checkpoint) as fh:
            state = json.load(fh)
    else:
        state = {
            "global_tp": 0, "global_tn": 0,
            "global_fp": 0, "global_fn": 0,
            "V1_tp": 0, "V1_tn": 0, "V1_fp": 0, "V1_fn": 0,
            "V2_tp": 0, "V2_tn": 0, "V2_fp": 0, "V2_fn": 0,
            "V3_tp": 0, "V3_tn": 0, "V3_fp": 0, "V3_fn": 0,
            "packets_sent": 0, "packets_delivered": 0,
            "baseline_tm": args.baseline_tm,
            "baseline_fm": args.baseline_fm,
        }

    out_dir = args.output_dir
    os.makedirs(out_dir, exist_ok=True)
    sim_time = args.sim_time

    # ── table_miss event ──────────────────────────────────────────────────
    if args.event == "table_miss":
        path = os.path.join(out_dir, "pem_v1_table_miss.csv")
        write_header = not os.path.exists(path)
        baseline = state.get("baseline_tm", args.baseline_tm)
        rate = args.value
        delta_pct = (rate - baseline) / max(baseline, 1e-9) * 100.0
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["sim_time_s", "tm_rate_per_s",
                             "delta_tm_pct", "baseline_tm_rate"])
            w.writerow([sim_time, round(rate, 4),
                        round(delta_pct, 2), baseline])

    # ── alert event ───────────────────────────────────────────────────────
    elif args.event == "alert":
        path = os.path.join(out_dir, "pem_alert_records.csv")
        write_header = not os.path.exists(path)
        fan_out = args.forwarded / max(args.received, 1)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["sim_time_s", "source_id", "hop_count",
                             "forwarded", "received", "fan_out_ratio"])
            w.writerow([sim_time, args.source_id, args.hop_count,
                        args.forwarded, args.received, round(fan_out, 4)])

    # ── topology snapshot ─────────────────────────────────────────────────
    elif args.event == "topology":
        path = os.path.join(out_dir, "pem_v3_topology_error.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["sim_time_s", "eps_topo",
                             "mismatched_nodes", "total_nodes",
                             "delta_pos_threshold_m"])
            w.writerow([sim_time, round(args.eps_topo, 6),
                        args.mismatched, args.total_nodes,
                        args.delta_pos])

    # ── flowmod event ─────────────────────────────────────────────────────
    elif args.event == "flowmod":
        path = os.path.join(out_dir, "pem_v3_flowmod.csv")
        write_header = not os.path.exists(path)
        state["flowmod_total"] = state.get("flowmod_total", 0) + 1
        if args.attack:
            state["flowmod_attack"] = state.get("flowmod_attack", 0) + 1
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["sim_time_s", "flowmod_cumulative",
                             "flowmod_attack_cumulative", "triggered_by_attack"])
            w.writerow([sim_time, state["flowmod_total"],
                        state.get("flowmod_attack", 0), args.attack])

    # ── detection event ───────────────────────────────────────────────────
    elif args.event == "detection":
        is_attack_true = args.true_label != "benign"
        is_attack_pred = args.pred_label != "benign"
        if is_attack_true and is_attack_pred:
            state["global_tp"] += 1
            state[f"{args.true_label}_tp"] += 1
        elif not is_attack_true and not is_attack_pred:
            state["global_tn"] += 1
            if args.true_label in ("V1", "V2", "V3"):
                state[f"{args.true_label}_tn"] += 1
        elif not is_attack_true and is_attack_pred:
            state["global_fp"] += 1
        else:
            state["global_fn"] += 1
            if args.true_label in ("V1", "V2", "V3"):
                state[f"{args.true_label}_fn"] += 1

    # ── packet event ──────────────────────────────────────────────────────
    elif args.event == "packet":
        if args.sent:
            state["packets_sent"] += 1
        if args.delivered:
            state["packets_delivered"] += 1

    # ── mitigation latency ────────────────────────────────────────────────
    elif args.event == "mitigation":
        latency = args.rule_time - args.onset_time
        path = os.path.join(out_dir, "pem_mitigation_latency.csv")
        write_header = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["sim_time_s", "mitigation_latency_s",
                             "mode", "variant"])
            w.writerow([sim_time, round(latency, 6),
                        args.mode, args.variant])

    # ── summary flush ─────────────────────────────────────────────────────
    elif args.event == "flush":
        _flush_summary(state, out_dir, sim_time)

    with open(checkpoint, "w") as fh:
        json.dump(state, fh, indent=2)


def _flush_summary(state: dict, out_dir: str, sim_time: float):
    """Write one summary row from persisted state dict."""
    tp = state.get("global_tp", 0)
    tn = state.get("global_tn", 0)
    fp = state.get("global_fp", 0)
    fn = state.get("global_fn", 0)
    total = tp + tn + fp + fn
    acc = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    mcc = compute_mcc(tp, tn, fp, fn)

    sent = state.get("packets_sent", 0)
    delivered = state.get("packets_delivered", 0)
    pdr = delivered / sent if sent > 0 else 1.0

    f1s = {}
    for v in ("V1", "V2", "V3"):
        vtp = state.get(f"{v}_tp", 0)
        vfp = state.get(f"{v}_fp", 0)
        vfn = state.get(f"{v}_fn", 0)
        f1s[v] = compute_f1(vtp, vfp, vfn)

    path = os.path.join(out_dir, "pem_summary.csv")
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow([
                "sim_time_s",
                "global_tp", "global_tn", "global_fp", "global_fn",
                "accuracy", "fpr", "mcc",
                "f1_v1", "f1_v2", "f1_v3",
                "pdr",
            ])
        w.writerow([
            round(sim_time, 4),
            tp, tn, fp, fn,
            round(acc, 6), round(fpr, 6), round(mcc, 6),
            round(f1s["V1"], 6), round(f1s["V2"], 6), round(f1s["V3"], 6),
            round(pdr, 6),
        ])


# ─────────────────────────────────────────────────────────────────────────────
# Demo / self-test
# ─────────────────────────────────────────────────────────────────────────────
def _run_demo():
    """
    Demonstrate the PEM module with a simulated 60-second SDVN scenario.
    Generates all CSV files in ./scratch/pem_results_demo/
    """
    import random as rnd
    print("=" * 60)
    print("  PEM Demo – Group 14 EDCF-Shield Performance Metrics")
    print("=" * 60)

    tracker = PEMTracker(
        output_dir="./scratch/pem_results_demo",
        save_interval_s=0,  # manual saves only
        baseline_table_miss_rate=5.0,
        baseline_flowmod_rate=2.0,
        delta_pos_threshold=5.0,
    )

    rnd.seed(42)
    n_vehicles = 20
    attack_start = 20.0   # attack begins at t=20 s
    attack_variant = "V1"

    for t in range(0, 61):
        tracker.tick(float(t))
        under_attack = t >= attack_start

        # ── packets ──────────────────────────────────────────────────────
        for _ in range(10):
            sent = True
            delivered = rnd.random() > (0.3 if under_attack else 0.05)
            tracker.record_packet(sent=sent, delivered=delivered)

        # ── table-miss events ─────────────────────────────────────────────
        n_miss = rnd.randint(20, 40) if under_attack else rnd.randint(3, 7)
        for _ in range(n_miss):
            tracker.record_control_plane_event("table_miss", sim_time=float(t))

        # ── detection decisions ───────────────────────────────────────────
        for _ in range(5):
            true_label = "V1" if under_attack else "benign"
            # Simulated detector with ~85% accuracy
            if rnd.random() < 0.85:
                pred = true_label
            else:
                pred = "benign" if true_label != "benign" else "V1"
            tracker.record_detection(true_label, pred, variant="V1")

        # ── V2 alerts ─────────────────────────────────────────────────────
        if under_attack and t % 5 == 0:
            for src in rnd.sample(range(n_vehicles), k=3):
                tracker.record_alert(
                    source_id=src,
                    hop_count=rnd.randint(3, 8),
                    forwarded_count=rnd.randint(5, 20),
                    received_count=rnd.randint(1, 3),
                    sim_time=float(t),
                )

        # ── V3 topology ───────────────────────────────────────────────────
        if t % 10 == 0:
            reported = {i: (rnd.uniform(0, 500), rnd.uniform(0, 500))
                        for i in range(n_vehicles)}
            true_pos = {i: (rnd.uniform(0, 500), rnd.uniform(0, 500))
                        for i in range(n_vehicles)}
            if under_attack:
                # Inject some large position errors
                for i in rnd.sample(range(n_vehicles), k=5):
                    rx, ry = reported[i]
                    reported[i] = (rx + rnd.uniform(20, 100),
                                   ry + rnd.uniform(20, 100))
            tracker.record_topology_snapshot(reported, true_pos)

        # ── FlowMod ───────────────────────────────────────────────────────
        for _ in range(rnd.randint(1, 4)):
            atk = under_attack and rnd.random() < 0.4
            tracker.record_flowmod(triggered_by_attack=atk,
                                   sim_time=float(t))

        # ── Mitigation ───────────────────────────────────────────────────
        if under_attack and t % 8 == 0:
            onset = float(t) - rnd.uniform(0.1, 0.5)
            rule_t = float(t) + rnd.uniform(0.05, 0.3)
            tracker.record_mitigation_event(
                attack_onset_time=onset,
                rule_installed_time=rule_t,
                mode="full",
                variant="V1",
            )

        # ── Save every 10 simulated seconds ───────────────────────────────
        if t % 10 == 0:
            tracker.save_all(sim_time=float(t))
            dm = tracker.compute_detection_metrics()
            pdr = (tracker._packets_delivered / tracker._packets_sent
                   if tracker._packets_sent > 0 else 1.0)
            print(
                f"  t={t:3d}s | MCC={dm['mcc']:.3f} "
                f"Acc={dm['accuracy']:.3f} "
                f"FPR={dm['fpr']:.3f} "
                f"PDR={pdr:.3f} "
                f"F1_V1={dm['per_variant']['V1']['f1']:.3f}"
            )

    tracker.save_all(sim_time=60.0)
    print("\n  CSV files written to: ./scratch/pem_results_demo/")
    print("  Files:")
    for fn in sorted(os.listdir("./scratch/pem_results_demo")):
        path = os.path.join("./scratch/pem_results_demo", fn)
        rows = sum(1 for _ in open(path)) - 1  # subtract header
        print(f"    {fn:<45} {rows:>5} data rows")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PEM – Performance Evaluation Metrics for EDCF-Shield"
    )
    sub = parser.add_subparsers(dest="cmd")

    # demo sub-command
    sub.add_parser("demo", help="Run self-test demo simulation")

    # record sub-command
    rec = sub.add_parser("record", help="Record a single event from NS-3")
    rec.add_argument("--event", required=True,
                     choices=["table_miss", "alert", "topology",
                               "flowmod", "detection", "packet",
                               "mitigation", "flush"])
    rec.add_argument("--sim_time", type=float, default=0.0)
    rec.add_argument("--output_dir", default="./scratch/pem_results")
    rec.add_argument("--state_file",
                     default="./scratch/pem_state.json")
    rec.add_argument("--baseline_tm", type=float, default=5.0)
    rec.add_argument("--baseline_fm", type=float, default=2.0)
    rec.add_argument("--value", type=float, default=0.0,
                     help="Generic float value (rate, etc.)")
    # alert args
    rec.add_argument("--source_id", type=int, default=0)
    rec.add_argument("--hop_count", type=int, default=0)
    rec.add_argument("--forwarded", type=int, default=0)
    rec.add_argument("--received", type=int, default=1)
    # topology args
    rec.add_argument("--eps_topo", type=float, default=0.0)
    rec.add_argument("--mismatched", type=int, default=0)
    rec.add_argument("--total_nodes", type=int, default=1)
    rec.add_argument("--delta_pos", type=float, default=5.0)
    # flowmod args
    rec.add_argument("--attack", action="store_true")
    # detection args
    rec.add_argument("--true_label", default="benign")
    rec.add_argument("--pred_label", default="benign")
    # packet args
    rec.add_argument("--sent", action="store_true")
    rec.add_argument("--delivered", action="store_true")
    # mitigation args
    rec.add_argument("--onset_time", type=float, default=0.0)
    rec.add_argument("--rule_time", type=float, default=0.0)
    rec.add_argument("--mode", default="full")
    rec.add_argument("--variant", default="unknown")

    args = parser.parse_args()

    if args.cmd == "demo":
        _run_demo()
    elif args.cmd == "record":
        _cli_record(args)
    else:
        parser.print_help()
