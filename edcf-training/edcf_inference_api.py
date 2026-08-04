"""
edcf_inference_api.py — EDCF-Shield Inference API
==================================================
Loads trained TGNN + LLM, serves predictions to routing.cc via HTTP.
Runs alongside blockchain API on port 3001.

Start BEFORE running NS-3:
    python3 edcf_inference_api.py

Endpoints:
    GET  /health               — check both models loaded
    POST /tgnn/predict         — per-node anomaly scores
    POST /llm/predict          — variant label + confidence
    POST /fused/decide         — final fused detection decision
    POST /mitigate/decide      — real-time socket bridge: runs TGNN+LLM
                                  fusion on pre-mitigation telemetry from
                                  routing.cc and returns {decision, ai_delay}
                                  where ai_delay is the ACTUAL measured
                                  wall-clock inference time (time.perf_counter()),
                                  never a hardcoded constant. NS-3 schedules
                                  the firewall drop ai_delay seconds of
                                  simulated time later via Simulator::Schedule,
                                  so EML is authentic end-to-end.
"""

import os, json, time, threading
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from torch_geometric.data import Data
from torch_geometric.nn import GATConv
from scipy.spatial import cKDTree
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from sentence_transformers import SentenceTransformer

# ─────────────────────────────────────────────────────────────
# CONFIG — update paths if needed
# ─────────────────────────────────────────────────────────────
TGNN_WEIGHTS  = "/home/sdvn_mobility_flooding/control-flooding-g14/edcf_traning/edcf_tgnn_best.pt"
LLM_BASE_PATH = "/home/sdvn_mobility_flooding/edcf_models/Mistral-7B-Instruct-v0.3"
LLM_ADAPTER   = "/home/sdvn_mobility_flooding/control-flooding-g14/edcf_traning/edcf_llm_best_adapter"
EMBED_MODEL   = "/home/sdvn_mobility_flooding/edcf_models/all-MiniLM-L6-v2"
RAG_CORPUS_PATH   = "/home/sdvn_mobility_flooding/control-flooding-g14/edcf_traning/rag_corpus.json"
GAMMA_CONFIG_PATH = "/home/sdvn_mobility_flooding/control-flooding-g14/edcf_traning/gamma_config.json"
MU_CONFIG_PATH    = "/home/sdvn_mobility_flooding/control-flooding-g14/edcf_traning/mu_config.json"
RAG_K         = 5     # must match step2_build_llm_dataset.py's RAG_K (training-time value)
PORT          = 3001
DSRC_RANGE    = 270.0

# Per-variant TGNN-LLM fusion weights (Eq 3.72: C_i^(v)(t) = mu*s_TGNN^(v) +
# (1-mu)*p_LLM^(v)), one mu PER VARIANT rather than a single global scalar --
# the report text specifies mu "tuned per variant on validation data",
# mirroring GAMMA below. Calibrated jointly with gamma_v by
# step5_gamma_calibration.py (mu and gamma are coupled: gamma's right value
# depends on what mu it's thresholding, since mu changes the shape of the
# blended confidence distribution). Falls back to a conservative 0.75 for
# any variant missing from mu_config.json.
try:
    with open(MU_CONFIG_PATH) as _f:
        _mucfg = json.load(_f)
    MU = {'V1': _mucfg.get('V1', 0.75), 'V2': _mucfg.get('V2', 0.75), 'V3': _mucfg.get('V3', 0.75)}
except FileNotFoundError:
    MU = {'V1': 0.75, 'V2': 0.75, 'V3': 0.75}
    print("[INIT] WARNING: mu_config.json not found — using uncalibrated 0.75 "
          "fallback for all variants. Run step5_gamma_calibration.py.")

# Per-variant fused-confidence thresholds (Eq 3.72: y_hat_i^(v) = 1[C_i(t) >= gamma_v]),
# calibrated by step5_gamma_calibration.py on the validation set. Falls back to a
# conservative 0.90 for any variant missing from gamma_config.json (fail-closed,
# not fail-open — an uncalibrated threshold should never default to "fires easily").
try:
    with open(GAMMA_CONFIG_PATH) as _f:
        _gcfg = json.load(_f)
    GAMMA = {'V1': _gcfg.get('V1', 0.90), 'V2': _gcfg.get('V2', 0.90), 'V3': _gcfg.get('V3', 0.90)}
    GAMMA_NO_SIGNAL = _gcfg.get('no_signal', {})
except FileNotFoundError:
    GAMMA = {'V1': 0.90, 'V2': 0.90, 'V3': 0.90}
    GAMMA_NO_SIGNAL = {}
    print("[INIT] WARNING: gamma_config.json not found — using uncalibrated 0.90 "
          "fallback for all variants. Run step5_gamma_calibration.py.")

device        = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# ─────────────────────────────────────────────────────────────
# LOAD TGNN
# ─────────────────────────────────────────────────────────────
print(f"[INIT] Loading TGNN from {TGNN_WEIGHTS}...")
ckpt     = torch.load(TGNN_WEIGHTS, map_location=device)
FEAT     = ckpt['feat_cols']
feat_mu  = torch.tensor([ckpt['feat_mean'][f] for f in FEAT], dtype=torch.float)
feat_sd  = torch.tensor([ckpt['feat_std'][f]  for f in FEAT], dtype=torch.float)
feat_sd  = torch.clamp(feat_sd, min=1e-6)
H_DIM    = ckpt['hidden_dim']
N_HEADS  = ckpt['heads']
N_FEAT   = len(FEAT)
label_map= ckpt['label_map']          # {'benign':0,'V1':1,'V2':2,'V3':3}
id2lbl   = {v:k for k,v in label_map.items()}

class TGNN(nn.Module):
    def __init__(self, hidden, heads):
        super().__init__()
        self.g1  = GATConv(N_FEAT,  hidden, heads=heads, dropout=0.3, add_self_loops=True)
        self.g2  = GATConv(hidden*heads, hidden, heads=1, dropout=0.3,
                            concat=False, add_self_loops=True)
        self.b1  = nn.BatchNorm1d(hidden*heads)
        self.b2  = nn.BatchNorm1d(hidden)
        self.gru = nn.GRU(hidden, hidden, num_layers=2, batch_first=True, dropout=0.3)
        self.clf = nn.Sequential(nn.Linear(hidden, hidden//2), nn.ReLU(),
                                 nn.Dropout(0.3), nn.Linear(hidden//2, 4))
    def enc(self, d):
        # Per-node embedding (not pooled) -- matches step1_tgnn_hparam_search.py's
        # architecture so edcf_tgnn_best.pt's weights load and behave consistently.
        x, ei = d.x, d.edge_index
        x = self.b1(F.elu(self.g1(x, ei)))
        x = self.b2(F.elu(self.g2(x, ei)))
        return x  # [N_nodes,hidden]
    def forward(self, snap_list):
        embs = torch.stack([self.enc(s) for s in snap_list], dim=1)  # [N_nodes,T_WIN,hidden]
        _, h = self.gru(embs)
        return self.clf(h[-1])  # [N_nodes,4] -- one prediction per vehicle

tgnn = TGNN(H_DIM, N_HEADS).to(device)
tgnn.load_state_dict(ckpt['model_state'])
tgnn.eval()
print(f"[INIT] TGNN loaded. Features: {FEAT}")

# ─────────────────────────────────────────────────────────────
# LOAD LLM
# ─────────────────────────────────────────────────────────────
print(f"[INIT] Loading LLM from {LLM_BASE_PATH} + adapter...")
llm_tok = AutoTokenizer.from_pretrained(LLM_ADAPTER, trust_remote_code=True)
if llm_tok.pad_token is None:
    llm_tok.pad_token = llm_tok.eos_token
llm_base = AutoModelForCausalLM.from_pretrained(
    LLM_BASE_PATH, device_map='auto',
    torch_dtype=torch.bfloat16, trust_remote_code=True)
llm_model = PeftModel.from_pretrained(llm_base, LLM_ADAPTER)
llm_model.eval()
print("[INIT] LLM loaded.")

# ─────────────────────────────────────────────────────────────
# LOAD RAG CORPUS + EMBEDDER
# ─────────────────────────────────────────────────────────────
# The LLM adapter was fine-tuned on prompts that include a "### Retrieved
# Context" section built by step2_build_llm_dataset.py's retrieve_rag_context()
# — the live prompt previously omitted this entirely (different template from
# what the model was trained on). Reproducing it exactly here needs no LLM
# retraining: the corpus, embedder, and adapter are all already trained; only
# the missing retrieval step is code.
print(f"[INIT] Loading RAG embedder from {EMBED_MODEL}...")
rag_embedder = SentenceTransformer(EMBED_MODEL, device=str(device))
with open(RAG_CORPUS_PATH) as _f:
    _rag_corpus = json.load(_f)
rag_corpus_logs   = [r['log'] for r in _rag_corpus]
rag_corpus_labels = [r['label'] for r in _rag_corpus]
print(f"[INIT] Embedding {len(rag_corpus_logs)} RAG corpus entries "
      f"(one-time cost at startup)...")
rag_corpus_embs = rag_embedder.encode(
    rag_corpus_logs, batch_size=64, show_progress_bar=False,
    normalize_embeddings=True)
print("[INIT] RAG corpus ready.")

def retrieve_rag_context(query_log, K=RAG_K):
    """Top-K most similar corpus entries — mirrors step2's retrieve_rag_context()
    exactly (same corpus, same embedder, same similarity metric, same K, same
    formatting), so live inference sees the same prompt shape the LLM adapter
    was fine-tuned on."""
    q_emb = rag_embedder.encode([query_log], normalize_embeddings=True)[0]
    sims = rag_corpus_embs @ q_emb
    top_k = np.argsort(sims)[-K:][::-1]
    ctx_parts = []
    for k in top_k:
        ctx_parts.append(
            f"[Historical Baseline | sim={sims[k]:.3f}]\n"
            f"{rag_corpus_logs[k][:300]}...")
    return "\n\n".join(ctx_parts)

# ─────────────────────────────────────────────────────────────
# TGNN INFERENCE
# ─────────────────────────────────────────────────────────────
# Sliding window buffer: stores last T_WIN snapshots per scenario
# Must match training (step1_tgnn_hparam_search.py / step4_fusion_eval.py /
# step5_gamma_calibration.py all use T_WIN=5, no padding) — serving T_WIN=3
# with earliest-frame padding fed the GRU a sequence shape/content it never
# saw during training, which was a root cause of the V2a FP saturation.
T_WIN    = 5
snap_buf       = {}   # key: scenario_str → deque of Data objects
snap_buf_cycle = {}   # key: scenario_str → cycle number of the newest entry in snap_buf

def build_snap_from_nodes(nodes_data):
    """
    nodes_data: list of dicts, one per vehicle:
      {node_id, zscore_v1_i, fanout_i, zeta, bcn_rate_i,
       alert_in_i, alert_out_i, pos_x, pos_y}
    Returns: torch_geometric Data object
    """
    rows   = []
    coords = []
    for n in nodes_data:
        row = [(n.get(f, 0.0) - feat_mu[i].item()) / feat_sd[i].item()
               for i, f in enumerate(FEAT)]
        rows.append(row)
        coords.append([n.get('pos_x', 0.0), n.get('pos_y', 0.0)])

    x      = torch.tensor(rows, dtype=torch.float)
    coords = np.array(coords, dtype=float)

    # Build edges within DSRC range
    tree   = cKDTree(coords)
    pairs  = list(tree.query_pairs(DSRC_RANGE))
    if pairs:
        s  = [i for i,j in pairs] + [j for i,j in pairs]
        d  = [j for i,j in pairs] + [i for i,j in pairs]
        ei = torch.tensor([s,d], dtype=torch.long)
    else:
        ei = torch.zeros((2,0), dtype=torch.long)

    gl = torch.zeros(1, dtype=torch.long)  # placeholder graph label
    return Data(x=x, edge_index=ei, graph_label=gl)

def tgnn_predict(nodes_data, scenario_key, cycle_key=None):
    """
    Maintains a sliding window of snapshots.
    Returns: dict of node_id → anomaly_score, plus graph-level variant probs.

    cycle_key: the PEM cycle number this graph snapshot belongs to (optional).
    Multiple flagged nodes in the same cycle now share one cached snapshot
    on the C++ side (routing.cc's per-cycle JSON cache), so repeat calls
    for the same cycle must NOT each push a new entry into the T_WIN=5
    sliding window — that would desync the window from real per-cycle
    steps (up to N duplicate entries per cycle) and reintroduce the same
    train/serve mismatch the T_WIN fix addressed.
    """
    global snap_buf, snap_buf_cycle
    snap = build_snap_from_nodes(nodes_data)

    if scenario_key not in snap_buf:
        snap_buf[scenario_key] = []

    is_duplicate_cycle = (cycle_key is not None
                           and snap_buf_cycle.get(scenario_key) == cycle_key)
    if not is_duplicate_cycle:
        snap_buf[scenario_key].append(snap)
        if cycle_key is not None:
            snap_buf_cycle[scenario_key] = cycle_key
        if len(snap_buf[scenario_key]) > T_WIN:
            snap_buf[scenario_key] = snap_buf[scenario_key][-T_WIN:]

    buf = snap_buf[scenario_key]
    if len(buf) < T_WIN:
        # Not enough real history yet to fill a T_WIN window. Training never
        # saw padded/repeated frames (step1/4/5 only form complete T_WIN=5
        # windows), so fabricating one here would feed the GRU an
        # out-of-distribution sequence — exactly what caused the V2a FP
        # saturation. Report "no signal yet" instead of guessing.
        per_node_probs = {str(n.get('node_id', i)): {'benign': 1.0, 'V1': 0.0, 'V2': 0.0, 'V3': 0.0}
                           for i, n in enumerate(nodes_data)}
        return {
            'variant_probs': {'benign': 1.0, 'V1': 0.0, 'V2': 0.0, 'V3': 0.0},
            'predicted_variant': 'benign',
            'attack_confidence': 0.0,
            'per_node_probs':    per_node_probs,
        }

    def mv(s): return Data(x=s.x.to(device), edge_index=s.edge_index.to(device),
                           graph_label=s.graph_label.to(device))

    # Genuine per-node prediction. TGNN.forward()/enc() no longer mean-pools
    # node embeddings before the classifier (see step1_tgnn_hparam_search.py) --
    # the model was retrained with a real per-vehicle output head, so `logits`
    # here is [N_nodes,4]: one true prediction per vehicle, not one graph-level
    # verdict broadcast to everyone. This replaces the old embedding-deviation
    # heuristic proxy entirely -- no need to approximate per-node behaviour
    # from pre-pooling embeddings anymore, the model gives it natively.
    with torch.no_grad():
        logits = tgnn([mv(s) for s in buf])            # [N_nodes,4]
        probs_per_node = F.softmax(logits, dim=1).cpu().numpy()  # [N_nodes,4]

    per_node_probs = {}
    for i, n in enumerate(nodes_data):
        nid = n.get('node_id', i)
        p = probs_per_node[i]
        per_node_probs[str(nid)] = {
            'benign': float(p[0]), 'V1': float(p[1]), 'V2': float(p[2]), 'V3': float(p[3]),
        }

    # Network-wide aggregate (mean over nodes) — kept for logging/health-check
    # consumers and as the fallback when a specific node_id isn't in this
    # batch, but the actual per-node decision (fused_decide/mitigate_decide)
    # uses per_node_probs for the queried node, not this average.
    mean_probs = probs_per_node.mean(axis=0)
    return {
        'variant_probs': {
            'benign': float(mean_probs[0]),
            'V1':     float(mean_probs[1]),
            'V2':     float(mean_probs[2]),
            'V3':     float(mean_probs[3]),
        },
        'predicted_variant': id2lbl[int(np.argmax(mean_probs))],
        'attack_confidence': float(1.0 - mean_probs[0]),
        'per_node_probs':    per_node_probs,
    }

# ─────────────────────────────────────────────────────────────
# LLM INFERENCE
# ─────────────────────────────────────────────────────────────
# Must match step2_build_llm_dataset.py's SYS EXACTLY — this is literally what
# the LoRA adapter was fine-tuned against. The previous shorter/generic prompt
# here was a different instruction than the one used in training, which is a
# real cause of degenerate live predictions independent of missing telemetry.
SYS = (
    "You are an SDVN (Software-Defined Vehicular Network) security analyst "
    "monitoring the SDN control plane in real time. "
    "Classify the following monitoring window log as:\n"
    "  benign — normal operation\n"
    "  V1 — Spoofed Beacon Flooding (table-miss surge, beacon-rate anomaly)\n"
    "  V2 — Cascading Alert Propagation (broadcast amplification storm)\n"
    "  V3 — Mobility Trace Manipulation (topology corruption, forged traces)\n"
    "Return ONLY valid JSON: "
    "{\"label\":\"...\",\"confidence\":0.0-1.0,\"evidence\":\"one sentence\"}"
)

def build_log_text(w):
    """Convert a window metrics dict (from routing.cc) to log text.
    Must match step2_build_llm_dataset.py's row_to_log() EXACTLY — same
    fields, same layout — since that's the log format inside every training
    example (both the "Current Window Log" and every retrieved-context entry).
    A different field set here means the fine-tuned model is being queried
    with a shape it never saw during training."""
    return (
        f"[Window {int(w.get('cycle',0))} | t={w.get('time_s',0):.0f}s | "
        f"Window={w.get('row_type','CYCLE')}]\n"
        f"Traffic Telemetry: CDR={w.get('CDR',1.0):.4f} | "
        f"ChLoad={w.get('ch_load_pct',0):.1f}% | "
        f"CCR={w.get('CCR',1)} | MCR={w.get('MCR',0)} | "
        f"eta_c={w.get('eta_c',0):.4f}\n"
        f"Signal Features: delta_tm={w.get('delta_tm_rate',0):.3f}% | "
        f"gamma={w.get('gamma',1):.4f} | eps_topo={w.get('eps_topo',0):.4f} | "
        f"hmac_ok={w.get('hmac_valid_pct',1):.3f}"
    )

import re
def llm_predict(window_metrics):
    log_text = build_log_text(window_metrics)
    ctx      = retrieve_rag_context(log_text, K=RAG_K)
    # Must match step2_build_llm_dataset.py's prompt assembly EXACTLY
    # (SYS || CTX || LOG || QUERY, Eq 3.87) — the adapter was fine-tuned on
    # this exact template, "### Retrieved Context" section included.
    prompt = (
        f"### Instruction:\n{SYS}\n\n"
        f"### Retrieved Context (top-{RAG_K} similar historical windows):\n{ctx}\n\n"
        f"### Current Window Log:\n{log_text}\n\n"
        f"### Response:\n"
    )

    inp = llm_tok(prompt, return_tensors='pt',
                  truncation=True, max_length=1792).to(device)
    with torch.no_grad():
        out = llm_model.generate(
            **inp, max_new_tokens=80, do_sample=False,
            repetition_penalty=1.1,
            pad_token_id=llm_tok.eos_token_id)
    gen = llm_tok.decode(out[0][inp['input_ids'].shape[1]:],
                         skip_special_tokens=True)
    print(f"[DEBUG] Raw LLM text: {gen!r}", flush=True)

    # Parse JSON
    try:
        result = json.loads(gen)
        label  = result.get('label', 'benign')
        conf   = float(result.get('confidence', 0.5))
        evid   = result.get('evidence', '')
        print(f"[DEBUG] Parsed via json.loads: label={label} conf={conf}", flush=True)
    except Exception as e:
        m = re.search(r'"label"\s*:\s*"([^"]+)"', gen)
        label = m.group(1) if m else 'benign'
        # Try to recover a real confidence from the raw text before
        # giving up — json.loads() failing (e.g. truncated generation,
        # trailing text after the JSON) doesn't mean no confidence was
        # ever emitted by the model.
        cm = re.search(r'"confidence"\s*:\s*([0-9]*\.?[0-9]+)', gen)
        conf = float(cm.group(1)) if cm else 0.5
        evid = gen[:100]
        for lbl in ['V1','V2','V3','benign']:
            if lbl in gen:
                label = lbl; break
        print(f"[DEBUG] json.loads FAILED ({e}); regex fallback: "
              f"label={label} conf={conf} (matched={'yes' if cm else 'NO — defaulted to 0.5'})",
              flush=True)

    # Convert to prob vector
    probs = {k: 0.05 for k in ['benign','V1','V2','V3']}
    probs[label] = conf
    total = sum(probs.values())
    probs = {k: v/total for k,v in probs.items()}

    return {
        'label':      label,
        'confidence': conf,
        'evidence':   evid,
        'variant_probs': probs,
    }

# ─────────────────────────────────────────────────────────────
# FUSED DECISION
# ─────────────────────────────────────────────────────────────
def fused_decide(tgnn_result, llm_result, mu=None, gamma=None, node_id=None):
    """Eq 3.72: C_i^(v)(t) = mu_v*s_TGNN^(v) + (1-mu_v)*p_LLM^(v), and
    independently per variant y_hat_i^(v) = 1[C_i^(v)(t) >= gamma_v]. mu is
    PER-VARIANT (mu_V1, mu_V2, mu_V3 -- see MU above), not one global
    scalar shared by all three, mirroring gamma's per-variant calibration.
    This is a multi-label decision (a node can trip more than one variant,
    or none) — NOT a single 4-way argmax winner, which is what this used to
    do. Argmax forces every node into some label even when its confidence
    is below any reasonable bar, which is what produced runaway false
    positives once the AI query was decoupled from the rule-based gate
    (see V2 rerun).

    mu: None (default) uses the calibrated per-variant MU dict; a single
    float broadcasts that one value to all three variants (useful for
    sensitivity sweeps / backward-compatible callers); a dict
    {"V1":.., "V2":.., "V3":..} overrides individual variants, falling back
    to MU for any missing key.

    node_id, if given, uses THIS vehicle's own per-node prediction
    (tgnn_result['per_node_probs'][node_id]) instead of the network-wide
    mean -- this is what actually makes per-node mitigation decisions differ
    from one node to the next, now that the TGNN has a real per-node head.
    Falls back to the network-wide 'variant_probs' when node_id is None or
    not present in this batch (e.g. /fused/decide callers that only pass
    pre-aggregated results, or the T_WIN cold-start case)."""
    if gamma is None:
        gamma = GAMMA
    if mu is None:
        mu = MU
    elif isinstance(mu, (int, float)):
        mu = {v: float(mu) for v in ['V1', 'V2', 'V3']}
    # else: assume an already per-variant dict, e.g. a partial HTTP override
    per_node = tgnn_result.get('per_node_probs') or {}
    if node_id is not None and str(node_id) in per_node:
        tp = per_node[str(node_id)]
    else:
        tp = tgnn_result['variant_probs']
    lp = llm_result['variant_probs']
    # Per-variant confidence — NOT renormalised across classes (that's what
    # entangled variants together before: raising one score forced the others
    # down regardless of their own evidence). Each variant stands on its own,
    # blended with ITS OWN mu_v.
    conf = {v: mu.get(v, MU.get(v, 0.75))*tp.get(v, 0.0)
             + (1-mu.get(v, MU.get(v, 0.75)))*lp.get(v, 0.0)
            for v in ['V1', 'V2', 'V3']}
    decisions = {v: bool(conf[v] >= gamma.get(v, 0.90)) for v in ['V1', 'V2', 'V3']}
    is_attack = any(decisions.values())
    if is_attack:
        label = max((v for v in decisions if decisions[v]), key=lambda v: conf[v])
        confidence = conf[label]
    else:
        label = 'benign'
        confidence = tp.get('benign', 0.0)
    return {
        'label':                label,
        'confidence':           confidence,
        'is_attack':            is_attack,
        'per_variant_confidence': conf,
        'per_variant_decision':   decisions,
        'gamma':                gamma,
        'tgnn_probs':           tp,
        'llm_probs':            lp,
        'mu':                   mu,
    }

# ─────────────────────────────────────────────────────────────
# REAL-TIME MITIGATION BRIDGE — Socket-Driven Time-Accurate Bridge
# ─────────────────────────────────────────────────────────────
# Called synchronously by routing.cc for a single flagged node.
# Runs the SAME TGNN+LLM fusion pipeline as the offline eval scripts,
# on live pre-mitigation telemetry, and reports the true wall-clock
# cost of that inference. No shortcuts, no hardcoded latency — if the
# LLM takes 1.4s to generate, ai_delay IS 1.4s, and NS-3 will schedule
# the firewall rule that many simulated seconds later.
def mitigate_decide(body):
    t0 = time.perf_counter()

    scenario = body.get('scenario', 'v1a')
    node_id  = body.get('node_id')
    nodes    = body.get('nodes', [])
    window   = body.get('window', {})

    tgnn_result = tgnn_predict(nodes, scenario, cycle_key=window.get('cycle'))
    # C_i^(v)(t) = mu_v*s_TGNN^(v) + (1-mu_v)*p_LLM^(v) (Eq 3.72) — per variant.
    # The LLM call is shared across all three variants' blends (one window
    # log -> one LLM verdict), so it can only be skipped if EVERY variant's
    # mu_v is already 1.0 (the LLM term is zero-weighted everywhere); if even
    # one variant still needs it, we must run it. Re-enables itself
    # automatically once any mu_v is recalibrated away from 1.0.
    if all(MU.get(v, 0.75) >= 1.0 - 1e-9 for v in ['V1', 'V2', 'V3']):
        llm_result = {
            'label': 'skipped_mu1', 'confidence': 0.0,
            'evidence': 'LLM bypassed: mu_v=1.0 for every variant gives it zero fusion weight',
            'variant_probs': {'benign': 0.0, 'V1': 0.0, 'V2': 0.0, 'V3': 0.0},
        }
    else:
        llm_result = llm_predict(window)
    fused       = fused_decide(tgnn_result, llm_result, node_id=node_id)
    node_tgnn_probs = (tgnn_result.get('per_node_probs') or {}).get(str(node_id), tgnn_result['variant_probs'])
    print(f"[DEBUG] node={node_id} tgnn_probs(this node)={node_tgnn_probs} "
          f"tgnn_probs(network mean)={tgnn_result['variant_probs']} "
          f"llm_probs={llm_result['variant_probs']} MU={MU} "
          f"per_variant_conf={fused['per_variant_confidence']} "
          f"gamma={fused['gamma']} decisions={fused['per_variant_decision']} "
          f"-> label={fused['label']} confidence={fused['confidence']:.4f}", flush=True)

    t1 = time.perf_counter()
    ai_delay = t1 - t0   # REAL measured inference latency — Eq/EML authentic

    return {
        'decision':   'DROP' if fused['is_attack'] else 'ALLOW',
        'ai_delay':   ai_delay,
        'node_id':    node_id,
        'label':      fused['label'],
        'confidence': fused['confidence'],
        'tgnn_variant': tgnn_result['predicted_variant'],
        'llm_label':    llm_result['label'],
    }

# ─────────────────────────────────────────────────────────────
# HTTP SERVER — threaded so LLM inference does not block logging
# ─────────────────────────────────────────────────────────────
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a separate thread."""
    daemon_threads = True

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence per-request logs

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n)) if n > 0 else {}

    def do_GET(self):
        if self.path == '/health':
            self.send_json(200, {
                'status':  'ok',
                'models':  ['TGNN','LLM-Mistral-7B-r16'],
                'device':  str(device),
                'port':    PORT,
                'fusion_mu': MU,
                'gamma': GAMMA,
                'gamma_no_signal': GAMMA_NO_SIGNAL,
                'rag_corpus_size': len(rag_corpus_logs),
            })
        else:
            self.send_json(404, {'error': 'not found'})

    def do_POST(self):
        # Log immediately on receipt — before any slow inference
        print(f"[API {time.strftime("%H:%M:%S")}] >>> {self.path} received", flush=True)
        try:
            body = self.read_body()

            if self.path == '/tgnn/predict':
                # body: {scenario, nodes:[{node_id, zscore_v1_i, ...}]}
                scenario = body.get('scenario', 'v1a')
                nodes    = body.get('nodes', [])
                result   = tgnn_predict(nodes, scenario)
                print(f"[API {time.strftime("%H:%M:%S")}] TGNN → "
                      f"{result['predicted_variant']} "
                      f"atk_conf={result['attack_confidence']:.3f}", flush=True)
                self.send_json(200, result)

            elif self.path == '/llm/predict':
                # body: window metrics dict (same keys as edcf_pem CSV)
                t0 = time.time()
                result = llm_predict(body)
                elapsed = time.time() - t0
                print(f"[API {time.strftime("%H:%M:%S")}] LLM → label={result['label']} "
                      f"conf={result['confidence']:.2f} ({elapsed:.1f}s)", flush=True)
                self.send_json(200, result)

            elif self.path == '/mitigate/decide':
                # body: {node_id, scenario, window:{...}, nodes:[{...}]}
                t0 = time.time()
                result = mitigate_decide(body)
                print(f"[API {time.strftime("%H:%M:%S")}] MITIGATE node={result['node_id']} "
                      f"→ {result['decision']} ai_delay={result['ai_delay']*1000:.1f}ms "
                      f"label={result['label']} conf={result['confidence']:.2f}", flush=True)
                self.send_json(200, result)

            elif self.path == '/fused/decide':
                # body: {tgnn_result:{...}, llm_result:{...}, mu:float|dict}
                # mu omitted -> calibrated per-variant MU; a single float
                # broadcasts to all three variants (sensitivity-sweep
                # overrides); a dict {"V1":..,"V2":..,"V3":..} overrides
                # individual variants. See fused_decide()'s docstring.
                tr  = body.get('tgnn_result', {})
                lr  = body.get('llm_result',  {})
                mu  = body.get('mu', None)
                result = fused_decide(tr, lr, mu)
                self.send_json(200, result)

            elif self.path == '/reset':
                # Called between simulation runs to clear snap buffer
                global snap_buf, snap_buf_cycle
                snap_buf = {}
                snap_buf_cycle = {}
                self.send_json(200, {'status': 'reset'})

            else:
                self.send_json(404, {'error': 'not found'})

        except Exception as e:
            self.send_json(500, {'error': str(e)})


if __name__ == '__main__':
    print(f"[API] EDCF Inference API listening on http://localhost:{PORT}")
    print(f"[API]   TGNN features : {FEAT}")
    print(f"[API]   Fusion μ      : {MU}")
    server = ThreadedHTTPServer(('0.0.0.0', PORT), Handler)
    print(f"[API] Multi-threaded server ready — LLM inference will not block", flush=True)
    server.serve_forever()