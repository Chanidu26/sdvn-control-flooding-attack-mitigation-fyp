"""
step5_gamma_calibration.py — Joint Per-Variant (mu_v, gamma_v) Calibration
============================================================================
Report Eq 3.72: C_i^(v)(t) = mu*s_TGNN_i^(v)(t) + (1-mu)*p_LLM^(v)(t),
                y_hat_i^(v) = 1[C_i^(v)(t) >= gamma_v]
and the surrounding report text: "mu in [0,1] tuned per variant on validation
data" -- i.e. mu itself is meant to be per-variant (mu_V1, mu_V2, mu_V3),
exactly like gamma_v already is, NOT one global scalar shared by all three
variants.

This SUPERSEDES the previous version of this script, which calibrated
gamma_v alone using conf = FUSION_MU * va_prob -- a fixed GLOBAL FUSION_MU
with the LLM term omitted entirely. That shortcut is only exact at
FUSION_MU=1.0; the actual runtime constant was 0.75, so the old
gamma_config.json was silently calibrated against an incomplete formula
(missing (1-mu)*p_LLM^(v) altogether). This version runs the real LLM over
the validation set (like step4_fusion_eval.py) and searches mu_v and gamma_v
JOINTLY, independently per variant -- gamma_v's right value depends on what
mu_v it's thresholding (mu changes the shape of the blended confidence
distribution C^(v)), so the two cannot be calibrated independently without
one silently miscalibrating the other.

Uses the SAME validation split as step4_fusion_eval.py / the previous
version of this script (no test-set leakage). TGNN sequences and LLM
validation examples are joined PER (scenario, atk_count) GROUP,
POSITIONALLY, in chronological order within that group -- NOT by an exact
(scenario, atk_count, cycle) key. An exact-key join was tried first and
found ZERO matches: tgnn_node_features.csv and edcf_pem_v*.csv are two
independently append-only files, accumulated across different sets of
ad-hoc NS-3 runs over the project's history, and do not share absolute
cycle numbering for the same (scenario, atk_count) group (e.g. v1a/atk=0
spans cycles [0,14] in tgnn_node_features.csv but [1,90] in
edcf_pem_v1.csv). The per-group positional join used here is the same
tolerance step4_fusion_eval.py's global (ungrouped) positional zip already
relies on, just scoped per group so pairs never cross between different
scenarios/attack counts. LLM outputs are cached to
mu_calibration_llm_cache.json as they're computed, so a crash in the
join/sweep logic below never throws away completed (slow) LLM generation
work on a re-run.

Run (real LLM generation over the validation set -- slow, run yourself;
per project policy this is never auto-run):
  cd ~/control-flooding-g14/edcf_traning
  python3 step5_gamma_calibration.py

Output:
  mu_gamma_calibration_sweep.csv — full (variant, mu, gamma, val_MCC) sweep evidence
  mu_config.json                 — {"V1":mu1, "V2":mu2, "V3":mu3}
  gamma_config.json              — {"V1":g1, "V2":g2, "V3":g3, "no_signal": {...}}
                                    (gamma_v is now the best gamma AT THAT
                                    VARIANT'S OWN calibrated mu_v, not at a
                                    shared global mu -- see module docstring)
  mu_calibration_llm_cache.json  — raw per-window LLM prediction cache; delete
                                    to force a clean recompute
"""
import json
import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GATConv
from scipy.spatial import cKDTree
from sklearn.metrics import matthews_corrcoef
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
label_map = {'benign': 0, 'V1': 1, 'V2': 2, 'V3': 3}

LLM_BASE_PATH = "/home/sdvn_mobility_flooding/edcf_models/Mistral-7B-Instruct-v0.3"
ADAPTER = "edcf_llm_best_adapter"

MU_GRID = np.arange(0.0, 1.01, 0.05)
GAMMA_GRID = np.arange(0.05, 0.96, 0.01)

# ── TGNN (same architecture as step1/step4/previous step5) ───────────────
print("Loading TGNN...")
ckpt = torch.load('edcf_tgnn_best.pt', map_location=device)
FEAT = ckpt['feat_cols']
feat_mu = pd.Series(ckpt['feat_mean'])
feat_sd = pd.Series(ckpt['feat_std'])
H, HEADS, N_F = ckpt['hidden_dim'], ckpt['heads'], len(FEAT)


class TGNN(nn.Module):
    def __init__(self, hidden, heads):
        super().__init__()
        self.g1 = GATConv(N_F, hidden, heads=heads, dropout=0.3, add_self_loops=True)
        self.g2 = GATConv(hidden*heads, hidden, heads=1, dropout=0.3, concat=False, add_self_loops=True)
        self.b1 = nn.BatchNorm1d(hidden*heads)
        self.b2 = nn.BatchNorm1d(hidden)
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

    def forward(self, sl):
        embs = torch.stack([self.enc(s) for s in sl], dim=1)  # [N_nodes,T_WIN,hidden]
        _, h = self.gru(embs)
        return self.clf(h[-1])  # [N_nodes,4]


tgnn = TGNN(H, HEADS).to(device)
tgnn.load_state_dict(ckpt['model_state'])
tgnn.eval()
T_WIN, DSRC = 5, 270.0


def build_snap(grp):
    xn = ((grp[FEAT]-feat_mu)/feat_sd).values
    x = torch.tensor(xn, dtype=torch.float)
    y = torch.tensor([label_map.get(l, 0) for l in grp['label']], dtype=torch.long)
    xy = grp[['pos_x', 'pos_y']].values.astype(float)
    pairs = list(cKDTree(xy).query_pairs(DSRC))
    if pairs:
        s = [i for i, j in pairs] + [j for i, j in pairs]
        d = [j for i, j in pairs] + [i for i, j in pairs]
        ei = torch.tensor([s, d], dtype=torch.long)
    else:
        ei = torch.zeros((2, 0), dtype=torch.long)
    gl = torch.tensor([int(y.mode().values.item())], dtype=torch.long)
    return Data(x=x, edge_index=ei, y=y, graph_label=gl)


def mv(sl):
    return [Data(x=s.x.to(device), edge_index=s.edge_index.to(device),
                 y=s.y.to(device), graph_label=s.graph_label.to(device)) for s in sl]


def tgnn_predict_proba_per_node(seq_list):
    # Eq 3.72 is explicitly per-node: y_hat_i^(v) = 1[C_i(t) >= gamma_v].
    # Calibration must therefore compare each vehicle's own predicted
    # probability against its own true label -- NOT a window-averaged
    # probability against a majority-vote graph_label.
    with torch.no_grad():
        logits = tgnn(mv(seq_list))            # [N_nodes,4]
        probs = F.softmax(logits, dim=1)
        return probs.cpu().numpy()             # [N_nodes,4]


print("Loading TGNN node features + rebuilding the SAME split as step4...")
df = pd.read_csv('tgnn_node_features.csv')
DROP = ['phi_v1_i', 'phi_v2_i', 'phi_v3_i', 'tau_dir', 'fm_count_i']
df = df.drop(columns=[c for c in DROP if c in df.columns])
# De-duplicate to one row per vehicle per snapshot -- see step1_tgnn_hparam_search.py
# for why (append-only CSV + repeated ad-hoc runs of the same scenario/atk_count).
df = df.drop_duplicates(subset=['scenario', 'atk_count', 'cycle', 'node_id'], keep='last')

# Chronological 70/15/15 split of CYCLES WITHIN each (scenario,atk_count)
# group -- matches step1_tgnn_hparam_search.py's actual split methodology.
df_va_rows, df_te_rows = [], []
for (sc, atk), sub in df.groupby(['scenario', 'atk_count']):
    sub_sorted = sub.sort_values('cycle').reset_index(drop=True)
    cycles = sorted(sub_sorted['cycle'].unique())
    n_va = max(T_WIN, int(len(cycles) * 0.15))
    n_te = max(T_WIN, int(len(cycles) * 0.15))
    n_tr = len(cycles) - n_va - n_te
    va_cycles = cycles[n_tr:n_tr+n_va]
    te_cycles = cycles[n_tr+n_va:]
    df_va_rows.append(sub_sorted[sub_sorted['cycle'].isin(va_cycles)])
    df_te_rows.append(sub_sorted[sub_sorted['cycle'].isin(te_cycles)])
df_va = pd.concat(df_va_rows).reset_index(drop=True)

va_snaps = {}
for keys, g in df_va.groupby(['scenario', 'atk_count', 'cycle']):
    va_snaps[keys] = build_snap(g.reset_index(drop=True))

# Keep the (scenario, atk_count, end_cycle) key alongside each sequence so it
# can be joined to the matching LLM validation example below -- the previous
# version of this script (and step4_fusion_eval.py's validation-set mu sweep)
# discarded this key and zipped TGNN/LLM lists positionally instead.
va_seqs = []
for (sc, atk), sub in df_va.groupby(['scenario', 'atk_count']):
    cycs = sorted(sub['cycle'].unique())
    for s in range(len(cycs) - T_WIN + 1):
        win = cycs[s:s + T_WIN]
        sl = [va_snaps.get((sc, atk, c)) for c in win]
        if all(x is not None for x in sl):
            va_seqs.append((sl, sc, int(atk), int(win[-1])))
print(f"TGNN validation sequences: {len(va_seqs)}")

print("Running TGNN on validation set (per-node)...")
# Grouped by (scenario, atk_count), in chronological (window-end-cycle) order.
# NOTE: tgnn_node_features.csv and edcf_pem_v*.csv are two INDEPENDENTLY
# append-only files, accumulated across different sets of ad-hoc NS-3 runs
# over the project's history -- they do NOT share absolute cycle numbering
# for the same (scenario, atk_count) group (e.g. v1a/atk=0 spans cycles
# [0,14] in tgnn_node_features.csv but [1,90] in edcf_pem_v1.csv). An exact
# (scenario, atk_count, cycle) join therefore finds zero matches. Instead,
# TGNN and LLM validation examples are aligned POSITIONALLY within each
# (scenario, atk_count) group's own chronological order -- the k-th
# validation-window TGNN sequence pairs with the k-th validation-window LLM
# example for that same group. This is the same tolerance step4_fusion_eval.py's
# global (ungrouped) positional zip already relies on, just scoped per group
# so pairs never cross between different scenarios/attack counts.
tgnn_by_group = {}   # (sc, atk) -> ordered list of (probs [N_nodes,4], true [N_nodes])
for sl, sc, atk, end_cycle in va_seqs:
    probs = tgnn_predict_proba_per_node(sl)
    true = sl[-1].y.cpu().numpy()
    tgnn_by_group.setdefault((sc, int(atk)), []).append((probs, true))

# ── Load fine-tuned LLM (same as step4_fusion_eval.py) ────────────────────
print("Loading fine-tuned LLM...")
llm_tok = AutoTokenizer.from_pretrained(ADAPTER, trust_remote_code=True)
if llm_tok.pad_token is None:
    llm_tok.pad_token = llm_tok.eos_token
llm_base = AutoModelForCausalLM.from_pretrained(
    LLM_BASE_PATH, device_map='auto', torch_dtype=torch.bfloat16, trust_remote_code=True)
llm_model = PeftModel.from_pretrained(llm_base, ADAPTER)
llm_model.eval()
print("LLM loaded.")


def llm_predict_proba(prompt_text):
    inp = llm_tok(prompt_text, return_tensors='pt', truncation=True, max_length=1792).to(device)
    with torch.no_grad():
        out = llm_model.generate(**inp, max_new_tokens=80, do_sample=False,
                                  repetition_penalty=1.1, pad_token_id=llm_tok.eos_token_id)
    gen = llm_tok.decode(out[0][inp['input_ids'].shape[1]:], skip_special_tokens=True)
    try:
        d = json.loads(gen)
        lbl = d.get('label', 'benign')
        conf = float(d.get('confidence', 0.9))
        proba = np.array([0.05, 0.05, 0.05, 0.05])
        proba[label_map.get(lbl, 0)] = conf
        proba = proba / proba.sum()
    except Exception:
        lbl_found = 'benign'
        for l in ['V1', 'V2', 'V3', 'benign']:
            if l in gen:
                lbl_found = l
                break
        proba = np.array([0.05, 0.05, 0.05, 0.05])
        proba[label_map.get(lbl_found, 0)] = 0.85
        proba = proba / proba.sum()
    return proba


print("Loading LLM validation examples (row_type=CYCLE only, to match TGNN's cycle granularity)...")
with open('llm_val.json') as f:
    llm_va = json.load(f)
llm_va_cycle = [r for r in llm_va if r.get('row_type') == 'CYCLE']
llm_va_cycle.sort(key=lambda r: (r['scenario'], int(r['atk_count']), int(r['cycle'])))
print(f"LLM validation examples (CYCLE rows): {len(llm_va_cycle)} of {len(llm_va)} total")

# Cache raw LLM outputs to disk as they're computed -- this loop is the slow
# part (real generate() calls, tens of minutes), and a downstream crash
# (e.g. the join/sweep logic) would otherwise throw all of that work away.
# Safe to reuse across re-runs as long as llm_val.json / the LLM adapter
# haven't changed; delete the cache file to force a clean recompute.
LLM_CACHE_PATH = 'mu_calibration_llm_cache.json'
llm_cache = {}
if os.path.exists(LLM_CACHE_PATH):
    with open(LLM_CACHE_PATH) as f:
        llm_cache = json.load(f)
    print(f"Loaded {len(llm_cache)} cached LLM predictions from {LLM_CACHE_PATH}")

print("Running LLM on validation set (this is the slow part -- real generate() calls)...")
llm_by_group = {}   # (sc, atk) -> ordered list of probs (same chronological order as llm_va_cycle)
for i, r in enumerate(llm_va_cycle):
    key = (r['scenario'], int(r['atk_count']))
    cache_key = f"{r['scenario']}|{int(r['atk_count'])}|{int(r['cycle'])}"
    if cache_key in llm_cache:
        probs = np.array(llm_cache[cache_key])
    else:
        prompt = r['text'].split("### Response:\n")[0] + "### Response:\n"
        probs = llm_predict_proba(prompt)
        llm_cache[cache_key] = probs.tolist()
    llm_by_group.setdefault(key, []).append(probs)
    if (i + 1) % 50 == 0:
        print(f"  {i + 1}/{len(llm_va_cycle)} done...")
        with open(LLM_CACHE_PATH, 'w') as f:
            json.dump(llm_cache, f)
with open(LLM_CACHE_PATH, 'w') as f:
    json.dump(llm_cache, f)

# ── Join TGNN and LLM validation data: per-(scenario,atk_count) group, ────
# ── positionally in chronological order (see note above tgnn_by_group) ───
node_tgnn_probs, node_llm_probs, node_true = [], [], []
total_pairs = 0
for key, t_list in tgnn_by_group.items():
    l_list = llm_by_group.get(key)
    if not l_list:
        continue
    n_pairs = min(len(t_list), len(l_list))
    total_pairs += n_pairs
    for i in range(n_pairs):
        t_probs, t_true = t_list[i]
        l_probs = l_list[i]
        n = t_probs.shape[0]
        node_tgnn_probs.append(t_probs)
        # Same window-level LLM probs broadcast to every node in that window
        # -- the LLM analyzes the network-wide window log, not individual
        # vehicles, exactly like the live fused_decide() broadcast.
        node_llm_probs.append(np.tile(l_probs, (n, 1)))
        node_true.append(t_true)
print(f"Joined (TGNN sequence, LLM prediction) pairs: {total_pairs} "
      f"(per-group positional alignment across {len(tgnn_by_group)} TGNN groups / "
      f"{len(llm_by_group)} LLM groups)")
if total_pairs < 20:
    print("[WARN] Very few joined validation examples -- the mu/gamma calibration "
          "below may be unreliable.")

node_tgnn_probs = np.concatenate(node_tgnn_probs, axis=0)   # [N,4]
node_llm_probs = np.concatenate(node_llm_probs, axis=0)     # [N,4]
node_true = np.concatenate(node_true, axis=0)                # [N]
print(f"Total per-node validation samples for calibration: {len(node_true)}")

# ── Joint (mu_v, gamma_v) sweep, independently per variant ────────────────
# Conservative fallbacks when NO (mu,gamma) combo in the sweep beats MCC=0
# (i.e. neither model carries discriminating signal for that variant): pick
# a high, hard-to-reach gamma and mu=1.0 (trust TGNN alone, since an
# uninformative LLM term should get zero weight) instead of trusting an
# arbitrary tie-break among equally-uninformative points. Mirrors the
# previous version's NO_SIGNAL_FALLBACK_GAMMA reasoning.
NO_SIGNAL_FALLBACK_GAMMA = 0.90
NO_SIGNAL_FALLBACK_MU = 1.0

rows = []
best_mu, best_gamma, no_signal = {}, {}, {}
for v, name in [(1, 'V1'), (2, 'V2'), (3, 'V3')]:
    y_true_bin = (node_true == v).astype(int)
    tgnn_c = node_tgnn_probs[:, v]
    llm_c = node_llm_probs[:, v]

    overall_best_mcc = -1.0
    overall_best_mu, overall_best_gamma = NO_SIGNAL_FALLBACK_MU, NO_SIGNAL_FALLBACK_GAMMA
    for mu in MU_GRID:
        c = mu * tgnn_c + (1 - mu) * llm_c
        best_mcc_this_mu, best_gamma_this_mu = -1.0, 0.5
        for g in GAMMA_GRID:
            y_pred = (c >= g).astype(int)
            if y_pred.sum() == 0 or y_pred.sum() == len(y_pred):
                mcc = 0.0
            else:
                mcc = matthews_corrcoef(y_true_bin, y_pred)
            rows.append({'variant': name, 'mu': round(float(mu), 2),
                         'gamma': round(float(g), 2), 'val_MCC': round(mcc, 4)})
            if mcc > best_mcc_this_mu:
                best_mcc_this_mu, best_gamma_this_mu = mcc, g
        if best_mcc_this_mu > overall_best_mcc:
            overall_best_mcc = best_mcc_this_mu
            overall_best_mu = mu
            overall_best_gamma = best_gamma_this_mu

    if overall_best_mcc <= 0.0:
        best_mu[name] = NO_SIGNAL_FALLBACK_MU
        best_gamma[name] = NO_SIGNAL_FALLBACK_GAMMA
        no_signal[name] = True
        print(f"  {name}: NO discriminating (mu,gamma) found -- MCC=0 everywhere in "
              f"the sweep. Falling back to mu={NO_SIGNAL_FALLBACK_MU}, "
              f"gamma={NO_SIGNAL_FALLBACK_GAMMA}. Needs retraining/re-fine-tuning to "
              f"actually detect {name}.")
    else:
        best_mu[name] = round(float(overall_best_mu), 2)
        best_gamma[name] = round(float(overall_best_gamma), 2)
        no_signal[name] = False
        print(f"  {name}: mu={overall_best_mu:.2f} gamma={overall_best_gamma:.2f} "
              f"(val_MCC={overall_best_mcc:.4f})")

pd.DataFrame(rows).to_csv('mu_gamma_calibration_sweep.csv', index=False)
with open('mu_config.json', 'w') as f:
    json.dump(best_mu, f, indent=2)
with open('gamma_config.json', 'w') as f:
    json.dump({**best_gamma, 'no_signal': no_signal}, f, indent=2)

print("\nSaved mu_gamma_calibration_sweep.csv, mu_config.json, gamma_config.json")
print("mu:", best_mu)
print("gamma:", best_gamma)
print("no_signal:", no_signal)
