"""
step2_build_llm_dataset.py  —  Build LLM Fine-tuning Dataset with RAG
======================================================================
Per report Section 3.10.1 and AI/ML Plan Section 2.2:
  - Converts NS-3 PEM window logs to instruction-tuning format
  - Builds RAG corpus from blockchain-style log history
  - Embeds corpus with all-MiniLM-L6-v2 (Eq 3.85-3.86)
  - At each example: retrieves top-K similar historical logs as context
  - Output matches prompt template P(t) = [SYS || CTX || LOG || QUERY] (Eq 3.87)

Leakage controls:
  - The 70/15/15 split is done FIRST, at the window level: a window's
    CYCLE and CUMULATIVE rows always land in the same split, so no test
    row has a near-duplicate twin in train.
  - The RAG corpus contains TRAIN windows only, so retrieved context
    (which shows labels) never exposes val/test ground truth.
  - Retrieval additionally excludes any corpus row from the query's own
    window (same scenario, atk_count, cycle), so a train example cannot
    retrieve itself or its CYCLE/CUMULATIVE twin.
  - Target confidence is derived from the window's own detection-signal
    magnitude (normalized by train attack-class medians), not a fixed
    per-class constant.

Outputs:
  llm_train.json     ← training examples with RAG context
  llm_val.json       ← validation examples
  llm_test.json      ← test examples
  rag_corpus.json    ← retrieval corpus (train windows only)

Run:
  cd ~/control-flooding-g14/edcf_traning
  python3 step2_build_llm_dataset.py
"""

import json, random
from collections import Counter, defaultdict
import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer

MODELS_ROOT = "/home/sdvn_mobility_flooding/edcf_models"
EMBED_MODEL  = f"{MODELS_ROOT}/all-MiniLM-L6-v2"
RAG_K        = 5     # top-K retrieved entries per example (swept later)
SEED         = 42
random.seed(SEED); np.random.seed(SEED)

# ── 1. Load PEM CSVs ──────────────────────────────────────────
print("Loading PEM CSVs...")
v1 = pd.read_csv('edcf_pem_v1.csv', comment='#')
v2 = pd.read_csv('edcf_pem_v2.csv', comment='#')
v3 = pd.read_csv('edcf_pem_v3.csv', comment='#')
pem = pd.concat([v1,v2,v3], ignore_index=True)

# Use ALL rows (both CYCLE and CUMULATIVE) for more data
print(f"Total rows: {len(pem)}  Label dist:\n{pem['label'].value_counts()}")

# ── 2. Window-level 70/15/15 temporal split (BEFORE retrieval) ─
# Within each run (scenario, atk_count): sort unique cycles, first 70%
# of windows → train, next 15% → val, last 15% → test. Both rows of a
# window (CYCLE + CUMULATIVE) share its split. Matches the TGNN split
# (step1_tgnn_hparam_search.py) exactly.
def window_key(r):
    return (r['scenario'], int(r['atk_count']), int(r['cycle']))

split_of_window = {}
for (sc, atk), grp in pem.groupby(['scenario','atk_count']):
    cycles = sorted(grp['cycle'].unique())
    n    = len(cycles)
    n_tr = int(n * 0.70)
    n_va = int(n * 0.15)
    for c in cycles[:n_tr]:            split_of_window[(sc,int(atk),int(c))] = 'train'
    for c in cycles[n_tr:n_tr+n_va]:   split_of_window[(sc,int(atk),int(c))] = 'val'
    for c in cycles[n_tr+n_va:]:       split_of_window[(sc,int(atk),int(c))] = 'test'

pem['split'] = [split_of_window[window_key(r)] for _,r in pem.iterrows()]
print("Split sizes (rows):", pem['split'].value_counts().to_dict())

# ── 3. Log serialization (Eq 3.87 LOG(L(t))) ─────────────────
def row_to_log(r):
    return (
        f"[Window {int(r['cycle'])} | t={float(r['time_s']):.0f}s | "
        f"Window={r['row_type']}]\n"
        f"Traffic Telemetry: CDR={float(r['CDR']):.4f} | "
        f"ChLoad={float(r['ch_load_pct']):.1f}% | "
        f"CCR={r['CCR']} | MCR={r['MCR']} | "
        f"eta_c={float(r['eta_c']):.4f}\n"
        f"Signal Features: delta_tm={float(r['delta_tm_rate']):.3f}% | "
        f"gamma={float(r['gamma']):.4f} | eps_topo={float(r['eps_topo']):.4f} | "
        f"hmac_ok={float(r['hmac_valid_pct']):.3f}"
    )

all_logs   = [row_to_log(r) for _,r in pem.iterrows()]
all_keys   = [window_key(r) for _,r in pem.iterrows()]
all_labels = list(pem['label'])

# ── 4. Build RAG corpus from TRAIN windows only ───────────────
train_idx     = np.flatnonzero((pem['split'] == 'train').to_numpy())
corpus_logs   = [all_logs[i]   for i in train_idx]
corpus_labels = [all_labels[i] for i in train_idx]
corpus_keys   = [all_keys[i]   for i in train_idx]
print(f"RAG corpus: {len(corpus_logs)} train rows (of {len(all_logs)} total)")

print(f"Loading embedding model: {EMBED_MODEL}")
embedder = SentenceTransformer(EMBED_MODEL)
print("Embedding all logs (this takes ~1 min)...")
all_embs = embedder.encode(all_logs, batch_size=64, show_progress_bar=True,
                           normalize_embeddings=True)
corpus_embs = all_embs[train_idx]
print(f"Corpus embeddings: {corpus_embs.shape}")

with open('rag_corpus.json','w') as f:
    json.dump([{'log':l,'label':lb} for l,lb in zip(corpus_logs,corpus_labels)],
              f, indent=2)
print("RAG corpus saved to rag_corpus.json")

# ── 5. Retrieve top-K similar TRAIN entries per example ───────
# Embeddings are normalized, so one matmul gives every query's cosine
# similarity to the whole corpus — no per-query re-encoding.
print("Computing similarity matrix...")
sims_all = all_embs @ corpus_embs.T          # (n_rows, n_train)

def retrieve_rag_context(query_idx, K=RAG_K):
    """Top-K most similar train logs, excluding the query's own window."""
    sims = sims_all[query_idx].copy()
    q_key = all_keys[query_idx]
    for j, ck in enumerate(corpus_keys):
        if ck == q_key:
            sims[j] = -1  # exclude self and CYCLE/CUMULATIVE twin
    top_k = np.argsort(sims)[-K:][::-1]
    ctx_parts = []
    for k in top_k:
        ctx_parts.append(
            f"[Historical Baseline | sim={sims[k]:.3f}]\n"
            f"{corpus_logs[k][:300]}..."
        )
    return "\n\n".join(ctx_parts)

# ── 6. System instruction (Eq 3.87 SYS) ──────────────────────
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

# ── 7. Label → output JSON ────────────────────────────────────
EV = {
    'V1': "Table-miss rate deviation ({dtm:.2f}%) and beacon-rate z-score spike indicate spoofed beacon flooding.",
    'V2': "Broadcast amplification gamma={gam:.3f} with cascade depth indicates cascading fake-alert propagation.",
    'V3': "Topology error rate eps_topo={eps:.4f} and mobility inconsistency indicate forged trace injection.",
    'benign': "All control-plane metrics within normal bounds; no anomaly detected.",
}

# Confidence scales: median signal magnitude of each attack class on the
# TRAIN split. Confidence grows with the window's own signal strength,
# floored at 0.50 and capped at 0.99 — not a fixed per-class constant.
tr = pem[pem['split'] == 'train']
SCALE_V1 = float(tr.loc[tr['label']=='V1', 'phi_v1_net'].median())
SCALE_V2 = float((tr.loc[tr['label']=='V2', 'gamma'] - 1.0).median())
SCALE_V3 = float(tr.loc[tr['label']=='V3', 'eps_topo'].median())
print(f"Confidence scales (train medians): "
      f"phi_v1={SCALE_V1:.4f} gamma-1={SCALE_V2:.4f} eps_topo={SCALE_V3:.4f}")

def make_conf(r):
    s_v1 = float(r['phi_v1_net']) / SCALE_V1
    s_v2 = (float(r['gamma']) - 1.0) / SCALE_V2
    s_v3 = float(r['eps_topo']) / SCALE_V3
    lbl = r['label']
    if   lbl == 'V1': s = s_v1
    elif lbl == 'V2': s = s_v2
    elif lbl == 'V3': s = s_v3
    else:             s = 1.0 - max(s_v1, s_v2, s_v3)  # benign: no attack signal
    return round(min(0.99, max(0.50, 0.5 + 0.49 * min(s, 1.0))), 2)

def make_output(r):
    lbl=r['label']
    ev=EV.get(lbl,'Normal.').format(
        dtm=float(r.get('delta_tm_rate',0)),
        gam=float(r.get('gamma',1)),
        eps=float(r.get('eps_topo',0)),
    )
    return json.dumps({"label":lbl,"confidence":make_conf(r),"evidence":ev})

# ── 8. Build full dataset with RAG context ────────────────────
print("Building dataset with RAG context...")
records = {'train':[], 'val':[], 'test':[]}
for idx,(_,r) in enumerate(pem.iterrows()):
    ctx    = retrieve_rag_context(idx, K=RAG_K)
    prompt = (
        f"### Instruction:\n{SYS}\n\n"
        f"### Retrieved Context (top-{RAG_K} similar historical windows):\n{ctx}\n\n"
        f"### Current Window Log:\n{all_logs[idx]}\n\n"
        f"### Response:\n{make_output(r)}"
    )
    records[r['split']].append({
        "text":    prompt,
        "label":   r['label'],
        "scenario":r['scenario'],
        "atk_count":int(r['atk_count']),
        "cycle":   int(r['cycle']),
        "row_type":r['row_type'],
    })

tr_recs, va_recs, te_recs = records['train'], records['val'], records['test']
print(f"Window-level 70/15/15 split:")
print(f"  Train:{len(tr_recs)}  Val:{len(va_recs)}  Test:{len(te_recs)}")
for split, recs in [("Train(70%)", tr_recs), ("Val(15%)", va_recs), ("Test(15%)", te_recs)]:
    sc_c  = Counter(r['scenario']  for r in recs)
    atk_c = Counter(r['atk_count'] for r in recs)
    lbl_c = Counter(r['label']     for r in recs)
    print(f"  {split}: scenarios={dict(sc_c)}")
    print(f"            atk_counts={dict(atk_c)}  labels={dict(lbl_c)}")

with open('llm_train.json','w') as f: json.dump(tr_recs,f,indent=2)
with open('llm_val.json','w') as f:   json.dump(va_recs,f,indent=2)
with open('llm_test.json','w') as f:  json.dump(te_recs,f,indent=2)

print("\nDone. Files written:")
print("  llm_train.json, llm_val.json, llm_test.json, rag_corpus.json")
