"""
step1c_k_ablation.py — K (temporal window) ablation for the TGNN
=======================================================================
Answers Sir's outstanding diagnostic: does performance genuinely improve
as the GRU's temporal window K grows 1 -> 2 -> 3, validating the paper's
claim (Phi^V3 requires K>=3 to evaluate tau_dir, latex.tex:1679) that
multi-snapshot temporal reasoning is actually necessary?

Design choice: the train/val/test CYCLE split is fixed once, using the
same 60/20/20 boundary the main run uses at T_WIN=3 (train=cycles 0-8,
val=9-11, test=12-14) -- identical across all three K conditions, so
only the GRU window length changes, not how much data is used. Varying
the split per-K (as step1_tgnn_hparam_search.py does for its own T_WIN)
would confound "less temporal context" with "less/different data" and
make the comparison unscientific.

Hyperparameters are fixed to the current best config (hidden=128,
heads=8, lr=1e-3) so the ablation isolates K alone, not architecture
size. This does re-run training 3x (K=1,2,3) at 150 epochs each --
expect roughly the same wall-clock time as 3 rows of the 27-grid search.

Outputs:
  tgnn_k_ablation.csv   <- val_MCC/test_MCC/F1 per K, evidence table

Run:
  cd ~/edcf_training   (or wherever tgnn_node_features.csv lives)
  python3 step1c_k_ablation.py
"""

import random
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GATConv
from scipy.spatial import cKDTree
from sklearn.metrics import matthews_corrcoef, f1_score, classification_report

SEED = 42
torch.manual_seed(SEED); np.random.seed(SEED); random.seed(SEED)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Device: {device}")

# ── Fixed hyperparameters (the current 27-grid winner) ─────────
HIDDEN, HEADS, LR, EPOCHS = 128, 8, 1e-3, 150

# ── Fixed split boundary (independent of K, see docstring) ─────
SPLIT_T_WIN = 3
K_VALUES = [1, 2, 3]

DATA = "tgnn_node_features.csv"
DSRC = 270.0

print("Loading data...")
df = pd.read_csv(DATA)

# Same s_BC patch as step1_tgnn_hparam_search.py (routing.cc bug: raw
# bc_rep_cache[] read instead of bc_get_reputation(); constant 1.0 here
# matches the intended fallback and z-normalises to 0 either way).
df['s_BC'] = 1.0

DROP = ['phi_v1_i', 'phi_v2_i', 'phi_v3_i', 'tau_dir', 'fm_count_i']
df = df.drop(columns=[c for c in DROP if c in df.columns])

_before = len(df)
df = df.drop_duplicates(subset=['scenario', 'atk_count', 'cycle', 'node_id'], keep='last')
print(f"De-duplicated snapshot rows: {_before} -> {len(df)} "
      f"({_before - len(df)} stale duplicate rows dropped)")

FEAT = ['zscore_v1_i', 'fanout_i', 'zeta', 'bcn_rate_i', 'alert_in_i',
        'alert_out_i', 's_BC', 'xi_tm_i']
N_F = len(FEAT)

label_map = {'benign': 0, 'V1': 1, 'V2': 2, 'V3': 3}
id2lbl = {v: k for k, v in label_map.items()}
df['y'] = df['label'].map(label_map)


def build_snap(grp, mu, sd):
    x = torch.tensor(((grp[FEAT] - mu) / sd).values, dtype=torch.float)
    y = torch.tensor(grp['y'].values, dtype=torch.long)
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


# ── Fixed 60/20/20 cycle split, identical for every K ───────────
df_tr_rows, df_va_rows, df_te_rows = [], [], []
for (sc, atk), sub in df.groupby(['scenario', 'atk_count']):
    sub_sorted = sub.sort_values('cycle').reset_index(drop=True)
    cycles = sorted(sub_sorted['cycle'].unique())
    n_va = max(SPLIT_T_WIN, int(len(cycles) * 0.15))
    n_te = max(SPLIT_T_WIN, int(len(cycles) * 0.15))
    n_tr = len(cycles) - n_va - n_te

    tr_cycles = cycles[:n_tr]
    va_cycles = cycles[n_tr:n_tr + n_va]
    te_cycles = cycles[n_tr + n_va:]

    df_tr_rows.append(sub_sorted[sub_sorted['cycle'].isin(tr_cycles)])
    df_va_rows.append(sub_sorted[sub_sorted['cycle'].isin(va_cycles)])
    df_te_rows.append(sub_sorted[sub_sorted['cycle'].isin(te_cycles)])

df_tr = pd.concat(df_tr_rows).reset_index(drop=True)
df_va = pd.concat(df_va_rows).reset_index(drop=True)
df_te = pd.concat(df_te_rows).reset_index(drop=True)

mu = df_tr[FEAT].mean()
sd = df_tr[FEAT].std().replace(0, 1)

print(f"Fixed split (same for every K): train={len(df_tr)} rows, "
      f"val={len(df_va)} rows, test={len(df_te)} rows")

lc = df_tr['label'].value_counts(); tot = len(df_tr)
cw = torch.tensor([tot / lc.get('benign', 1), tot / lc.get('V1', 1),
                    tot / lc.get('V2', 1), tot / lc.get('V3', 1)], dtype=torch.float).to(device)
cw = cw / cw.sum() * 4


def build_sequences_from_df(data, mu, sd, k):
    """Same windowing as step1_tgnn_hparam_search.py but window length k
    is a parameter instead of the module-level T_WIN constant."""
    seqs = []
    for (sc, atk), sub in data.groupby(['scenario', 'atk_count']):
        cycs = sorted(sub['cycle'].unique())
        snaps = {}
        for c in cycs:
            g = sub[sub['cycle'] == c].reset_index(drop=True)
            snaps[c] = build_snap(g, mu, sd)
        for s in range(len(cycs) - k + 1):
            win = cycs[s:s + k]
            sl = [snaps.get(c) for c in win]
            if all(x is not None for x in sl):
                seqs.append((sl, sl[-1].y, sc, atk))
    return seqs


def mv(sl, dev):
    return [Data(x=s.x.to(dev), edge_index=s.edge_index.to(dev),
                  y=s.y.to(dev), graph_label=s.graph_label.to(dev)) for s in sl]


class TGNN(nn.Module):
    def __init__(self, hidden, heads):
        super().__init__()
        self.g1 = GATConv(N_F, hidden, heads=heads, dropout=0.3, add_self_loops=True)
        self.g2 = GATConv(hidden * heads, hidden, heads=1, dropout=0.3, concat=False, add_self_loops=True)
        self.b1 = nn.BatchNorm1d(hidden * heads)
        self.b2 = nn.BatchNorm1d(hidden)
        self.gru = nn.GRU(hidden, hidden, num_layers=2, batch_first=True, dropout=0.3)
        self.clf = nn.Sequential(nn.Linear(hidden, hidden // 2), nn.ReLU(),
                                  nn.Dropout(0.3), nn.Linear(hidden // 2, 4))

    def enc(self, d):
        x, ei = d.x, d.edge_index
        x = self.b1(F.elu(self.g1(x, ei)))
        x = self.b2(F.elu(self.g2(x, ei)))
        return x

    def forward(self, sl):
        embs = torch.stack([self.enc(s) for s in sl], dim=1)  # [N_nodes, len(sl), hidden]
        _, h = self.gru(embs)
        return self.clf(h[-1])


def train_eval(k, tr_seq, va_seq, te_seq, epochs=EPOCHS):
    mdl = TGNN(HIDDEN, HEADS).to(device)
    opt = torch.optim.AdamW(mdl.parameters(), lr=LR, weight_decay=1e-4)
    sch = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    loss_fn = nn.CrossEntropyLoss(weight=cw)
    best_mcc = -1; best_st = None

    for ep in range(1, epochs + 1):
        mdl.train(); random.shuffle(tr_seq); opt.zero_grad()
        for step, (sl, lbl, _sc, _atk) in enumerate(tr_seq, 1):
            sl = mv(sl, device)
            loss = loss_fn(mdl(sl), lbl.to(device)) / 8
            loss.backward()
            if step % 8 == 0 or step == len(tr_seq):
                torch.nn.utils.clip_grad_norm_(mdl.parameters(), 1.0)
                opt.step(); opt.zero_grad()
        sch.step()
        if ep % 2 == 0 or ep == epochs:
            mdl.eval(); p, t = [], []
            with torch.no_grad():
                for sl, lbl, _sc, _atk in va_seq:
                    sl = mv(sl, device)
                    p.extend(mdl(sl).argmax(dim=1).tolist()); t.extend(lbl.tolist())
            mcc = matthews_corrcoef(t, p)
            if mcc > best_mcc:
                best_mcc = mcc; best_st = {kk: vv.clone() for kk, vv in mdl.state_dict().items()}

    mdl.load_state_dict(best_st); mdl.eval(); p, t = [], []
    with torch.no_grad():
        for sl, lbl, _sc, _atk in te_seq:
            sl = mv(sl, device)
            p.extend(mdl(sl).argmax(dim=1).tolist()); t.extend(lbl.tolist())
    pn = [id2lbl[x] for x in p]; tn = [id2lbl[x] for x in t]
    rep = classification_report(tn, pn, labels=['benign', 'V1', 'V2', 'V3'],
                                 output_dict=True, zero_division=0)
    return {
        'K': k,
        'n_train_seq': len(tr_seq), 'n_val_seq': len(va_seq), 'n_test_seq': len(te_seq),
        'val_MCC': round(best_mcc, 4),
        'test_MCC': round(matthews_corrcoef(t, p), 4),
        'F1_macro': round(f1_score(t, p, average='macro', zero_division=0), 4),
        'F1_V1': round(rep['V1']['f1-score'], 4),
        'F1_V2': round(rep['V2']['f1-score'], 4),
        'F1_V3': round(rep['V3']['f1-score'], 4),
    }


results = []
for k in K_VALUES:
    print(f"\n{'=' * 60}\nK={k}  (hidden={HIDDEN}, heads={HEADS}, lr={LR:.0e})\n{'=' * 60}")
    tr_seq = build_sequences_from_df(df_tr, mu, sd, k)
    va_seq = build_sequences_from_df(df_va, mu, sd, k)
    te_seq = build_sequences_from_df(df_te, mu, sd, k)
    print(f"  sequences: train={len(tr_seq)} val={len(va_seq)} test={len(te_seq)}")
    row = train_eval(k, tr_seq, va_seq, te_seq)
    results.append(row)
    print(f"  val_MCC={row['val_MCC']:.4f}  test_MCC={row['test_MCC']:.4f}  "
          f"F1_macro={row['F1_macro']:.4f}  F1_V1={row['F1_V1']:.4f}  "
          f"F1_V2={row['F1_V2']:.4f}  F1_V3={row['F1_V3']:.4f}")

res_df = pd.DataFrame(results)
res_df.to_csv('tgnn_k_ablation.csv', index=False)

print("\n" + "=" * 70)
print("  K Ablation Results (fixed split, fixed hyperparameters)")
print("=" * 70)
print(f"{'K':>3} {'train_seq':>9} {'val_seq':>7} {'test_seq':>8} {'val_MCC':>8} "
      f"{'test_MCC':>9} {'F1_mac':>7} {'F1_V1':>6} {'F1_V2':>6} {'F1_V3':>6}")
print("-" * 70)
for _, r in res_df.iterrows():
    print(f"{int(r['K']):>3} {int(r['n_train_seq']):>9} {int(r['n_val_seq']):>7} "
          f"{int(r['n_test_seq']):>8} {r['val_MCC']:>8.4f} {r['test_MCC']:>9.4f} "
          f"{r['F1_macro']:>7.4f} {r['F1_V1']:>6.4f} {r['F1_V2']:>6.4f} {r['F1_V3']:>6.4f}")
print("=" * 70)
print("\nExpectation per paper (latex.tex:1679, Phi^V3 needs K>=3 for tau_dir):")
print("  test_MCC and F1_V3 should rise from K=1 -> K=3.")
print("  If K=1 already matches K=3, the temporal-necessity claim is not supported")
print("  by this data and Section on kinematic compliance needs revisiting.")
print("\nSaved: tgnn_k_ablation.csv")
