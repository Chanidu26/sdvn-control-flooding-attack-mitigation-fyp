"""
step4_fusion_eval.py  —  Fusion, Ablation, and Final Evaluation
================================================================
Per AI/ML Plan Section 4 and report Section 4.3:

  1. Load trained TGNN (edcf_tgnn_best.pt)
  2. Load fine-tuned LLM (edcf_llm_best_adapter/)
  3. Sweep fusion weight μ ∈ [0,1] on VALIDATION set → pick best μ
  4. Run final FUSED evaluation on TEST set
  5. Report standalone TGNN-only, LLM-only, and fused results
  6. Run 4 ablations (A1–A4 per report Section 4.3)
  7. Compare fused model vs 3 baselines from simulation CSVs

Outputs:
  fusion_mu_sweep.csv          ← μ sweep evidence
  final_evaluation_results.csv ← all method comparison
  ablation_results.csv         ← A1-A4 ablation evidence
  final_summary_table.txt      ← printable thesis table

Run:
  cd ~/edcf_training
  python3 step4_fusion_eval.py
"""

import json, re, os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GATConv
from scipy.spatial import cKDTree
from sklearn.metrics import matthews_corrcoef, f1_score, accuracy_score
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
VALID_LABELS = {'benign','V1','V2','V3'}
label_map    = {'benign':0,'V1':1,'V2':2,'V3':3}
id2lbl       = {v:k for k,v in label_map.items()}

# ── Load TGNN ─────────────────────────────────────────────────
print("Loading TGNN...")
ckpt     = torch.load('edcf_tgnn_best.pt', map_location=device)
FEAT     = ckpt['feat_cols']
feat_mu  = pd.Series(ckpt['feat_mean'])
feat_sd  = pd.Series(ckpt['feat_std'])
H        = ckpt['hidden_dim']
HEADS    = ckpt['heads']
N_F      = len(FEAT)

class TGNN(nn.Module):
    def __init__(self,hidden,heads):
        super().__init__()
        self.g1=GATConv(N_F,hidden,heads=heads,dropout=0.3,add_self_loops=True)
        self.g2=GATConv(hidden*heads,hidden,heads=1,dropout=0.3,concat=False,add_self_loops=True)
        self.b1=nn.BatchNorm1d(hidden*heads)
        self.b2=nn.BatchNorm1d(hidden)
        self.gru=nn.GRU(hidden,hidden,num_layers=2,batch_first=True,dropout=0.3)
        self.clf=nn.Sequential(nn.Linear(hidden,hidden//2),nn.ReLU(),
                               nn.Dropout(0.3),nn.Linear(hidden//2,4))
    def enc(self,d):
        # Per-node embedding (not pooled) -- matches step1_tgnn_hparam_search.py's
        # architecture so edcf_tgnn_best.pt's weights load and behave consistently.
        x,ei=d.x,d.edge_index
        x=self.b1(F.elu(self.g1(x,ei))); x=self.b2(F.elu(self.g2(x,ei)))
        return x  # [N_nodes,hidden]
    def forward(self,sl):
        embs=torch.stack([self.enc(s) for s in sl],dim=1)  # [N_nodes,T_WIN,hidden]
        _,h=self.gru(embs)
        return self.clf(h[-1])   # [N_nodes,4]

tgnn=TGNN(H,HEADS).to(device); tgnn.load_state_dict(ckpt['model_state']); tgnn.eval()
T_WIN=5; DSRC=270.0

def build_snap(grp):
    xn=((grp[FEAT]-feat_mu)/feat_sd).values
    x=torch.tensor(xn,dtype=torch.float)
    y=torch.tensor(grp['label'].map(label_map).values,dtype=torch.long)
    if 'label_enc' in grp.columns:
        y=torch.tensor(grp['label_enc'].values,dtype=torch.long)
    elif 'label' in grp.columns:
        y=torch.tensor([label_map.get(l,0) for l in grp['label']],dtype=torch.long)
    xy=grp[['pos_x','pos_y']].values.astype(float)
    pairs=list(cKDTree(xy).query_pairs(DSRC))
    if pairs:
        s=[i for i,j in pairs]+[j for i,j in pairs]
        d=[j for i,j in pairs]+[i for i,j in pairs]
        ei=torch.tensor([s,d],dtype=torch.long)
    else: ei=torch.zeros((2,0),dtype=torch.long)
    gl=torch.tensor([int(y.mode().values.item())],dtype=torch.long)
    return Data(x=x,edge_index=ei,y=y,graph_label=gl)

def mv(sl): return [Data(x=s.x.to(device),edge_index=s.edge_index.to(device),
                          y=s.y.to(device),graph_label=s.graph_label.to(device)) for s in sl]

def tgnn_predict_proba(seq_list):
    """Returns softmax probabilities [n_classes] for a sequence.

    tgnn(...) now returns per-node logits [N_nodes,4] (real per-vehicle
    predictions, see step1_tgnn_hparam_search.py). Fusion with the LLM
    needs a single window-level distribution to combine with the LLM's
    one-per-window verdict, so this averages each node's probability
    vector across the snapshot -- "mean attack-likelihood across the
    network this window" -- rather than the old graph-pooled-then-classify
    approach, but still exposing the same [4]-vector contract to callers.
    """
    tgnn.eval()
    with torch.no_grad():
        logits=tgnn(mv(seq_list))                    # [N_nodes,4]
        probs=F.softmax(logits,dim=1).mean(dim=0)     # [4]
        return probs.cpu().numpy()

# ── Load LLM ──────────────────────────────────────────────────
print("Loading fine-tuned LLM...")
LLM_PATH="/home/sdvn_mobility_flooding/edcf_models/Mistral-7B-Instruct-v0.3"
ADAPTER ="edcf_llm_best_adapter"
llm_tok =AutoTokenizer.from_pretrained(ADAPTER,trust_remote_code=True)
if llm_tok.pad_token is None: llm_tok.pad_token=llm_tok.eos_token
llm_base=AutoModelForCausalLM.from_pretrained(LLM_PATH,device_map='auto',
                                               torch_dtype=torch.bfloat16,trust_remote_code=True)
llm_model=PeftModel.from_pretrained(llm_base,ADAPTER); llm_model.eval()
print("LLM loaded.")

def llm_predict_proba(prompt_text):
    """Returns confidence per class from LLM JSON output."""
    inp=llm_tok(prompt_text,return_tensors='pt',truncation=True,max_length=1792).to(device)
    with torch.no_grad():
        out=llm_model.generate(**inp,max_new_tokens=80,do_sample=False,
                                repetition_penalty=1.1,pad_token_id=llm_tok.eos_token_id)
    gen=llm_tok.decode(out[0][inp['input_ids'].shape[1]:],skip_special_tokens=True)
    try:
        d=json.loads(gen)
        lbl=d.get('label','benign'); conf=float(d.get('confidence',0.9))
        proba=np.array([0.05,0.05,0.05,0.05])  # base low prob
        idx=label_map.get(lbl,0); proba[idx]=conf
        proba=proba/proba.sum()
    except:
        lbl_found='benign'
        for l in ['V1','V2','V3','benign']:
            if l in gen: lbl_found=l; break
        proba=np.array([0.05,0.05,0.05,0.05])
        proba[label_map.get(lbl_found,0)]=0.85; proba=proba/proba.sum()
    return proba

# ── Load test data (TGNN) ─────────────────────────────────────
print("Loading TGNN test sequences...")
df=pd.read_csv('tgnn_node_features.csv')
DROP=['phi_v1_i','phi_v2_i','phi_v3_i','tau_dir','fm_count_i']
df=df.drop(columns=[c for c in DROP if c in df.columns])
# De-duplicate to one row per vehicle per snapshot -- see step1_tgnn_hparam_search.py
# for why (append-only CSV + repeated ad-hoc runs of the same scenario/atk_count).
df=df.drop_duplicates(subset=['scenario','atk_count','cycle','node_id'],keep='last')
df['label_enc']=df['label'].map(label_map)

# Chronological 70/15/15 split of CYCLES WITHIN each (scenario,atk_count)
# group -- matches step1_tgnn_hparam_search.py's actual split methodology.
# Previously this sliced the sorted LIST of 42 (scenario,atk_count) groups
# (runs[int(n*.85):]) -- since group names sort alphabetically, that put
# the entire test set in v3b alone and the entire val set in v3a alone
# (see step5_gamma_calibration.py's fix), with zero V1/V2 data in either --
# every metric/ablation below that used df_te/df_va was silently V3-only.
def _cycle_split(data, frac_va=0.15, frac_te=0.15):
    va_rows, te_rows = [], []
    for (sc, atk), sub in data.groupby(['scenario', 'atk_count']):
        sub_sorted = sub.sort_values('cycle').reset_index(drop=True)
        cycles = sorted(sub_sorted['cycle'].unique())
        n_va = max(T_WIN, int(len(cycles) * frac_va))
        n_te = max(T_WIN, int(len(cycles) * frac_te))
        n_tr = len(cycles) - n_va - n_te
        va_cycles = cycles[n_tr:n_tr+n_va]
        te_cycles = cycles[n_tr+n_va:]
        va_rows.append(sub_sorted[sub_sorted['cycle'].isin(va_cycles)])
        te_rows.append(sub_sorted[sub_sorted['cycle'].isin(te_cycles)])
    return pd.concat(va_rows).reset_index(drop=True), pd.concat(te_rows).reset_index(drop=True)

df_va, df_te = _cycle_split(df)

te_snaps={}
for keys,g in df_te.groupby(['scenario','atk_count','cycle']):
    te_snaps[keys]=build_snap(g.reset_index(drop=True))

te_seqs=[]
for (sc,atk),sub in df_te.groupby(['scenario','atk_count']):
    cycs=sorted(sub['cycle'].unique())
    for s in range(len(cycs)-T_WIN+1):
        win=cycs[s:s+T_WIN]
        sl=[te_snaps.get((sc,atk,c)) for c in win]
        if all(x is not None for x in sl):
            te_seqs.append((sl,sl[-1].graph_label.item(),sc,atk))
print(f"Test sequences: {len(te_seqs)}")

# ── Load LLM test examples ────────────────────────────────────
with open('llm_test.json') as f: llm_te=json.load(f)
llm_te_prompts=[r['text'].split("### Response:\n")[0]+"### Response:\n" for r in llm_te]
llm_te_true   =[r['label'] for r in llm_te]

# ── Get predictions from each model ──────────────────────────
print("Getting TGNN predictions on test set...")
tgnn_probas=[]; tgnn_true=[]
for sl,lbl,sc,atk in te_seqs:
    tgnn_probas.append(tgnn_predict_proba(sl)); tgnn_true.append(lbl)
tgnn_preds=[np.argmax(p) for p in tgnn_probas]

print("Getting LLM predictions on test set...")
llm_probas=[]; llm_true_enc=[label_map.get(t,0) for t in llm_te_true]
for prompt in llm_te_prompts:
    llm_probas.append(llm_predict_proba(prompt))
llm_preds=[np.argmax(p) for p in llm_probas]

# ── μ sweep on VALIDATION set ─────────────────────────────────
print("Running μ fusion sweep on validation set...")
with open('llm_val.json') as f: llm_va=json.load(f)
llm_va_prompts=[r['text'].split("### Response:\n")[0]+"### Response:\n" for r in llm_va]

# df_va already built above by _cycle_split() alongside df_te.
va_snaps={}
for keys,g in df_va.groupby(['scenario','atk_count','cycle']):
    va_snaps[keys]=build_snap(g.reset_index(drop=True))
va_seqs=[]
for (sc,atk),sub in df_va.groupby(['scenario','atk_count']):
    cycs=sorted(sub['cycle'].unique())
    for s in range(len(cycs)-T_WIN+1):
        win=cycs[s:s+T_WIN]; sl=[va_snaps.get((sc,atk,c)) for c in win]
        if all(x is not None for x in sl):
            va_seqs.append((sl,sl[-1].graph_label.item()))

va_tgnn_prob=[tgnn_predict_proba(sl) for sl,_ in va_seqs]
va_tgnn_true=[lbl for _,lbl in va_seqs]
va_llm_prob=[llm_predict_proba(p) for p in llm_va_prompts]
va_llm_true=[label_map.get(r['label'],0) for r in llm_va]

# Align to same length (use min)
N=min(len(va_tgnn_prob),len(va_llm_prob))
va_tp=va_tgnn_prob[:N]; va_lp=va_llm_prob[:N]
va_true_aligned=[va_tgnn_true[i] for i in range(N)]

mu_rows=[]
for mu in np.arange(0.0,1.05,0.05):
    fused_prob=[mu*tp+(1-mu)*lp for tp,lp in zip(va_tp,va_lp)]
    preds=[np.argmax(p) for p in fused_prob]
    mcc=matthews_corrcoef(va_true_aligned,preds)
    mu_rows.append({'mu':round(mu,2),'val_MCC':round(mcc,4)})

mu_df=pd.DataFrame(mu_rows)
mu_df.to_csv('fusion_mu_sweep.csv',index=False)
best_mu=mu_df.loc[mu_df['val_MCC'].idxmax(),'mu']
print(f"Best μ = {best_mu:.2f}  (val_MCC={mu_df['val_MCC'].max():.4f})")

# ── Final test evaluation ──────────────────────────────────────
def eval_metrics(true_list, pred_list, name):
    mcc=matthews_corrcoef(true_list,pred_list)
    f1 =f1_score(true_list,pred_list,average='macro',zero_division=0)
    acc=accuracy_score(true_list,pred_list)
    pn=[id2lbl.get(p,'benign') for p in pred_list]
    tn=[id2lbl.get(t,'benign') for t in true_list]
    from sklearn.metrics import classification_report
    rep=classification_report(tn,pn,labels=['benign','V1','V2','V3'],
                               output_dict=True,zero_division=0)
    return {'method':name,'MCC':round(mcc,4),'F1_macro':round(f1,4),'Accuracy':round(acc,4),
            'F1_V1':round(rep['V1']['f1-score'],4),'F1_V2':round(rep['V2']['f1-score'],4),
            'F1_V3':round(rep['V3']['f1-score'],4),'F1_benign':round(rep['benign']['f1-score'],4)}

N_te=min(len(tgnn_preds),len(llm_preds))
te_true_aligned=tgnn_true[:N_te]

fused_preds=[np.argmax(best_mu*tp+(1-best_mu)*lp)
             for tp,lp in zip(tgnn_probas[:N_te],llm_probas[:N_te])]

results=[]
results.append(eval_metrics(te_true_aligned,tgnn_preds[:N_te],'TGNN-only'))
results.append(eval_metrics(llm_true_enc[:N_te],llm_preds[:N_te],'LLM-only'))
results.append(eval_metrics(te_true_aligned,fused_preds,f'Fused(μ={best_mu:.2f})'))

# ── Per-variant μ fused evaluation (Eq 3.72: μ tuned per variant) ────────
# The row above blends the WHOLE 4-class vector with one shared μ. The
# report specifies μ per variant (μ_V1, μ_V2, μ_V3, calibrated jointly with
# γ_v by step5_gamma_calibration.py into mu_config.json) — this generalizes
# the single-μ blend to a per-class μ vector: class c gets
# fused_prob[c] = mu_vec[c]*tp[c] + (1-mu_vec[c])*lp[c]. Eq 3.72 has no
# μ defined for the benign class (only v in {1,2,3}), so benign uses the
# mean of the three calibrated variant μ's as a neutral stand-in.
if os.path.exists('mu_config.json'):
    with open('mu_config.json') as f:
        _mu_cfg = json.load(f)
    _mu_v1 = _mu_cfg.get('V1', best_mu)
    _mu_v2 = _mu_cfg.get('V2', best_mu)
    _mu_v3 = _mu_cfg.get('V3', best_mu)
    _mu_benign = float(np.mean([_mu_v1, _mu_v2, _mu_v3]))
    mu_vec = np.array([_mu_benign, _mu_v1, _mu_v2, _mu_v3])  # [benign,V1,V2,V3]
    fused_preds_pv = [np.argmax(mu_vec*tp + (1-mu_vec)*lp)
                      for tp, lp in zip(tgnn_probas[:N_te], llm_probas[:N_te])]
    results.append(eval_metrics(
        te_true_aligned, fused_preds_pv,
        f'Fused-per-variant(μ_V1={_mu_v1:.2f},μ_V2={_mu_v2:.2f},μ_V3={_mu_v3:.2f})'))
else:
    print("  mu_config.json not found -- skipping per-variant-μ evaluation row "
          "(run step5_gamma_calibration.py first)")

# ── Ablations ─────────────────────────────────────────────────
# A1: rule-based only (lightweight MCC from PEM CSV)
pem_all=pd.concat([pd.read_csv('edcf_pem_v1.csv',comment='#'),
                    pd.read_csv('edcf_pem_v2.csv',comment='#'),
                    pd.read_csv('edcf_pem_v3.csv',comment='#')])
rule_mcc=pem_all[pem_all['row_type']=='CUMULATIVE']['MCC'].mean()
results.append({'method':'A1_Rule-only','MCC':round(rule_mcc,4),'F1_macro':0,'Accuracy':0,
                'F1_V1':0,'F1_V2':0,'F1_V3':0,'F1_benign':0})

# A2/A4(AB3): TGNN ablations — each loads its own trained checkpoint
# (a distinct model trained with the corresponding feature/component removed)
# and is evaluated legitimately against the held-out test set.
def load_tgnn_ckpt(path):
    c = torch.load(path, map_location=device)
    feat_cols = c['feat_cols']
    mu, sd = pd.Series(c['feat_mean']), pd.Series(c['feat_std'])
    mdl = TGNN(c['hidden_dim'], c['heads']).to(device)
    mdl.load_state_dict(c['model_state']); mdl.eval()
    return mdl, feat_cols, mu, sd

def build_snap_for(grp, feat_cols, mu, sd):
    xn = ((grp[feat_cols]-mu)/sd).values
    x  = torch.tensor(xn, dtype=torch.float)
    y  = torch.tensor([label_map.get(l,0) for l in grp['label']], dtype=torch.long)
    xy = grp[['pos_x','pos_y']].values.astype(float)
    pairs = list(cKDTree(xy).query_pairs(DSRC))
    if pairs:
        s=[i for i,j in pairs]+[j for i,j in pairs]
        d=[j for i,j in pairs]+[i for i,j in pairs]
        ei=torch.tensor([s,d],dtype=torch.long)
    else: ei=torch.zeros((2,0),dtype=torch.long)
    gl=torch.tensor([int(y.mode().values.item())],dtype=torch.long)
    return Data(x=x,edge_index=ei,y=y,graph_label=gl)

def eval_ablation_ckpt(ckpt_path, method_name):
    if not os.path.exists(ckpt_path):
        print(f"  {ckpt_path} not found — skipping {method_name}")
        return None
    mdl, feat_cols, a_mu, a_sd = load_tgnn_ckpt(ckpt_path)
    snaps = {}
    for keys,g in df_te.groupby(['scenario','atk_count','cycle']):
        snaps[keys] = build_snap_for(g.reset_index(drop=True), feat_cols, a_mu, a_sd)
    seqs = []
    for (sc,atk),sub in df_te.groupby(['scenario','atk_count']):
        cycs = sorted(sub['cycle'].unique())
        for s in range(len(cycs)-T_WIN+1):
            win = cycs[s:s+T_WIN]
            sl  = [snaps.get((sc,atk,c)) for c in win]
            if all(x is not None for x in sl):
                seqs.append((sl, sl[-1].graph_label.item()))
    preds, trues = [], []
    with torch.no_grad():
        for sl, lbl in seqs:
            logits = mdl(mv(sl))                 # [N_nodes,4]
            # Same window-level aggregation as tgnn_predict_proba(): mean
            # per-node probability across the snapshot, then argmax, so this
            # stays comparable to the other ablations' single-label-per-window.
            probs = F.softmax(logits, dim=1).mean(dim=0)
            preds.append(probs.argmax().item()); trues.append(lbl)
    return eval_metrics(trues, preds, method_name)

a2_result = eval_ablation_ckpt('edcf_tgnn_no_trust.pt', 'A2_TGNN-no-trust')
if a2_result is not None: results.append(a2_result)

# A3: no-HE-aggregation is a cryptographic/NS-3 component, not a TGNN variant —
# still reported symbolically since it cannot be evaluated via a TGNN checkpoint.
results.append({'method':'A3_no-HE-aggregation','MCC':'see_report','F1_macro':'-','Accuracy':'-',
                'F1_V1':'-','F1_V2':'-','F1_V3':'-','F1_benign':'-'})

# A4 / AB3: no-blockchain ablation, evaluated from its own trained TGNN checkpoint
a4_result = eval_ablation_ckpt('edcf_tgnn_ab3_no_blockchain.pt', 'A4_no-blockchain(AB3)')
if a4_result is not None:
    results.append(a4_result)
else:
    results.append({'method':'A4_no-blockchain(AB3)','MCC':'see_report','F1_macro':'-','Accuracy':'-',
                    'F1_V1':'-','F1_V2':'-','F1_V3':'-','F1_benign':'-'})

# ── Baselines from simulation CSVs ────────────────────────────
for csv_file,method in [('baseline_anyanwu.csv','Anyanwu_RBF-SVM'),
                          ('baseline_ppmds.csv','Gyawali_HE-MDS'),
                          ('baseline_wang.csv','Wang_DRL')]:
    try:
        bdf=pd.read_csv(csv_file,comment='#')
        bdf=bdf[bdf['row_type']=='CUMULATIVE']
        mcc=bdf['MCC'].mean()
        results.append({'method':method,'MCC':round(mcc,4),'F1_macro':round(bdf['F1'].mean(),4),
                        'Accuracy':round(bdf['Accuracy'].mean(),4),
                        'F1_V1':'-','F1_V2':'-','F1_V3':'-','F1_benign':'-'})
    except: print(f"  {csv_file} not found, skipping")

# ── Save and print final table ────────────────────────────────
res_df=pd.DataFrame(results)
res_df.to_csv('final_evaluation_results.csv',index=False)

print("\n"+"="*75)
print("  FINAL EVALUATION — EDCF-Shield vs Baselines")
print(f"  Fusion weight μ={best_mu:.2f} (tuned on validation)")
print("="*75)
print(f"{'Method':<25}{'MCC':>8}{'F1_mac':>8}{'F1_V1':>7}{'F1_V2':>7}{'F1_V3':>7}")
print("-"*75)
for _,r in res_df.iterrows():
    print(f"{r['method']:<25}{str(r['MCC']):>8}{str(r['F1_macro']):>8}"
          f"{str(r['F1_V1']):>7}{str(r['F1_V2']):>7}{str(r['F1_V3']):>7}")
print("="*75)

with open('final_summary_table.txt','w') as f:
    f.write("EDCF-Shield Final Evaluation Results\n")
    f.write(res_df.to_string(index=False))
print("\nAll evidence saved. Check final_evaluation_results.csv and final_summary_table.txt")
