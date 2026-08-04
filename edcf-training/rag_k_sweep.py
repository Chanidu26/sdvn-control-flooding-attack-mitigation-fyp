"""
rag_k_sweep.py — Sensitivity sweep: RAG retrieval depth K
============================================================
vs. LLM inference latency (ms) and LLM test-set MCC.

Reuses the ALREADY fine-tuned LLM adapter (edcf_llm_best_adapter/) and the
existing RAG corpus (rag_corpus.json) exactly as-is -- no retraining, no
NS-3. Only the inference-time retrieval depth K varies; the fine-tuned
model (trained with K=5 context) and the corpus it retrieves from are held
fixed, matching a standard "robustness to inference-time context depth"
ablation rather than a train-time hyperparameter sweep.

Method:
  For each K in --k:
    - Re-run retrieval (same embedder, same corpus) against every
      llm_test.json example's "Current Window Log" section, at the new K
    - Feed the reconstructed prompt through the SAME fine-tuned model
    - Measure wall-clock generate() latency and the predicted label
  Report mean inference latency (ms) and test MCC per K.

Run (no NS-3, no retrain -- pure Python inference over the existing test
split; you run this yourself, per project policy on not auto-running
model/simulation scripts):
  cd ~/control-flooding-g14/edcf_traning
  python3 rag_k_sweep.py --k 1 3 5 10 15 --sample 200

  # Full 1332-row test set instead of a subsample (much slower -- 1332
  # LLM generate() calls per K, 5 K values):
  python3 rag_k_sweep.py --k 1 3 5 10 15 --sample -1

Output: rag_k_sweep.csv  [K, n_examples, avg_latency_ms, test_MCC]
"""

import argparse, json, re, time
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import matthews_corrcoef
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from sentence_transformers import SentenceTransformer

LLM_BASE_PATH = "/home/sdvn_mobility_flooding/edcf_models/Mistral-7B-Instruct-v0.3"
ADAPTER       = "edcf_llm_best_adapter"
EMBED_MODEL   = "/home/sdvn_mobility_flooding/edcf_models/all-MiniLM-L6-v2"

label_map = {'benign': 0, 'V1': 1, 'V2': 2, 'V3': 3}

# Must match step2_build_llm_dataset.py's SYS EXACTLY -- this is what the
# LoRA adapter was fine-tuned against.
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


def parse_args():
    p = argparse.ArgumentParser(description="RAG retrieval-depth K sensitivity sweep")
    p.add_argument('--k', type=int, nargs='+', default=[1, 3, 5, 10, 15],
                    help="Retrieval depths to sweep")
    p.add_argument('--sample', type=int, default=200,
                    help="Subsample this many test examples (fixed random subset, "
                         "same subset reused across all K for a fair comparison) to "
                         "keep runtime bounded. Use -1 for the full 1332-row test set "
                         "(len(k) x 1332 LLM generate() calls -- can take hours).")
    p.add_argument('--seed', type=int, default=42)
    p.add_argument('--out', default='rag_k_sweep.csv')
    return p.parse_args()


def extract_query_log(prompt_text):
    """Pull the 'Current Window Log' section out of an existing llm_test.json
    prompt (built at training time with K=5 baked in) so it can be
    re-embedded/re-queried at a different K without reloading or re-splitting
    the raw PEM CSVs -- the log text itself doesn't depend on K."""
    m = re.search(r"### Current Window Log:\n(.*?)\n\n### Response:", prompt_text, re.S)
    if not m:
        raise ValueError("Could not find 'Current Window Log' section in prompt text")
    return m.group(1)


def main():
    args = parse_args()
    rng = np.random.RandomState(args.seed)

    print("Loading llm_test.json + rag_corpus.json...")
    with open('llm_test.json') as f:
        llm_te = json.load(f)
    with open('rag_corpus.json') as f:
        rag_corpus = json.load(f)
    corpus_logs = [r['log'] for r in rag_corpus]

    if 0 < args.sample < len(llm_te):
        idx = rng.choice(len(llm_te), size=args.sample, replace=False)
        idx.sort()
        llm_te = [llm_te[i] for i in idx]
    print(f"Evaluating on {len(llm_te)} test examples (of {len(rag_corpus)} corpus rows).")

    query_logs = [extract_query_log(r['text']) for r in llm_te]
    true_labels = [label_map.get(r['label'], 0) for r in llm_te]

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    print(f"Loading RAG embedder from {EMBED_MODEL}...")
    embedder = SentenceTransformer(EMBED_MODEL, device=str(device))
    print(f"Embedding {len(corpus_logs)} corpus entries + {len(query_logs)} queries "
          "(same embedder/corpus for every K -- only retrieval depth changes)...")
    corpus_embs = embedder.encode(corpus_logs, batch_size=64, show_progress_bar=False,
                                   normalize_embeddings=True)
    query_embs = embedder.encode(query_logs, batch_size=64, show_progress_bar=False,
                                  normalize_embeddings=True)
    sims_all = query_embs @ corpus_embs.T  # [n_queries, n_corpus]

    print("Loading fine-tuned LLM (fixed across all K -- only retrieval depth varies)...")
    tok = AutoTokenizer.from_pretrained(ADAPTER, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        LLM_BASE_PATH, device_map='auto', torch_dtype=torch.bfloat16, trust_remote_code=True)
    model = PeftModel.from_pretrained(base, ADAPTER)
    model.eval()
    print("LLM loaded.")

    def build_ctx(qi, K):
        sims = sims_all[qi]
        top_k = np.argsort(sims)[-K:][::-1]
        parts = [f"[Historical Baseline | sim={sims[k]:.3f}]\n{corpus_logs[k][:300]}..."
                 for k in top_k]
        return "\n\n".join(parts)

    def predict(prompt_text):
        inp = tok(prompt_text, return_tensors='pt', truncation=True, max_length=1792).to(device)
        t0 = time.perf_counter()
        with torch.no_grad():
            out = model.generate(**inp, max_new_tokens=80, do_sample=False,
                                  repetition_penalty=1.1, pad_token_id=tok.eos_token_id)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        gen = tok.decode(out[0][inp['input_ids'].shape[1]:], skip_special_tokens=True)
        try:
            d = json.loads(gen)
            lbl = d.get('label', 'benign')
        except Exception:
            lbl = 'benign'
            for l in ['V1', 'V2', 'V3', 'benign']:
                if l in gen:
                    lbl = l
                    break
        return label_map.get(lbl, 0), latency_ms

    rows = []
    for K in args.k:
        print(f"\n=== K={K} ===")
        preds, lats = [], []
        for qi, qlog in enumerate(query_logs):
            ctx = build_ctx(qi, K)
            # Must match step2_build_llm_dataset.py's prompt assembly EXACTLY
            # (SYS || CTX || LOG || QUERY, Eq 3.87) except for K itself.
            prompt = (
                f"### Instruction:\n{SYS}\n\n"
                f"### Retrieved Context (top-{K} similar historical windows):\n{ctx}\n\n"
                f"### Current Window Log:\n{qlog}\n\n"
                f"### Response:\n"
            )
            pred, lat = predict(prompt)
            preds.append(pred)
            lats.append(lat)
            if (qi + 1) % 50 == 0:
                print(f"  {qi + 1}/{len(query_logs)} done...")
        mcc = matthews_corrcoef(true_labels, preds)
        avg_lat = float(np.mean(lats))
        print(f"K={K}: avg_latency={avg_lat:.1f}ms  test_MCC={mcc:.4f}")
        rows.append({'K': K, 'n_examples': len(query_logs),
                      'avg_latency_ms': round(avg_lat, 1), 'test_MCC': round(mcc, 4)})

    pd.DataFrame(rows).to_csv(args.out, index=False)
    print(f"\nSaved {args.out}")


if __name__ == '__main__':
    main()
