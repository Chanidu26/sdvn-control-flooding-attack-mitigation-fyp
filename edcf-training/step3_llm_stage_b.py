"""
step3_llm_stage_b.py  —  LLM Stage B: Fine-tune All 5 Candidates
=================================================================
Per AI/ML Plan Section 1.3 (Stage B) and Section 2.4:
  Fine-tunes all 5 downloaded LLMs under identical, locked hyperparameters
  on our actual NS-3 data. Compares on validation MCC to confirm
  (or revise) the Stage-A selection of Qwen2.5-7B-Instruct.

LoRA hyperparameters are locked (r=16, alpha=32) — no rank sweep.

Outputs:
  llm_stage_b_results.csv       ← Stage B comparison evidence
  edcf_llm_best_adapter/        ← best adapter weights
  llm_stage_b_table.txt         ← printable evidence table

Run:
  cd ~/edcf_training
  python3 step3_llm_stage_b.py
"""

import os, json, re, time
import pandas as pd
import numpy as np
import torch
from datasets import Dataset
from transformers import (AutoTokenizer, AutoModelForCausalLM,
                          TrainingArguments, BitsAndBytesConfig)
from peft import LoraConfig, get_peft_model, TaskType, PeftModel
from transformers import Trainer, EarlyStoppingCallback
from sklearn.metrics import matthews_corrcoef, f1_score, accuracy_score

MODELS_ROOT = "/home/sdvn_mobility_flooding/edcf_models"

CANDIDATES = {
    # "Qwen2.5-7B":   "Qwen2.5-7B-Instruct",
    # "Llama-3.1-8B": "Llama-3.1-8B-Instruct",
    "Mistral-7B":   "Mistral-7B-Instruct-v0.3",
    # "Qwen3-8B":     "Qwen3-8B",
    # "Phi-4":        "Phi-4",
}

# Stage B hyperparams — identical for all candidates, locked (no sweep)
STAGE_B_CFG = dict(
    rank=16, alpha=32, dropout=0.1,  # locked: r=16, alpha=32 (alpha = 2r)
    epochs=4, batch=4, grad_acc=4, lr=1e-4,  # effective batch=16
    # Full prompt (SYS + top-5 RAG context + window log + response) measured
    # 1516-1615 tokens on the Mistral tokenizer. The previous max_seq=1024
    # silently right-truncated the "### Response:\n{json}" answer off of
    # EVERY training example (verified: 200/200 sampled), so the model never
    # saw the label it was supposed to learn. 1792 covers the observed max
    # with headroom.
    max_seq=1792,
)
VALID_LABELS = {'benign','V1','V2','V3'}
label_map    = {'benign':0,'V1':1,'V2':2,'V3':3}

# ── Load data ─────────────────────────────────────────────────
print("Loading datasets...")
with open('llm_train.json') as f: tr_recs=json.load(f)
with open('llm_val.json')   as f: va_recs=json.load(f)
with open('llm_test.json')  as f: te_recs=json.load(f)
print(f"Train:{len(tr_recs)}  Val:{len(va_recs)}  Test:{len(te_recs)}")

train_ds = Dataset.from_dict({"text":[r['text'] for r in tr_recs]})
val_ds   = Dataset.from_dict({"text":[r['text'] for r in va_recs]})

va_true = [r['label'] for r in va_recs]
te_true = [r['label'] for r in te_recs]

def extract_label(text):
    try: return json.loads(text)['label']
    except: pass
    m=re.search(r'"label"\s*:\s*"([^"]+)"',text)
    if m and m.group(1) in VALID_LABELS: return m.group(1)
    for l in ['V1','V2','V3','benign']:
        if l in text: return l
    return 'benign'

def run_inference(model,tok,recs,dev):
    model.eval(); preds=[]
    for r in recs:
        prompt=r['text'].split("### Response:\n")[0]+"### Response:\n"
        # max_length must cover the full prompt (SYS + RAG context + current
        # window log measures 1516-1557 tokens) — 768 was silently cutting
        # off the current window log (and the "### Response:" tag) from the
        # right, so the model was generating with no view of the thing it
        # was supposed to classify.
        inp=tok(prompt,return_tensors='pt',truncation=True,max_length=1792).to(dev)
        with torch.no_grad():
            out=model.generate(**inp,max_new_tokens=80,do_sample=False,
                               repetition_penalty=1.1,
                               pad_token_id=tok.eos_token_id)
        gen=tok.decode(out[0][inp['input_ids'].shape[1]:],skip_special_tokens=True)
        preds.append(extract_label(gen))
    te=[label_map.get(x,0) for x in [r['label'] for r in recs]]
    pe=[label_map.get(x,0) for x in preds]
    mcc=matthews_corrcoef(te,pe)
    f1 =f1_score(te,pe,average='macro',zero_division=0)
    acc=accuracy_score(te,pe)
    per={l:sum(preds[i]==l for i,r in enumerate(recs) if r['label']==l)/
              max(1,sum(r['label']==l for r in recs))
         for l in VALID_LABELS}
    return mcc,f1,acc,per

def fine_tune_model(name,dir_name,rank,alpha,epochs,out_dir):
    path=os.path.join(MODELS_ROOT,dir_name)
    if not os.path.isdir(path):
        print(f"  [SKIP] {name} not found at {path}"); return None

    # Skip TRAINING if already trained — but still load the adapter and
    # re-score it. Returning None metrics here used to silently blank out
    # the results CSV on every re-run once an adapter directory existed,
    # which is how a since-fixed run_inference() truncation bug (max_length
    # 768→1792, see comment above) stayed hidden in llm_stage_b_results.csv /
    # llm_rank_sweep_results.csv long after the code itself was corrected.
    if os.path.isdir(out_dir) and os.path.exists(os.path.join(out_dir,"adapter_config.json")):
        print(f"  [SKIP-TRAIN] {name} already trained at {out_dir} — re-scoring existing adapter")
        t0=time.time()
        bnb=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',
                                bnb_4bit_use_double_quant=True,
                                bnb_4bit_compute_dtype=torch.bfloat16)
        tok=AutoTokenizer.from_pretrained(path,trust_remote_code=True,padding_side='right')
        if tok.pad_token is None: tok.pad_token=tok.eos_token
        base=AutoModelForCausalLM.from_pretrained(path,quantization_config=bnb,
                                                   device_map='auto',trust_remote_code=True,
                                                   torch_dtype=torch.bfloat16)
        model=PeftModel.from_pretrained(base,out_dir)
        dev=next(model.parameters()).device

        va_mcc,va_f1,va_acc,va_per=run_inference(model,tok,va_recs,dev)
        te_mcc,te_f1,te_acc,te_per=run_inference(model,tok,te_recs,dev)
        mins=(time.time()-t0)/60
        print(f"  val MCC={va_mcc:.4f}  test MCC={te_mcc:.4f}  F1={te_f1:.4f}  {mins:.0f}min")
        del model,base; torch.cuda.empty_cache()

        return {'model':name,'rank':rank,'val_MCC':round(va_mcc,4),
                'test_MCC':round(te_mcc,4),'F1_macro':round(te_f1,4),'Accuracy':round(te_acc,4),
                'acc_benign':round(te_per.get('benign',0),4),'acc_V1':round(te_per.get('V1',0),4),
                'acc_V2':round(te_per.get('V2',0),4),'acc_V3':round(te_per.get('V3',0),4),
                'train_min':round(mins,1),'adapter_dir':out_dir,'note':'loaded_existing'}

    print(f"\n{'='*55}\n  {name}  rank={rank}  epochs={epochs}\n{'='*55}")
    t0=time.time()

    bnb=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',
                            bnb_4bit_use_double_quant=True,
                            bnb_4bit_compute_dtype=torch.bfloat16)
    try:
        tok=AutoTokenizer.from_pretrained(path,trust_remote_code=True,padding_side='right')
        if tok.pad_token is None: tok.pad_token=tok.eos_token
        base=AutoModelForCausalLM.from_pretrained(path,quantization_config=bnb,
                                                   device_map='auto',trust_remote_code=True,
                                                   torch_dtype=torch.bfloat16)
        base.config.use_cache=False
    except Exception as e:
        print(f"  [ERROR] {e}"); return None

    lora=LoraConfig(r=rank,lora_alpha=alpha,lora_dropout=STAGE_B_CFG['dropout'],
                    bias='none',task_type=TaskType.CAUSAL_LM,
                    target_modules=['q_proj','k_proj','v_proj','o_proj',
                                    'gate_proj','up_proj','down_proj'])
    model=get_peft_model(base,lora)

    # Tokenize dataset manually — version-stable across all trl/transformers
    # Loss is masked to the "### Response:\n{json}" span only. Without this,
    # labels=full input_ids trains the model to reproduce the ~2000-token
    # SYS+RAG boilerplate (identical/near-identical across examples) with the
    # same weight as the ~30-token JSON answer, so eval_loss drops fast while
    # telling us almost nothing about classification quality.
    RESP_TAG = "### Response:\n"
    def tokenize_fn(examples):
        texts   = examples['text']
        prefixes= [t.split(RESP_TAG)[0] + RESP_TAG for t in texts]
        out     = tok(texts, truncation=True,
                       max_length=STAGE_B_CFG['max_seq'], padding=False)
        pre_out = tok(prefixes, truncation=True,
                       max_length=STAGE_B_CFG['max_seq'], padding=False)
        labels=[]
        for ids, pre_ids in zip(out['input_ids'], pre_out['input_ids']):
            plen = min(len(pre_ids), len(ids))
            labels.append([-100]*plen + ids[plen:])
        out['labels']=labels
        return out
    tok_tr=train_ds.map(tokenize_fn,batched=True,remove_columns=['text'])
    tok_va=val_ds.map(tokenize_fn,batched=True,remove_columns=['text'])

    # DataCollatorForLanguageModeling(mlm=False) ignores any pre-set 'labels'
    # and rebuilds them as a full clone of input_ids — it would silently
    # undo the masking above. Use a plain collator that right-pads input_ids/
    # attention_mask and pads labels with -100 instead of the pad token id.
    def collator(features):
        input_ids = [f['input_ids'] for f in features]
        labels    = [f['labels']    for f in features]
        maxlen    = max(len(x) for x in input_ids)
        pad_id    = tok.pad_token_id
        b_ids, b_attn, b_lab = [], [], []
        for ids, labs in zip(input_ids, labels):
            pad_len = maxlen - len(ids)
            b_ids.append(list(ids) + [pad_id]*pad_len)
            b_attn.append([1]*len(ids) + [0]*pad_len)
            b_lab.append(list(labs) + [-100]*pad_len)
        return {
            'input_ids':      torch.tensor(b_ids, dtype=torch.long),
            'attention_mask': torch.tensor(b_attn, dtype=torch.long),
            'labels':         torch.tensor(b_lab, dtype=torch.long),
        }
    args=TrainingArguments(
        output_dir=out_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=STAGE_B_CFG['batch'],
        per_device_eval_batch_size=STAGE_B_CFG['batch'],
        gradient_accumulation_steps=STAGE_B_CFG['grad_acc'],
        gradient_checkpointing=True,
        learning_rate=STAGE_B_CFG['lr'],
        lr_scheduler_type='cosine',warmup_steps=30,weight_decay=0.01,
        eval_strategy='steps',eval_steps=100,
        save_strategy='steps',save_steps=100,
        load_best_model_at_end=True,metric_for_best_model='eval_loss',
        logging_steps=10,bf16=True,fp16=False,
        dataloader_pin_memory=False,report_to='none',seed=42,
    )
    trainer=Trainer(model=model,train_dataset=tok_tr,eval_dataset=tok_va,
                    data_collator=collator,args=args,
                    callbacks=[EarlyStoppingCallback(early_stopping_patience=2)])
    trainer.train()
    model.save_pretrained(out_dir); tok.save_pretrained(out_dir)

    dev=next(model.parameters()).device
    va_mcc,va_f1,va_acc,va_per=run_inference(model,tok,va_recs,dev)
    te_mcc,te_f1,te_acc,te_per=run_inference(model,tok,te_recs,dev)
    mins=(time.time()-t0)/60

    print(f"  val MCC={va_mcc:.4f}  test MCC={te_mcc:.4f}  F1={te_f1:.4f}  {mins:.0f}min")
    del model,base,trainer; torch.cuda.empty_cache()

    return {'model':name,'rank':rank,'val_MCC':round(va_mcc,4),
            'test_MCC':round(te_mcc,4),'F1_macro':round(te_f1,4),'Accuracy':round(te_acc,4),
            'acc_benign':round(te_per.get('benign',0),4),'acc_V1':round(te_per.get('V1',0),4),
            'acc_V2':round(te_per.get('V2',0),4),'acc_V3':round(te_per.get('V3',0),4),
            'train_min':round(mins,1),'adapter_dir':out_dir}

# ── Stage B: all 5 candidates, locked LoRA hyperparameters ───
print("\n" + "="*55)
print("  STAGE B: Fine-tuning all 5 candidate LLMs")
print("="*55)
stage_b_results=[]
for name,dir_name in CANDIDATES.items():
    res=fine_tune_model(name,dir_name,rank=STAGE_B_CFG['rank'],alpha=STAGE_B_CFG['alpha'],
                        epochs=STAGE_B_CFG['epochs'],
                        out_dir=f"./adapter_stageb_{name.replace('.','_')}")
    if res: stage_b_results.append(res)

sb_df=pd.DataFrame(stage_b_results).sort_values('test_MCC',ascending=False)
sb_df.to_csv('llm_stage_b_results.csv',index=False)
best_model_name=sb_df.iloc[0]['model']
best_adapter   =sb_df.iloc[0]['adapter_dir']

# Print Stage B table
print("\n"+"="*75)
print("  LLM STAGE B RESULTS — on actual NS-3 control-plane log data")
print("="*75)
print(f"{'Model':<16}{'val_MCC':>8}{'test_MCC':>9}{'F1_mac':>7}"
      f"{'benign':>8}{'V1':>6}{'V2':>6}{'V3':>6}{'min':>6}")
print("-"*75)
for _,r in sb_df.iterrows():
    mk="  ← SELECTED" if r['model']==best_model_name else ""
    print(f"{r['model']:<16}{r['val_MCC']:>8.4f}{r['test_MCC']:>9.4f}"
          f"{r['F1_macro']:>7.4f}{r['acc_benign']:>8.4f}{r['acc_V1']:>6.4f}"
          f"{r['acc_V2']:>6.4f}{r['acc_V3']:>6.4f}{r['train_min']:>6.1f}{mk}")
print("="*75)
print(f"  Selected (Stage B): {best_model_name}  (test_MCC={sb_df.iloc[0]['test_MCC']:.4f})")

# Copy best adapter (LoRA hyperparameters are locked — no rank sweep)
import shutil
if os.path.isdir(str(best_adapter)):
    if os.path.exists('edcf_llm_best_adapter'): shutil.rmtree('edcf_llm_best_adapter')
    shutil.copytree(str(best_adapter),'edcf_llm_best_adapter')

# Write evidence table file
lines=["="*75,
       "  LLM Stage B Selection Evidence — EDCF-Shield",
       "="*75,
       f"Stage B selected: {best_model_name}  "
       f"rank={STAGE_B_CFG['rank']} alpha={STAGE_B_CFG['alpha']}",
       f"Confirms/revises Stage A selection (Qwen2.5-7B-Instruct)","="*75]
with open('llm_stage_b_table.txt','w') as f: f.write("\n".join(lines))

print(f"\nBest adapter: {best_adapter}  (rank={STAGE_B_CFG['rank']})")
print("All evidence saved.")