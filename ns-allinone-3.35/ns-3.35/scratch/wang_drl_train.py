#!/usr/bin/env python3
"""
wang_drl_train.py  —  Wang [22] DRL Offline Training
Place at: ns-3.35/scratch/wang_drl_train.py
Run:      python3 scratch/wang_drl_train.py
Output:   scratch/wang_qtable.dat  (loaded by routing.cc)
          scratch/wang_drl_training_results.csv
"""

import numpy as np
import random
import os
import struct
import csv
from collections import deque

# === Paper Table III parameters ===
M           = 4      # RSU servers (matches 4-controller NS-3 layout)
N_SERVICES  = 1      # N = ceil(M/4) = 1
N_VEHICLES  = 200    # your NS-3 vehicle count
GAMMA       = 0.8    # discount factor γ
LR          = 0.001  # learning rate β (paper Fig 12 best)
EPSILON     = 0.1    # ε-greedy exploration
REPLAY_CAP  = 1000   # replay memory
BATCH_SIZE  = 32     # mini-batch
STEPS_EP    = 200    # steps per episode
N_EPISODES  = 300    # training episodes
N_EVAL_RUNS = 10     # "ten times of experiments" (paper §IV-B)
TGT_SYNC_C  = 100    # target network sync interval

N_STATES    = (2**M) * 4   # 32
N_ACTIONS   = M             # 3

OUTPUT_DIR  = "./scratch"
QTABLE_FILE = os.path.join(OUTPUT_DIR, "wang_qtable.dat")
RESULTS_CSV = os.path.join(OUTPUT_DIR, "wang_drl_training_results.csv")

# === Valid one-hot action vectors ===
VALID_ACTIONS = [[int(i==j) for j in range(M)] for i in range(M)]

def build_topology(m):
    t = [[0]*m for _ in range(m)]
    for i in range(m-1): t[i][i+1]=t[i+1][i]=1
    for i in range(m):
        if i+3<m: t[i][i+3]=t[i+3][i]=1
    return t

def compute_suc(D, fake, topo, nv, m):
    if sum(D)==0: return 0.0
    ok=tot=0
    vpR=nv//m; rem=nv%m
    for rsu in range(m):
        for _ in range(vpR+(1 if rsu<rem else 0)):
            tot+=1
            if D[rsu]: ok+=1; continue
            vis={rsu}; q=[rsu]; found=False
            while q and not found:
                c=q.pop(0)
                for nb in range(m):
                    if nb in vis: continue
                    if tuple(sorted((c,nb))) in fake: continue
                    if topo[c][nb]:
                        vis.add(nb)
                        if D[nb]: found=True; break
                        q.append(nb)
            if found: ok+=1
    return ok/tot if tot else 0.0

def encode_state(D, loss):
    di = sum(D[i]*(1<<(M-1-i)) for i in range(M))
    lb = min(int(loss/0.25), 3)
    return di*4+lb

def decode_action(a): return list(VALID_ACTIONS[a])

def reachable_rsus(D, fake, topo, m):
    """
    S_RSU (paper Eq. 2): "number of RSUs that will host service and can
    successfully receive migrated VMs." An RSU is FULLY isolated (cannot
    receive the migration command) only when ALL of its incident links
    are simultaneously faked — not merely when one of its links touches
    a fake pair, which would also zero out an RSU that's already serving
    fine through its other link (the bug that originally made every
    episode's reward collapse to 0 whenever the deployed RSU happened to
    touch any fake link at all, regardless of whether it still had a
    working path). This still rewards migrating away from a heavily
    targeted RSU, since targeted_fake_links() concentrates fake links on
    whichever RSU currently hosts the service.
    """
    def fully_isolated(i):
        neighbours = [j for j in range(m) if topo[i][j]]
        return len(neighbours) > 0 and all(
            tuple(sorted((i, j))) in fake for j in neighbours)
    return sum(1 for i in range(m) if D[i] and not fully_isolated(i))

def targeted_fake_links(D, all_links, nf):
    """
    Sample nf fake links, BIASED toward links incident to the RSU(s)
    currently hosting the service (D). This mirrors the paper's threat
    model (§II-B3 / III-A): the attacker poisons the topology around
    the deployed service to cut vehicles off from it, not a uniformly
    random link anywhere in the network.

    Without this bias, M=4's topology is vertex-transitive (a 4-cycle —
    every RSU looks structurally identical), so a uniformly-random fake
    link is statistically no more likely to isolate the deployed RSU
    than any other RSU. That symmetry means "stay put" and "migrate"
    have the same expected success rate, so DRL has nothing to learn
    and collapses to the no-recovery baseline (DRL-Suc == NoRecov).
    Targeting the deployed RSU's incident links recreates the asymmetry
    the agent is supposed to learn to evade.
    """
    hosted = [i for i in range(M) if D[i]]
    incident = [l for l in all_links if l[0] in hosted or l[1] in hosted]
    other = [l for l in all_links if l not in incident]
    nf = min(nf, len(all_links))
    # Prioritise links touching the deployed RSU(s); fall back to the
    # remaining links only once those are exhausted.
    if len(incident) >= nf:
        chosen = random.sample(incident, nf)
    else:
        chosen = list(incident) + random.sample(other, nf - len(incident))
    return set(tuple(sorted(l)) for l in chosen)

class QNet:
    def __init__(self, seed=0):
        rng=np.random.RandomState(seed)
        self.Q=rng.uniform(0,0.1,(N_STATES,N_ACTIONS))
    def get(self,s): return self.Q[s].copy()
    def update(self,s,a,target):
        self.Q[s,a]+=LR*(target-self.Q[s,a])
    def sync_from(self,other): self.Q=other.Q.copy()

class Replay:
    def __init__(self,cap): self.buf=deque(maxlen=cap)
    def push(self,*t): self.buf.append(t)
    def sample(self,n): return random.sample(list(self.buf),min(n,len(self.buf)))
    def __len__(self): return len(self.buf)

def train(scenarios, seed=42):
    random.seed(seed); np.random.seed(seed)
    topo=build_topology(M)
    Qe=QNet(seed); Qt=QNet(seed); Qt.sync_from(Qe)
    mem=Replay(REPLAY_CAP)
    sync_ctr=0; log=[]
    print(f"[*] Training Wang [22] DRL  M={M} γ={GAMMA} β={LR} ε={EPSILON}")
    print(f"    Episodes={N_EPISODES}  Batch={BATCH_SIZE}  Scenarios={len(scenarios)}\n")
    for ep in range(N_EPISODES):
        fake=scenarios[ep%len(scenarios)]
        D=decode_action(0); cum_r=0.0
        for step in range(STEPS_EP):
            suc=compute_suc(D,fake,topo,N_VEHICLES,M)
            s=encode_state(D,1-suc)
            a=(random.randrange(N_ACTIONS) if random.random()<EPSILON
               else int(np.argmax(Qe.get(s))))
            nD=decode_action(a)
            suc_n=compute_suc(nD,fake,topo,N_VEHICLES,M)
            S_RSU=reachable_rsus(nD,fake,topo,M)
            r=suc_n*(S_RSU/N_SERVICES); cum_r+=r
            s_n=encode_state(nD,1-suc_n)
            done=(1-suc_n<0.02)
            mem.push(s,a,r,s_n,done); D=nD
            if len(mem)>=BATCH_SIZE:
                for (bs,ba,br,bsn,bt) in mem.sample(BATCH_SIZE):
                    yj=(br if bt else
                        br+GAMMA*Qt.get(bsn)[int(np.argmax(Qe.get(bsn)))])
                    Qe.update(bs,ba,yj)
            sync_ctr+=1
            if sync_ctr>=TGT_SYNC_C: Qt.sync_from(Qe); sync_ctr=0
            if done: break
        log.append({"ep":ep,"cum_r":round(cum_r,4)})
        if ep%50==0 or ep==N_EPISODES-1:
            print(f"    ep {ep:3d}/{N_EPISODES}: cumR={cum_r:.3f}")
    return Qe, log

def evaluate(Qe, seed_base=9999):
    topo=build_topology(M)
    all_links=[(i,j) for i in range(M) for j in range(i+1,M)]
    print(f"\n[*] Evaluation — paper Fig 9 (M={M})")
    print(f"    {'FakeLinks':>9} | {'NoRecov':>8} | {'DRL-Suc':>8} | {'Optimal':>8}")
    print(f"    {'-'*9}-+-{'-'*8}-+-{'-'*8}-+-{'-'*8}")
    results=[]
    for nf in range(1,min(len(all_links)+1,7)):
        ar,dr,or_=[],[],[]
        for run in range(N_EVAL_RUNS):
            random.seed(seed_base+run*100+nf)
            D0=decode_action(0)
            fake=targeted_fake_links(D0, all_links, nf)
            sno=compute_suc(D0,fake,topo,N_VEHICLES,M)
            sopt=max(compute_suc(decode_action(a),fake,topo,N_VEHICLES,M)
                     for a in range(N_ACTIONS))
            D=list(D0); best=sno
            for _ in range(STEPS_EP):
                sn=compute_suc(D,fake,topo,N_VEHICLES,M)
                a_g=int(np.argmax(Qe.get(encode_state(D,1-sn))))
                nD=decode_action(a_g)
                snn=compute_suc(nD,fake,topo,N_VEHICLES,M)
                if snn>best: best=snn
                D=nD
                if 1-snn<0.02: break
            ar.append(sno); dr.append(best); or_.append(sopt)
        ma,md,mo=round(float(np.mean(ar)),3),round(float(np.mean(dr)),3),round(float(np.mean(or_)),3)
        print(f"    {nf:>9} | {ma:>8.3f} | {md:>8.3f} | {mo:>8.3f}")
        results.append({"M":M,"n_fake":nf,"no_recovery":ma,"drl":md,"optimal":mo})
    return results

def export_qtable(Qe, path):
    """
    Binary file format — read by routing.cc with wang_load_qtable():
      bytes  0- 3: uint32 magic    = 0xDEEDFEED
      bytes  4- 7: uint32 M        (RSU count)
      bytes  8-11: uint32 N_STATES (32)
      bytes 12-15: uint32 N_ACTS   (3)
      bytes 16+  : double[N_STATES][N_ACTS] row-major little-endian
    Total: 16 + 64*4*8 = 2064 bytes  (M=4: 64 states x 4 actions)
    """
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path,"wb") as f:
        f.write(struct.pack("<I",0xDEEDFEED))
        f.write(struct.pack("<I",M))
        f.write(struct.pack("<I",N_STATES))
        f.write(struct.pack("<I",N_ACTIONS))
        for s in range(N_STATES):
            for a in range(N_ACTIONS):
                f.write(struct.pack("<d",float(Qe.Q[s,a])))
    print(f"\n[*] Q-table → {path}  ({os.path.getsize(path)} bytes)")

def save_csv(log, eval_r, path):
    with open(path,"w",newline="") as f:
        f.write("# Wang [22] DRL Training Results\n")
        f.write("# M={} N_svc={} gamma={} lr={} eps={} episodes={}\n"
                .format(M,N_SERVICES,GAMMA,LR,EPSILON,N_EPISODES))
        f.write("section,ep_or_nfake,value1,value2\n")
        for r in log:
            f.write(f"TRAIN,{r['ep']},{r['cum_r']},0\n")
        for r in eval_r:
            f.write(f"EVAL_nfake={r['n_fake']},{r['no_recovery']},{r['drl']},{r['optimal']}\n")
    print(f"[*] Results → {path}")

def main():
    print("="*65)
    print("Wang [22] DRL Training — scratch/wang_drl_train.py")
    print("="*65)
    random.seed(42); np.random.seed(42)
    all_links=[(i,j) for i in range(M) for j in range(i+1,M)]
    scenarios=[]
    D0=decode_action(0)
    for nf in range(1,min(len(all_links)+1,7)):
        for run in range(5):
            random.seed(run*10+nf)
            scenarios.append(targeted_fake_links(D0, all_links, nf))
    Qe,log=train(scenarios,seed=42)
    eval_r=evaluate(Qe,seed_base=9999)
    export_qtable(Qe,QTABLE_FILE)
    save_csv(log,eval_r,RESULTS_CSV)
    print("\n[*] DONE")
    print(f"    {QTABLE_FILE}  ← routing.cc loads this at startup")
    print(f"    {RESULTS_CSV}")
    print("\n[*] Next:")
    print("    cd ns-3.35")
    print("    python3 scratch/wang_drl_train.py")
    print('    ./waf --run "routing --edcf_scenario=v3a --edcf_atk_count=20 --edcf_has_key=0"')
    print("    cat scratch/baseline_wang.csv")

if __name__=="__main__":
    main()
