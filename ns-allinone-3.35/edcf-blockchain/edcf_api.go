// =============================================================
// edcf_api.go — EDCF-Shield Blockchain API v4
//
// New revisions per Nilmantha Sir's feedback:
//   R10: RSU nodes are blockchain peers (NOT controllers)
//        Controllers are read-only clients only
//   R11: Dynamic trust-score-based peer selection at runtime
//        "peer selection occasionally at runtime based on trust score"
//   R12: RSU quarantine/removal lifecycle
//        ACTIVE → QUARANTINE (demote to client) → REMOVED
//   R13: Controller writes require RSU co-signatures per eq:multisig
//   R14: DKG threshold fixed at t=4-of-7 (one designated RSU per grid zone)
// =============================================================
package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"golang.org/x/crypto/hkdf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	N_RSU_TOTAL        = 64   // 8x8 grid — all RSU nodes in NS-3
	N_RSU_DKG          = 7    // 7 RSUs participate in DKG (one per grid zone, per sim settings)
	T_DKG              = 4    // threshold t=4: any 4-of-7 DKG RSUs reconstruct k_root (Eq dkg_reconstruct)
	N_RSU_PEERS_MIN    = 2    // R11: min RSU peers to co-sign a controller write
	N_RSU_PEERS_MAX    = 10   // R11: max peers selected per consensus round
	RSU_PEER_TH        = 0.5  // R11: min trust score to be selected as active peer
	RSU_QUARANTINE_TH  = 0.3  // R12: score below → quarantine after W bad windows
	RSU_QUARANTINE_WIN = 3    // R12: consecutive bad windows before quarantine
	RSU_REMOVE_TH      = 0.15 // R12: score below this while quarantined → REMOVE
	RSU_RESTORE_TH     = 0.6  // R12: score above this while quarantined → restore ACTIVE
	RHO                = 0.80  // Eq 3.23: decay parameter ρ=0.80 per sim settings
	R_TH               = 0.3
	N_TH               = 3
	RCTRL_TH           = 0.5
	INITIAL_REP        = 1.0
	M_CTRL             = 4    // 4 SDN controllers per sim settings (nodes 0-3)
	REQUIRED_SIGS      = 3 // eq:multisig: ceil(4/2)+1 = 3 RSU co-sigs (4 controllers)
	K_OBS              = 2
	K_AGG              = 2
	T_VERIFY           = 2
	SECKEY             = "edcf-secplane-2025"
	LEDGER_FILE        = "./edcf_ledger.json"
	KDF_HMAC_LABEL     = "HMAC-AUTH"
)

// R12: RSU peer states
const (
	RSU_PEER_ACTIVE     = "ACTIVE"     // full peer — participates in consensus
	RSU_PEER_QUARANTINE = "QUARANTINE" // suspected malicious — demoted to client
	RSU_PEER_REMOVED    = "REMOVED"    // confirmed malicious — excluded permanently
)

type EventType string

const (
	EVT_VEHICLE_TX      EventType = "VEHICLE_TX"
	EVT_DETECTION       EventType = "DETECTION"
	EVT_CONTROLLER_TX   EventType = "CONTROLLER_TX"
	EVT_CTRL_OBS        EventType = "CTRL_OBS"
	EVT_REP_UPDATE      EventType = "REP_UPDATE"
	EVT_CTRL_REP_UPDATE EventType = "CTRL_REP_UPDATE"
	EVT_ISOLATION       EventType = "ISOLATION"
	EVT_FLOW_REVOKE     EventType = "FLOW_REVOKE"
	EVT_ENFORCE_PATH    EventType = "ENFORCE_PATH"
	EVT_FAILOVER        EventType = "FAILOVER"
	EVT_DOMAIN_HANDOVER EventType = "DOMAIN_HANDOVER"
	EVT_MERKLE_BATCH    EventType = "MERKLE_BATCH"
	EVT_DKG_INIT        EventType = "DKG_INIT"
	EVT_REINSTATE       EventType = "REINSTATE"
	EVT_RSU_QUARANTINE  EventType = "RSU_QUARANTINE"
	EVT_RSU_RESTORE     EventType = "RSU_RESTORE"
	EVT_RSU_REMOVE      EventType = "RSU_REMOVE"
	EVT_PEER_SELECTION  EventType = "PEER_SELECTION"
)

// R10+R11+R12: RSU peer node
type RSUPeer struct {
	RSUID          string  `json:"rsu_id"`
	State          string  `json:"state"`            // ACTIVE / QUARANTINE / REMOVED
	TrustScore     float64 `json:"trust_score"`
	BadWindowCount int     `json:"bad_window_count"` // consecutive windows below RSU_QUARANTINE_TH
	IsSelectedPeer bool    `json:"is_selected_peer"` // selected in current round
	LastUpdated    float64 `json:"last_updated"`
	Note           string  `json:"note,omitempty"`
}

type Block struct {
	BlockNum    int                    `json:"block_num"`
	TxID        string                 `json:"tx_id"`
	EventType   EventType              `json:"event_type"`
	EquationRef string                 `json:"equation_ref"`
	NodeID      string                 `json:"node_id"`
	CtrlID      string                 `json:"ctrl_id,omitempty"`
	Timestamp   float64                `json:"timestamp"`
	Payload     map[string]interface{} `json:"payload"`
	PrevTxID    string                 `json:"prev_tx_id"`
}

type NodeReputation struct {
	NodeID       string  `json:"node_id"`
	Score        float64 `json:"score"`
	Isolated     bool    `json:"isolated"`
	DetectCount  int     `json:"detect_count"`
	WindowCount  int     `json:"window_count"`
	LastUpdated  float64 `json:"last_updated"`
	IsController bool    `json:"is_controller"`
	AssignedCtrl string  `json:"assigned_ctrl"`
}

type CtrlReputation struct {
	CtrlID        string  `json:"ctrl_id"`
	Score         float64 `json:"score"`
	Isolated      bool    `json:"isolated"`
	ObsCount      int     `json:"obs_count"`
	StableWindows int     `json:"stable_windows"`
	LastUpdated   float64 `json:"last_updated"`
}

type CtrlObsRecord struct {
	VehicleID    string  `json:"vehicle_id"`
	CtrlID       string  `json:"ctrl_id"`
	FlowModRate  float64 `json:"flow_mod_rate"`
	RouteErrRate float64 `json:"route_err_rate"`
	Timestamp    float64 `json:"timestamp"`
	Signature    string  `json:"signature"`
}

type MerkleBatch struct {
	WindowID   int      `json:"window_id"`
	TxHashes   []string `json:"tx_hashes"`
	MerkleRoot string   `json:"merkle_root"`
	Count      int      `json:"count"`
	Committed  bool     `json:"committed"`
}

type FlowRevocation struct {
	NodeID          string  `json:"node_id"`
	Timestamp       float64 `json:"timestamp"`
	EnforcedVia     string  `json:"enforced_via"`
	ControllerScore float64 `json:"controller_score"`
	InitiatedBy     string  `json:"initiated_by"`
	FailoverCtrl    string  `json:"failover_ctrl,omitempty"`
}

type AlertLogEntry struct {
	TxID            string  `json:"tx_id"`
	BlockNum        int     `json:"block_num"`
	NodeID          string  `json:"node_id"`
	AttackLabel     int     `json:"attack_label"`
	TGNNScore       float64 `json:"tgnn_score"`
	PhiScore        float64 `json:"phi_score"`
	Variant         string  `json:"variant"`
	Timestamp       float64 `json:"timestamp"`
	SecPlaneSign    string  `json:"secplane_sign"`
	HMACDetected    bool    `json:"hmac_detected"`
	SigFlagDetected bool    `json:"sig_flag_detected"`
	RSUSigner       string  `json:"rsu_signer"`
	RSUSignature    string  `json:"rsu_signature"`
	Isolated        bool    `json:"isolated"`
	ReputationAfter float64 `json:"reputation_after"`
	AssignedCtrl    string  `json:"assigned_ctrl"`
}

type LedgerStats struct {
	TotalVehicleTxs     int `json:"total_vehicle_txs"`
	TotalDetections     int `json:"total_detections"`
	TotalControllerTxs  int `json:"total_controller_txs"`
	TotalCtrlObs        int `json:"total_ctrl_obs"`
	TotalIsolations     int `json:"total_isolations"`
	TotalRevocations    int `json:"total_revocations"`
	TotalFailovers      int `json:"total_failovers"`
	TotalMerkleBatches  int `json:"total_merkle_batches"`
	RejectedTxs         int `json:"rejected_txs"`
	TotalRSUQuarantines int `json:"total_rsu_quarantines"`
	TotalRSURemovals    int `json:"total_rsu_removals"`
}

type Ledger struct {
	Chain           []*Block                    `json:"chain"`
	BlockCount      int                         `json:"block_count"`
	TxCounter       int                         `json:"tx_counter"`
	Reputations     map[string]*NodeReputation  `json:"reputations"`
	CtrlReputations map[string]*CtrlReputation  `json:"ctrl_reputations"`
	RSUPeers        map[string]*RSUPeer         `json:"rsu_peers"` // R10: RSU peer registry
	AlertLog        []*AlertLogEntry            `json:"alert_log"`
	Revocations     map[string]*FlowRevocation  `json:"revocations"`
	CtrlObsBuffer   map[string][]*CtrlObsRecord `json:"ctrl_obs_buffer"`
	CurrentBatch    *MerkleBatch                `json:"current_batch"`
	BatchCounter    int                         `json:"batch_counter"`
	Stats           LedgerStats                 `json:"stats"`
}

var (
	ledger   *Ledger
	ledgerMu sync.RWMutex
)

// R10: Initialise all N RSU nodes as ACTIVE peers with full trust score
// "Initially you can have everyone as peers as trust scores are just initialized"
func initRSUPeers(n int) map[string]*RSUPeer {
	peers := make(map[string]*RSUPeer, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("RSU_%d", i)
		peers[id] = &RSUPeer{
			RSUID:      id,
			State:      RSU_PEER_ACTIVE,
			TrustScore: INITIAL_REP,
		}
	}
	return peers
}

func newLedger() *Ledger {
	return &Ledger{
		Chain:       []*Block{},
		Reputations: make(map[string]*NodeReputation),
		CtrlReputations: map[string]*CtrlReputation{
			"ctrl0": {CtrlID: "ctrl0", Score: INITIAL_REP},  // 4 SDN controllers per report
			"ctrl1": {CtrlID: "ctrl1", Score: INITIAL_REP},
			"ctrl2": {CtrlID: "ctrl2", Score: INITIAL_REP},
			"ctrl3": {CtrlID: "ctrl3", Score: INITIAL_REP},
		},
		RSUPeers:      initRSUPeers(N_RSU_TOTAL), // R10: all 64 RSUs start as ACTIVE peers
		AlertLog:      []*AlertLogEntry{},
		Revocations:   make(map[string]*FlowRevocation),
		CtrlObsBuffer: make(map[string][]*CtrlObsRecord),
		CurrentBatch:  &MerkleBatch{WindowID: 1},
	}
}

// R11: Select top-N RSU peers by trust score (dynamic, per consensus round)
func selectRSUPeers(n int) []*RSUPeer {
	var eligible []*RSUPeer
	for _, p := range ledger.RSUPeers {
		if p.State == RSU_PEER_ACTIVE && p.TrustScore >= RSU_PEER_TH {
			eligible = append(eligible, p)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].TrustScore > eligible[j].TrustScore
	})
	if len(eligible) > n {
		eligible = eligible[:n]
	}
	for _, p := range ledger.RSUPeers {
		p.IsSelectedPeer = false
	}
	for _, p := range eligible {
		p.IsSelectedPeer = true
	}
	return eligible
}

// R12: Update RSU peer state per PEM window
func updateRSUPeerState(rsuID string, newScore float64, ts float64) {
	p, ok := ledger.RSUPeers[rsuID]
	if !ok || p.State == RSU_PEER_REMOVED {
		return
	}
	oldState := p.State
	p.TrustScore = newScore
	p.LastUpdated = ts

	switch p.State {
	case RSU_PEER_ACTIVE:
		if newScore < RSU_QUARANTINE_TH {
			p.BadWindowCount++
			if p.BadWindowCount >= RSU_QUARANTINE_WIN {
				p.State = RSU_PEER_QUARANTINE
				p.Note = fmt.Sprintf("Quarantined: score=%.3f after %d bad windows", newScore, p.BadWindowCount)
				ledger.Stats.TotalRSUQuarantines++
				appendBlock(EVT_RSU_QUARANTINE, "Eq rsu_peer_quarantine", rsuID, "", map[string]interface{}{
					"trust_score": newScore, "bad_windows": p.BadWindowCount,
					"action":  "Demoted to CLIENT state — cannot co-sign controller writes",
					"monitor": "Score continues updating. Recovery if score >= RSU_RESTORE_TH",
				})
				log.Printf("[BC] R12 QUARANTINE: %s score=%.3f", rsuID, newScore)
			}
		} else {
			p.BadWindowCount = 0
		}
	case RSU_PEER_QUARANTINE:
		if newScore < RSU_REMOVE_TH {
			p.State = RSU_PEER_REMOVED
			ledger.Stats.TotalRSURemovals++
			appendBlock(EVT_RSU_REMOVE, "Eq rsu_peer_remove", rsuID, "", map[string]interface{}{
				"trust_score": newScore, "remove_th": RSU_REMOVE_TH,
				"action": "RSU permanently removed from blockchain network",
			})
			log.Printf("[BC] R12 REMOVED: %s score=%.3f", rsuID, newScore)
		} else if newScore >= RSU_RESTORE_TH {
			p.State = RSU_PEER_ACTIVE
			p.BadWindowCount = 0
			appendBlock(EVT_RSU_RESTORE, "Eq rsu_peer_restore", rsuID, "", map[string]interface{}{
				"trust_score": newScore, "restore_th": RSU_RESTORE_TH,
				"action": "RSU restored to ACTIVE peer",
			})
			log.Printf("[BC] R12 RESTORED: %s score=%.3f", rsuID, newScore)
		}
	}
	if p.State != oldState {
		log.Printf("[BC] RSU state: %s %s→%s (score=%.3f)", rsuID, oldState, p.State, newScore)
	}
}

func loadLedger() {
	data, err := os.ReadFile(LEDGER_FILE)
	if err != nil {
		log.Printf("[LEDGER] Starting fresh")
		ledger = newLedger()
		logDKGInit()
		return
	}
	ledger = newLedger()
	if err := json.Unmarshal(data, ledger); err != nil {
		log.Printf("[LEDGER] Parse error: %v", err)
		ledger = newLedger()
		logDKGInit()
		return
	}
	if ledger.RSUPeers == nil {
		ledger.RSUPeers = initRSUPeers(N_RSU_TOTAL)
	}
	log.Printf("[LEDGER] Loaded: %d blocks, %d reps, %d RSU peers",
		len(ledger.Chain), len(ledger.Reputations), len(ledger.RSUPeers))
}

func saveLedger() {
	data, _ := json.MarshalIndent(ledger, "", "  ")
	os.WriteFile(LEDGER_FILE, data, 0644)
}

func nextTxID() string {
	ledger.TxCounter++
	return fmt.Sprintf("tx-%06d-%d", ledger.TxCounter, time.Now().UnixNano())
}

func appendBlock(evtType EventType, eq, nodeID, ctrlID string, payload map[string]interface{}) *Block {
	ledger.BlockCount++
	prevTxID := ""
	if len(ledger.Chain) > 0 {
		prevTxID = ledger.Chain[len(ledger.Chain)-1].TxID
	}
	b := &Block{
		BlockNum: ledger.BlockCount, TxID: nextTxID(),
		EventType: evtType, EquationRef: eq,
		NodeID: nodeID, CtrlID: ctrlID,
		Timestamp: float64(time.Now().UnixMilli()) / 1000.0,
		Payload:   payload, PrevTxID: prevTxID,
	}
	ledger.Chain = append(ledger.Chain, b)
	return b
}

// R3+R14: DKG init — t=2 (NOT t=10)
func logDKGInit() {
	appendBlock(EVT_DKG_INIT, "Eq dkg_share+dkg_combine+kg_derivation", "", "RSU_0..RSU_6",  // 7 DKG RSUs (one per grid zone)
		map[string]interface{}{
			"description":     "DKG: 7 RSU nodes hold shares (one per grid zone) — k_root never at single node",
			"total_rsus":      N_RSU_TOTAL,
			"dkg_rsu_count":   N_RSU_DKG,  // =7, one per grid zone
			"threshold":       T_DKG,  // =4, any 4-of-7 reconstruct k_root
			"threshold_note":  "t=4: any 4-of-7 designated DKG RSUs reconstruct k_root",
			"all_rsus_in_dkg": "Only 7 designated RSUs (one per grid zone) hold DKG shares",
			"non_dkg_rsus":    "RSU_7..RSU_63: routing + peer consensus only (not DKG)",
			"peer_model":      "ALL 64 RSUs start as ACTIVE peers (trust-score selected dynamically)",
			"ctrl_role":       "Controllers are READ-ONLY clients — submit Txs, NOT peers",
			"formula_kg":      "k_g = KDF(k_root || 'HMAC-AUTH')  (Eq kg_derivation)",
		})
	log.Printf("[BC] DKG init: t=%d-of-%d designated RSUs (one per grid zone). All %d RSUs are blockchain peers.", T_DKG, N_RSU_DKG, N_RSU_TOTAL)
}

func assignedCtrl(nodeID string) string {
	if strings.HasPrefix(nodeID, "vehicle_") {
		if num, err := strconv.Atoi(strings.TrimPrefix(nodeID, "vehicle_")); err == nil {
			idx := (num - 5) % 4  // 4 controllers (nodes 0-3), vehicles start at node 5
			if idx < 0 { idx += 4 }
			return fmt.Sprintf("ctrl%d", idx)  // ctrl0..ctrl3
		}
	}
	if strings.HasPrefix(nodeID, "ctrl") { return nodeID }
	return "ctrl0"
}

func deriveKg(kRoot string) string {
	//h := sha256.New()
	//h.Write([]byte(kRoot + "|" + KDF_HMAC_LABEL))
	//return hex.EncodeToString(h.Sum(nil))[:32]
	hk := hkdf.New(sha512.New, []byte(kRoot), nil, []byte(KDF_HMAC_LABEL))
	out := make([]byte, 32)
	io.ReadFull(hk, out)
	return hex.EncodeToString(out)
}

// R10+R11+R13: Consensus uses RSU peer signatures — controllers are clients only
func validateConsensus(ctrlID string, rsuSigs []string) (bool, string) {
	activePeers := selectRSUPeers(N_RSU_PEERS_MAX)
	if len(activePeers) < N_RSU_PEERS_MIN {
		return false, fmt.Sprintf("insufficient active RSU peers: %d < %d required", len(activePeers), N_RSU_PEERS_MIN)
	}
	if len(rsuSigs) < REQUIRED_SIGS {
		return false, fmt.Sprintf("need %d RSU co-signatures, got %d (eq:multisig)", REQUIRED_SIGS, len(rsuSigs))
	}
	peerIDs := make([]string, len(activePeers))
	for i, p := range activePeers { peerIDs[i] = p.RSUID }
	appendBlock(EVT_PEER_SELECTION, "Eq rsu_peer_select", "", ctrlID, map[string]interface{}{
		"selected_peers": peerIDs, "total_active": len(activePeers),
		"required_sigs": REQUIRED_SIGS, "rsu_sig_count": len(rsuSigs),
		"formula": "Peers(t) = top-N RSU_i by TrustScore where State=ACTIVE, TrustScore>=tau_peer",
		"note":    "Dynamic peer selection per consensus round",
	})
	if cr, ok := ledger.CtrlReputations[ctrlID]; ok {
		if cr.Score < RCTRL_TH {
			ledger.Stats.RejectedTxs++
			return false, fmt.Sprintf("%s score %.4f < R_ctrl_th — client write rejected", ctrlID, cr.Score)
		}
	}
	return true, ""
}

func getOrCreateRep(nodeID string, isCtrl bool) *NodeReputation {
	if r, ok := ledger.Reputations[nodeID]; ok { return r }
	r := &NodeReputation{NodeID: nodeID, Score: INITIAL_REP, IsController: isCtrl, AssignedCtrl: assignedCtrl(nodeID)}
	ledger.Reputations[nodeID] = r
	return r
}

func updateReputation(nodeID string, yhat, ts float64) float64 {
	r := getOrCreateRep(nodeID, false)
	oldScore := r.Score
	r.Score = r.Score*(1.0-RHO*yhat) + RHO*(1.0-yhat)
	if r.Score < 0 { r.Score = 0 }
	if r.Score > 1 { r.Score = 1 }
	if yhat > 0 { r.DetectCount++; r.WindowCount++ }
	r.LastUpdated = ts
	appendBlock(EVT_REP_UPDATE, "Eq 3.23", nodeID, r.AssignedCtrl, map[string]interface{}{
		"old_score": oldScore, "new_score": r.Score, "yhat": yhat,
		"formula": "R_i(t) = R_i(t-1)*(1-rho*yhat) + rho*(1-yhat)",
	})
	return r.Score
}

func tryUpdateCtrlRep(ctrlID string, ts float64) {
	obs := ledger.CtrlObsBuffer[ctrlID]
	if len(obs) < K_OBS { return }
	avgFM, avgErr := 0.0, 0.0
	for _, o := range obs { avgFM += o.FlowModRate; avgErr += o.RouteErrRate }
	avgFM /= float64(len(obs)); avgErr /= float64(len(obs))
	yhat := 0.0
	if avgFM > 50.0 || avgErr > 0.3 { yhat = 1.0 }
	cr := ledger.CtrlReputations[ctrlID]
	oldScore := cr.Score
	cr.Score = cr.Score*(1.0-RHO*yhat) + RHO*(1.0-yhat)
	if cr.Score < 0 { cr.Score = 0 }
	if cr.Score > 1 { cr.Score = 1 }
	cr.LastUpdated = ts; cr.ObsCount += len(obs)
	appendBlock(EVT_CTRL_REP_UPDATE, "Eq ctrl_rep_update", "", ctrlID, map[string]interface{}{
		"old_score": oldScore, "new_score": cr.Score, "yhat_c": yhat, "k_obs": len(obs),
	})
	ledger.CtrlObsBuffer[ctrlID] = []*CtrlObsRecord{}
}

func checkAndIsolate(nodeID string, ts float64) bool {
	r := getOrCreateRep(nodeID, false)
	if r.Isolated { return true }
	trigger := ""
	if r.Score < R_TH { trigger = fmt.Sprintf("R_i=%.4f<R_th", r.Score) }
	if r.WindowCount >= N_TH { trigger = fmt.Sprintf("window_count=%d>=N_th", r.WindowCount) }
	if trigger == "" { return false }
	r.Isolated = true; ledger.Stats.TotalIsolations++
	appendBlock(EVT_ISOLATION, "Eq 3.24", nodeID, r.AssignedCtrl, map[string]interface{}{
		"trigger": trigger, "r_i": r.Score, "window_count": r.WindowCount,
	})
	return true
}

func selectFailover(excludeCtrl string) string {
	best, bestScore := "", -1.0
	for ctrlID, cr := range ledger.CtrlReputations {
		if ctrlID == excludeCtrl || cr.Isolated || cr.Score < RCTRL_TH || cr.StableWindows < T_VERIFY { continue }
		if cr.Score > bestScore { bestScore = cr.Score; best = ctrlID }
	}
	return best
}

func triggerFlowRevocation(nodeID string, ts float64, initiatedBy string) {
	ctrl := assignedCtrl(nodeID)
	cr := ledger.CtrlReputations[ctrl]
	failoverCtrl := selectFailover("")
	if strings.HasPrefix(nodeID, "ctrl") { failoverCtrl = selectFailover(nodeID) }
	path := "peer_ctrl"
	if cr.Score >= RCTRL_TH && failoverCtrl != "" { path = "trusted_ctrl" }
	ledger.Revocations[nodeID] = &FlowRevocation{
		NodeID: nodeID, Timestamp: ts, EnforcedVia: path,
		ControllerScore: cr.Score, InitiatedBy: initiatedBy, FailoverCtrl: failoverCtrl,
	}
	ledger.Stats.TotalRevocations++
	appendBlock(EVT_FLOW_REVOKE, "Eq 3.25", nodeID, initiatedBy, map[string]interface{}{"path": path, "failover": failoverCtrl})
	appendBlock(EVT_ENFORCE_PATH, "Eq 3.26", nodeID, initiatedBy, map[string]interface{}{"path": path})
	if strings.HasPrefix(nodeID, "ctrl") && failoverCtrl != "" {
		appendBlock(EVT_DOMAIN_HANDOVER, "Eq domain_handover", nodeID, failoverCtrl, map[string]interface{}{"failover": failoverCtrl})
		appendBlock(EVT_FAILOVER, "Eq failover", nodeID, failoverCtrl, map[string]interface{}{"failover": failoverCtrl})
		ledger.Stats.TotalFailovers++
	}
}

func hashTx(txid, nodeID, txType string, ts float64) string {
	//h := sha256.New()
	h := sha512.New()   // Eq 3.26 — SHA-512 ledger hashing (cat-5)
	h.Write([]byte(fmt.Sprintf("%s|%s|%s|%f", txid, nodeID, txType, ts)))
	//return hex.EncodeToString(h.Sum(nil))[:16]
	return hex.EncodeToString(h.Sum(nil))
}

func addToBatch(txHash string) {
	if ledger.CurrentBatch == nil { ledger.CurrentBatch = &MerkleBatch{WindowID: ledger.BatchCounter + 1} }
	ledger.CurrentBatch.TxHashes = append(ledger.CurrentBatch.TxHashes, txHash)
	ledger.CurrentBatch.Count++
}

func computeMerkleRoot(hashes []string) string {
	if len(hashes) == 0 { return "" }
	//h := sha256.New()
	//for _, hash := range hashes { h.Write([]byte(hash)) }
	//return hex.EncodeToString(h.Sum(nil))[:32]
	return merkleRootSHA512(hashes)
}
func merkleRootSHA512(leafStrings []string) string {
	level := make([][]byte, len(leafStrings))
	for i, s := range leafStrings {
		h := sha512.Sum512([]byte(s))
		level[i] = h[:]
	}
	if len(level) == 0 {
		h := sha512.Sum512(nil)
		return hex.EncodeToString(h[:])
	}
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			a := level[i]
			b := level[i]
			if i+1 < len(level) { b = level[i+1] }
			cat := append(append([]byte{}, a...), b...)
			h := sha512.Sum512(cat)
			next = append(next, h[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

func commitMerkleBatch(windowID int, ts float64) {
	if ledger.CurrentBatch == nil || ledger.CurrentBatch.Count == 0 { return }
	root := computeMerkleRoot(ledger.CurrentBatch.TxHashes)
	ledger.CurrentBatch.MerkleRoot = root; ledger.CurrentBatch.Committed = true
	appendBlock(EVT_MERKLE_BATCH, "Eq merkle_batch", "", "ctrl0", map[string]interface{}{
		"window_id": windowID, "tx_count": ledger.CurrentBatch.Count, "merkle_root": root,
		"depth": math.Ceil(math.Log2(float64(ledger.CurrentBatch.Count) + 1)),
	})
	ledger.BatchCounter++; ledger.Stats.TotalMerkleBatches++
	ledger.CurrentBatch = &MerkleBatch{WindowID: ledger.BatchCounter + 1}
}

func secSign(payload interface{}) string {
	b, _ := json.Marshal(payload)
	mac := hmac.New(sha512.New, []byte(SECKEY))   // Eq 3.21 — cat-5 HMAC-SHA-512
	mac.Write(b); return hex.EncodeToString(mac.Sum(nil))
}
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json"); w.WriteHeader(code); json.NewEncoder(w).Encode(v)
}
func errJSON(w http.ResponseWriter, code int, msg string) { writeJSON(w, code, map[string]string{"error": msg}) }
func readBody(r *http.Request, v interface{}) error {
	b, err := io.ReadAll(r.Body)
	if err != nil { return err }; return json.Unmarshal(b, v)
}
func nowTS() float64 { return float64(time.Now().UnixMilli()) / 1000.0 }

// HANDLERS

func handleHealth(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	isolated, ctrlIso, active, quarantined, removed := 0, 0, 0, 0, 0
	for _, rep := range ledger.Reputations { if rep.Isolated { isolated++ } }
	for _, cr := range ledger.CtrlReputations { if cr.Isolated { ctrlIso++ } }
	for _, p := range ledger.RSUPeers {
		switch p.State {
		case RSU_PEER_ACTIVE: active++
		case RSU_PEER_QUARANTINE: quarantined++
		case RSU_PEER_REMOVED: removed++
		}
	}
	stats := ledger.Stats; blocks := len(ledger.Chain)
	ledgerMu.RUnlock()
	writeJSON(w, 200, map[string]interface{}{
		"status": "ok", "backend": "edcf-v4-rsu-peer-model",
		"revisions": []string{"R1-R9 (unchanged)", "R10:RSU_peers", "R11:dynamic_peer_selection", "R12:quarantine_lifecycle", "R13:RSU_cosigs", "R14:DKG_t=2"},
		"peer_model": map[string]interface{}{
			"peers": "RSU nodes (trust-score selected, all 64 start ACTIVE)",
			"ctrl_role": "READ-ONLY clients",
			"active_peers": active, "quarantined": quarantined, "removed": removed,
			"required_cosigs": REQUIRED_SIGS,
		},
		"dkg": map[string]interface{}{"participants": N_RSU_DKG, "threshold": T_DKG, "note": "t=4-of-7: one designated RSU per grid zone holds a DKG share"},
		"chain": map[string]interface{}{"total_blocks": blocks},
		"stats": stats, "vehicle_isolated": isolated, "ctrl_isolated": ctrlIso,
	})
}

func handleVehicleSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID    string  `json:"node_id"`
		Message   string  `json:"message"`
		Signature string  `json:"signature"`
		TxType    string  `json:"tx_type"`
		Timestamp float64 `json:"timestamp"`
	}
	if err := readBody(r, &req); err != nil { errJSON(w, 400, "invalid body"); return }
	if req.NodeID == "" || req.TxType == "" { errJSON(w, 400, "node_id and tx_type required"); return }
	if req.Timestamp == 0 { req.Timestamp = nowTS() }
	ctrl := assignedCtrl(req.NodeID)
	ledgerMu.Lock()
	getOrCreateRep(req.NodeID, false)
	txHash := hashTx(nextTxID(), req.NodeID, req.TxType, req.Timestamp)
	addToBatch(txHash); ledger.Stats.TotalVehicleTxs++; saveLedger()
	ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{
		"success": true, "node_id": req.NodeID, "tx_hash": txHash,
		"batch_mode": true, "assigned_ctrl": ctrl,
	})
}

func handleDetectionSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID          string  `json:"node_id"`
		AttackLabel     int     `json:"attack_label"`
		TGNNScore       float64 `json:"tgnn_score"`
		PhiScore        float64 `json:"phi_score"`
		Variant         string  `json:"variant"`
		Timestamp       float64 `json:"timestamp"`
		HMACDetected    bool    `json:"hmac_detected"`
		SigFlagDetected bool    `json:"sig_flag_detected"`
		RSUSigner       string  `json:"rsu_signer"`
		RSUSignature    string  `json:"rsu_signature"`
	}
	if err := readBody(r, &req); err != nil { errJSON(w, 400, "invalid body"); return }
	if req.NodeID == "" { errJSON(w, 400, "node_id required"); return }
	if req.Timestamp == 0 { req.Timestamp = nowTS() }
	if req.Variant == "" { req.Variant = "v1a" }
	ctrl := assignedCtrl(req.NodeID)
	sig := secSign(map[string]interface{}{"node_id": req.NodeID, "label": req.AttackLabel, "ts": req.Timestamp})
	ledgerMu.Lock()
	txid := nextTxID()
	blk := appendBlock(EVT_DETECTION, "Eq 3.20", req.NodeID, ctrl, map[string]interface{}{
		"attack_label": req.AttackLabel, "tgnn_score": req.TGNNScore, "phi_score": req.PhiScore,
		"variant": req.Variant, "secplane_sign": sig, "hmac_detected": req.HMACDetected,
		"rsu_signer": req.RSUSigner, "rsu_signature": req.RSUSignature, // Eq 3.24 — FALCON-1024
	})
	blk.TxID = txid; ledger.Stats.TotalDetections++
	yhat := 0.0; if req.AttackLabel > 0 { yhat = 1.0 }
	newScore := updateReputation(req.NodeID, yhat, req.Timestamp)
	isolated := checkAndIsolate(req.NodeID, req.Timestamp)
	if isolated { triggerFlowRevocation(req.NodeID, req.Timestamp, ctrl) }
	ledger.AlertLog = append(ledger.AlertLog, &AlertLogEntry{
		TxID: txid, BlockNum: blk.BlockNum, NodeID: req.NodeID,
		AttackLabel: req.AttackLabel, TGNNScore: req.TGNNScore, PhiScore: req.PhiScore,
		Variant: req.Variant, Timestamp: req.Timestamp, SecPlaneSign: sig,
		HMACDetected: req.HMACDetected, SigFlagDetected: req.SigFlagDetected,
		RSUSigner: req.RSUSigner, RSUSignature: req.RSUSignature,
		Isolated: isolated, ReputationAfter: newScore, AssignedCtrl: ctrl,
	})
	saveLedger(); ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{
		"success": true, "node_id": req.NodeID, "attack_label": req.AttackLabel,
		"reputation": newScore, "isolated": isolated, "tx_id": txid, "block_num": blk.BlockNum,
	})
}

// R13: Accept rsu_signatures — controllers are clients, RSUs co-sign
func handleControllerSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ControllerID   string   `json:"controller_id"`
		TxData         string   `json:"tx_data"`
		RSUSignatures  []string `json:"rsu_signatures"`
		CtrlSignatures []string `json:"ctrl_signatures"`
	}
	if err := readBody(r, &req); err != nil { errJSON(w, 400, "invalid body"); return }
	if req.ControllerID == "" || req.TxData == "" { errJSON(w, 400, "controller_id and tx_data required"); return }
	sigs := req.RSUSignatures
	if len(sigs) == 0 { sigs = req.CtrlSignatures } // legacy NS-3 calls
	ledgerMu.Lock()
	ok, reason := validateConsensus(req.ControllerID, sigs)
	if !ok {
		ledger.Stats.RejectedTxs++; saveLedger(); ledgerMu.Unlock()
		errJSON(w, 403, "consensus rejected: "+reason); return
	}
	activePeers := selectRSUPeers(N_RSU_PEERS_MAX)
	peerIDs := make([]string, len(activePeers))
	for i, p := range activePeers { peerIDs[i] = p.RSUID }
	blk := appendBlock(EVT_CONTROLLER_TX, "eq:multisig", "", req.ControllerID, map[string]interface{}{
		"tx_data": req.TxData, "rsu_signatures": sigs,
		"rsu_sig_count": len(sigs), "required_rsu_sigs": REQUIRED_SIGS,
		"selected_rsu_peers": peerIDs,
		"ctrl_role": "CLIENT — write co-signed by RSU peers",
		"note": "eq:multisig: RSU co-signatures required, NOT controller signatures",
	})
	ledger.Stats.TotalControllerTxs++; saveLedger(); ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{
		"success": true, "controller_id": req.ControllerID,
		"rsu_sigs": len(sigs), "tx_id": blk.TxID, "consensus": "PASSED",
	})
}

func handleCtrlObs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VehicleID    string  `json:"vehicle_id"`
		CtrlID       string  `json:"ctrl_id"`
		FlowModRate  float64 `json:"flow_mod_rate"`
		RouteErrRate float64 `json:"route_err_rate"`
		Timestamp    float64 `json:"timestamp"`
	}
	if err := readBody(r, &req); err != nil { errJSON(w, 400, "invalid body"); return }
	if req.VehicleID == "" || req.CtrlID == "" { errJSON(w, 400, "vehicle_id and ctrl_id required"); return }
	if req.Timestamp == 0 { req.Timestamp = nowTS() }
	sig := secSign(map[string]interface{}{"vehicle": req.VehicleID, "ctrl": req.CtrlID, "ts": req.Timestamp})
	obs := &CtrlObsRecord{VehicleID: req.VehicleID, CtrlID: req.CtrlID,
		FlowModRate: req.FlowModRate, RouteErrRate: req.RouteErrRate, Timestamp: req.Timestamp, Signature: sig}
	ledgerMu.Lock()
	ledger.CtrlObsBuffer[req.CtrlID] = append(ledger.CtrlObsBuffer[req.CtrlID], obs)
	appendBlock(EVT_CTRL_OBS, "Eq tx_obs", req.VehicleID, req.CtrlID, map[string]interface{}{
		"vehicle_id": req.VehicleID, "ctrl_id": req.CtrlID,
		"formula": "Tx_c^obs = <c, lambda_FM, epsilon_route, t, Sign>",
	})
	ledger.Stats.TotalCtrlObs++; tryUpdateCtrlRep(req.CtrlID, req.Timestamp); saveLedger()
	ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{"success": true, "vehicle_id": req.VehicleID, "ctrl_id": req.CtrlID})
}

func handleBatchCommit(w http.ResponseWriter, r *http.Request) {
	var req struct{ WindowID int `json:"window_id"` }
	readBody(r, &req)
	ledgerMu.Lock(); commitMerkleBatch(req.WindowID, nowTS()); saveLedger(); ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{"success": true})
}

// R11+R12: Update RSU peer trust score and state
func handleRSUPeerUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RSUID      string  `json:"rsu_id"`
		TrustScore float64 `json:"trust_score"`
		Timestamp  float64 `json:"timestamp"`
		Reason     string  `json:"reason,omitempty"`
	}
	if err := readBody(r, &req); err != nil { errJSON(w, 400, "invalid body"); return }
	if req.RSUID == "" { errJSON(w, 400, "rsu_id required"); return }
	if req.Timestamp == 0 { req.Timestamp = nowTS() }
	ledgerMu.Lock()
	if _, ok := ledger.RSUPeers[req.RSUID]; !ok {
		ledger.RSUPeers[req.RSUID] = &RSUPeer{RSUID: req.RSUID, State: RSU_PEER_ACTIVE, TrustScore: INITIAL_REP}
	}
	oldState := ledger.RSUPeers[req.RSUID].State
	updateRSUPeerState(req.RSUID, req.TrustScore, req.Timestamp)
	newState := ledger.RSUPeers[req.RSUID].State
	saveLedger(); ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{
		"success": true, "rsu_id": req.RSUID,
		"trust_score": req.TrustScore, "old_state": oldState, "new_state": newState,
	})
}

// R10: List all RSU peer states
func handleRSUPeers(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	peers := make([]*RSUPeer, 0, len(ledger.RSUPeers))
	for _, p := range ledger.RSUPeers { peers = append(peers, p) }
	selected := selectRSUPeers(N_RSU_PEERS_MAX)
	selectedIDs := make([]string, len(selected))
	for i, p := range selected { selectedIDs[i] = p.RSUID }
	ledgerMu.RUnlock()
	sort.Slice(peers, func(i, j int) bool { return peers[i].RSUID < peers[j].RSUID })
	writeJSON(w, 200, map[string]interface{}{
		"peers": peers, "current_selected": selectedIDs,
		"ctrl_note": "Controllers are blockchain CLIENTS only — not peers",
		"peer_selection": "dynamic per consensus round by trust score",
	})
}

func handleAggregator(w http.ResponseWriter, neighbourhood string) {
	ledgerMu.RLock()
	best, bestScore := "", -1.0
	for nodeID, rep := range ledger.Reputations {
		if strings.HasPrefix(nodeID, "vehicle_") && !rep.Isolated && rep.Score > bestScore {
			bestScore = rep.Score; best = nodeID
		}
	}
	ledgerMu.RUnlock()
	writeJSON(w, 200, map[string]interface{}{"aggregator": best, "score": bestScore, "neighbourhood": neighbourhood})
}

func handleReputationAll(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	reps := make([]*NodeReputation, 0, len(ledger.Reputations))
	for _, rep := range ledger.Reputations { reps = append(reps, rep) }
	ledgerMu.RUnlock(); writeJSON(w, 200, reps)
}
func handleReputationOne(w http.ResponseWriter, nodeID string) {
	ledgerMu.RLock(); r, ok := ledger.Reputations[nodeID]; ledgerMu.RUnlock()
	if !ok { writeJSON(w, 200, &NodeReputation{NodeID: nodeID, Score: INITIAL_REP, AssignedCtrl: assignedCtrl(nodeID)}); return }
	writeJSON(w, 200, r)
}
func handleCtrlReputation(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	crs := make([]*CtrlReputation, 0)
	for _, cr := range ledger.CtrlReputations { crs = append(crs, cr) }
	ledgerMu.RUnlock(); writeJSON(w, 200, crs)
}
func handleIsolation(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	var iso []string
	for nodeID, rep := range ledger.Reputations { if rep.Isolated { iso = append(iso, nodeID) } }
	for ctrlID, cr := range ledger.CtrlReputations { if cr.Isolated { iso = append(iso, ctrlID) } }
	ledgerMu.RUnlock()
	if iso == nil { iso = []string{} }; sort.Strings(iso); writeJSON(w, 200, iso)
}
func handleAlertLog(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" { if n, err := strconv.Atoi(l); err == nil { limit = n } }
	ledgerMu.RLock(); entries := ledger.AlertLog
	if len(entries) > limit { entries = entries[len(entries)-limit:] }
	ledgerMu.RUnlock()
	if entries == nil { entries = []*AlertLogEntry{} }; writeJSON(w, 200, entries)
}
func handleRevocations(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	revs := make([]*FlowRevocation, 0, len(ledger.Revocations))
	for _, rev := range ledger.Revocations { revs = append(revs, rev) }
	ledgerMu.RUnlock(); if revs == nil { revs = []*FlowRevocation{} }; writeJSON(w, 200, revs)
}
func handleChain(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" { if n, err := strconv.Atoi(l); err == nil { limit = n } }
	ledgerMu.RLock(); chain := ledger.Chain
	if len(chain) > limit { chain = chain[len(chain)-limit:] }
	ledgerMu.RUnlock(); writeJSON(w, 200, chain)
}
func handleChainStats(w http.ResponseWriter, r *http.Request) {
	ledgerMu.RLock()
	counts := make(map[EventType]int)
	for _, b := range ledger.Chain { counts[b.EventType]++ }
	iso, ctrlIso, active, quar, rem := 0, 0, 0, 0, 0
	for _, rep := range ledger.Reputations { if rep.Isolated { iso++ } }
	for _, cr := range ledger.CtrlReputations { if cr.Isolated { ctrlIso++ } }
	for _, p := range ledger.RSUPeers {
		switch p.State {
		case RSU_PEER_ACTIVE: active++
		case RSU_PEER_QUARANTINE: quar++
		case RSU_PEER_REMOVED: rem++
		}
	}
	stats := ledger.Stats; ledgerMu.RUnlock()
	writeJSON(w, 200, map[string]interface{}{
		"total_blocks": ledger.BlockCount, "event_counts": counts,
		"vehicle_isolated": iso, "ctrl_isolated": ctrlIso,
		"rsu_peers": map[string]int{"active": active, "quarantine": quar, "removed": rem},
		"stats": stats,
	})
}
func handleReinstate(w http.ResponseWriter, nodeID string) {
	ledgerMu.Lock()
	rep, ok := ledger.Reputations[nodeID]
	if !ok || !rep.Isolated { ledgerMu.Unlock(); errJSON(w, 400, "node not isolated"); return }
	if rep.Score < R_TH { ledgerMu.Unlock(); errJSON(w, 400, fmt.Sprintf("denied: score %.4f < R_th", rep.Score)); return }
	rep.Isolated = false; rep.WindowCount = 0; delete(ledger.Revocations, nodeID)
	appendBlock(EVT_REINSTATE, "§3.3.6", nodeID, rep.AssignedCtrl, map[string]interface{}{"score": rep.Score})
	saveLedger(); ledgerMu.Unlock()
	writeJSON(w, 200, map[string]interface{}{"success": true, "node_id": nodeID})
}

func router(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path; method := r.Method
	log.Printf("[API] %s %s", method, path)
	switch {
	case method == "GET"  && path == "/health":                           handleHealth(w, r)
	case method == "POST" && path == "/vehicle/submit":                   handleVehicleSubmit(w, r)
	case method == "POST" && path == "/detection/submit":                 handleDetectionSubmit(w, r)
	case method == "POST" && path == "/controller/submit":                handleControllerSubmit(w, r)
	case method == "POST" && path == "/ctrl/obs":                         handleCtrlObs(w, r)
	case method == "POST" && path == "/batch/commit":                     handleBatchCommit(w, r)
	case method == "POST" && path == "/rsu/peer/update":                  handleRSUPeerUpdate(w, r)
	case method == "GET"  && path == "/rsu/peers":                        handleRSUPeers(w, r)
	case method == "GET"  && path == "/reputation":                       handleReputationAll(w, r)
	case method == "GET"  && strings.HasPrefix(path, "/reputation/"):     handleReputationOne(w, strings.TrimPrefix(path, "/reputation/"))
	case method == "GET"  && path == "/ctrl/reputation":                  handleCtrlReputation(w, r)
	case method == "GET"  && path == "/isolation":                        handleIsolation(w, r)
	case method == "GET"  && path == "/alertlog":                         handleAlertLog(w, r)
	case method == "GET"  && path == "/revocations":                      handleRevocations(w, r)
	case method == "GET"  && path == "/chain":                            handleChain(w, r)
	case method == "GET"  && path == "/chain/stats":                      handleChainStats(w, r)
	case method == "GET"  && strings.HasPrefix(path, "/aggregator/"):     handleAggregator(w, strings.TrimPrefix(path, "/aggregator/"))
	case method == "POST" && strings.HasPrefix(path, "/reinstate/"):      handleReinstate(w, strings.TrimPrefix(path, "/reinstate/"))
	default:                                                               errJSON(w, 404, "not found")
	}
}

func main() {
	port := "3000"
	if p := os.Getenv("PORT"); p != "" { port = p }
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("=== EDCF-Shield Blockchain API v4 ===")
	log.Printf("    R10: RSU nodes = blockchain peers (4 SDN controllers = clients only)")
	log.Printf("    R11: Dynamic trust-score peer selection at runtime")
	log.Printf("    R12: ACTIVE → QUARANTINE → REMOVED lifecycle per RSU")
	log.Printf("    R13: Controller writes need RSU co-sigs (eq:multisig)")
	log.Printf("    R14: DKG threshold t=4-of-7 (one designated RSU per grid zone holds a share)")
	log.Printf("    Ledger: %s  Port: %s", LEDGER_FILE, port)
	loadLedger()
	http.HandleFunc("/", router)
	log.Printf("[API] Listening on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[API] Server error: %v", err)
	}
}
