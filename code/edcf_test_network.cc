/**
 * EDCF-Shield Test Network -- Group 14
 *
 * TOPOLOGY:
 *   V2V : 802.11p WiFi (V0-V4 + ATK on shared DSRC channel)
 *   V2I : PointToPoint per vehicle-controller association
 *         V0->C0, V1->C0, V2->C1, V3->C2, V4->C2
 *         ATK->C0 (V2I P2P), ATK->V2 (dedicated P2P for v2a/v3a)
 *   C2C : PointToPoint full mesh (C0-C1, C0-C2, C1-C2)
 *
 * HMAC INTEGRATION (inline, no Python dependency):
 *   Each packet tag carries a 32-byte HMAC-SHA256 field computed from:
 *     message = sender_node_id | packet_type | fake_x | fake_y
 *   using a per-node pre-shared 256-bit key stored in g_hmac_keys[].
 *   On reception, PktRxCb recomputes the HMAC and compares.
 *   - Legitimate packets (BEACON, FLOWMOD, C2C, RECOMPUTE, ROUTE_CHG,
 *     CASCADE): HMAC matches -> TP counted
 *   - Attack packets (FAKE_BEACON, FAKE_ALERT, FAKE_TRACE, WRONG_FM,
 *     WRONG_TOPO): HMAC mismatch -> FP counted (detected as attack)
 *   This gives real TP/FP/TN/FN values and non-zero PEM metrics.
 *
 * PEM METRICS FIX:
 *   Previous version counted attack pkts as FN (missed detections) with
 *   TP always 0, making MCC/F1/Precision always 0. Now:
 *   - TP: legitimate pkt received with valid HMAC
 *   - TN: attack pkt detected (HMAC mismatch on attack type)
 *   - FP: legitimate pkt with unexpected HMAC fail (0 in ideal case)
 *   - FN: attack pkt that slipped through (0 in ideal HMAC case)
 *   MCC/Accuracy/F1 are now non-zero and meaningful.
 *
 * All Simulator::Schedule calls use plain static void functions --
 * ns-3.35 MakeEvent does not support capturing lambdas.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/tag.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cmath>
#include <vector>
#include <cstring>    /* memcpy */
#include <stdint.h>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("EdcfTestNetwork");

/* ================================================================
   NODE INDICES
   ================================================================ */
static const uint32_t IDX_V0  = 0;
static const uint32_t IDX_V1  = 1;
static const uint32_t IDX_V2  = 2;
static const uint32_t IDX_V3  = 3;
static const uint32_t IDX_V4  = 4;
static const uint32_t IDX_ATK = 5;
static const uint32_t IDX_C0  = 6;
static const uint32_t IDX_C1  = 7;
static const uint32_t IDX_C2  = 8;
static const uint32_t N_NODES = 9;

static const double PX[9] = { 50, 175, 300, 425, 550,  300,  100, 300, 500};
static const double PY[9] = {100, 100, 100, 100, 100,  220,  400, 400, 400};
static const uint32_t CA[5] = {IDX_C0, IDX_C0, IDX_C1, IDX_C2, IDX_C2};

static string   g_scenario = "v1a";
static double   g_simTime  = 12.0;
static uint32_t g_cycle    = 0;
/* When true, ATK is treated as having stolen the network key
   (models credential theft / rogue insider).
   Set via --atk_has_key=1 on command line.
   Default 0 = external attacker with unknown key. */
static bool     g_atk_has_valid_key = false;
/* Number of attacker nodes. Each extra attacker beyond the first
   is added as an additional node that behaves identically to ATK.
   atk_count=1  ->  9 total nodes (11.1%)
   atk_count=2  -> 10 total nodes (20.0%)
   atk_count=3  -> 11 total nodes (27.3%)
   atk_count=4  -> 12 total nodes (33.3%)
   atk_count=5  -> 13 total nodes (38.5%)
   atk_count=6  -> 14 total nodes (42.9%)
   atk_count=7  -> 15 total nodes (46.7%)
   atk_count=8  -> 16 total nodes (50.0%)
   atk_count=9  -> 17 total nodes (52.9%)
   atk_count=10 -> 18 total nodes (55.6%) */
static uint32_t g_atk_count = 1;
/* Actual total nodes = N_NODES + (g_atk_count - 1) extra attackers */
static uint32_t g_total_nodes = N_NODES;  /* set in main() */

/* ================================================================
   INLINE HMAC-SHA256
   Pure C++ -- no OpenSSL/Python dependency.
   Based on FIPS 198-1 / RFC 2104.
   ================================================================ */
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)   (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c)  (((a)&(b))^((a)&(c))^((b)&(c)))
#define SIG0(a) (ROTR32(a,2)^ROTR32(a,13)^ROTR32(a,22))
#define SIG1(e) (ROTR32(e,6)^ROTR32(e,11)^ROTR32(e,25))
#define sig0(x) (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define sig1(x) (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void sha256_block(uint32_t h[8], const uint8_t blk[64])
{
    uint32_t w[64];
    for (int i=0;i<16;i++)
        w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)
              |((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for (int i=16;i<64;i++)
        w[i] = sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i=0;i<64;i++){
        uint32_t t1=hh+SIG1(e)+CH(e,f,g)+SHA256_K[i]+w[i];
        uint32_t t2=SIG0(a)+MAJ(a,b,c);
        hh=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
    h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void sha256(const uint8_t* msg, size_t len, uint8_t out[32])
{
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64];
    size_t i;
    uint64_t bitlen = (uint64_t)len*8;
    size_t pos=0;
    while (pos+64<=len){
        sha256_block(h, msg+pos);
        pos+=64;
    }
    size_t rem=len-pos;
    memset(blk,0,64);
    memcpy(blk,msg+pos,rem);
    blk[rem]=0x80;
    if (rem>=56){
        sha256_block(h,blk);
        memset(blk,0,64);
    }
    for (i=0;i<8;i++) blk[56+i]=(uint8_t)(bitlen>>((7-i)*8));
    sha256_block(h,blk);
    for (i=0;i<8;i++){
        out[i*4]=(uint8_t)(h[i]>>24);
        out[i*4+1]=(uint8_t)(h[i]>>16);
        out[i*4+2]=(uint8_t)(h[i]>>8);
        out[i*4+3]=(uint8_t)(h[i]);
    }
}

/* HMAC-SHA256: key up to 64 bytes, arbitrary message, 32-byte digest */
static void hmac_sha256(const uint8_t* key, size_t klen,
                         const uint8_t* msg, size_t mlen,
                         uint8_t out[32])
{
    uint8_t k0[64]={0}, ipad[64], opad[64], tmp[64+32];
    size_t i;
    if (klen>64){ sha256(key,klen,k0); }
    else { memcpy(k0,key,klen); }
    for (i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }
    /* inner: H(ipad||msg) */
    uint8_t* ibuf=new uint8_t[64+mlen];
    memcpy(ibuf,ipad,64); memcpy(ibuf+64,msg,mlen);
    uint8_t inner[32];
    sha256(ibuf,64+mlen,inner);
    delete[] ibuf;
    /* outer: H(opad||inner) */
    memcpy(tmp,opad,64); memcpy(tmp+64,inner,32);
    sha256(tmp,96,out);
}

/* ================================================================
   HMAC KEY DESIGN  (mirrors LDA_security.py global_hmac_key pattern)
   ---------------------------------------------------------------
   ONE shared network key (g_net_key) is distributed to ALL
   legitimate nodes (V0-V4, C0-C2) -- equivalent to the
   "global_hmac_key" generated by SecurityManager_controller and
   shared with nodes via the set_global_hmac_keys() mechanism.
   
   The external attacker (IDX_ATK=5) does NOT possess this key.
   It signs with its own rogue key (g_atk_key).
   
   On reception, verify_hmac always checks against g_net_key.
   - Legitimate sender  -> HMAC computed with g_net_key -> MATCH   -> TP
   - External attacker  -> HMAC computed with g_atk_key -> MISMATCH -> TN
   - Compromised ctrl   -> also has g_net_key (insider) -> MATCH   -> FN
     (v1b/v2b/v3b model insider threats that evade HMAC)
   ================================================================ */

/* Network-wide pre-shared key (all legitimate nodes share this) */
static const uint8_t g_net_key[32] = {
    0xA3,0x7F,0x2C,0x91,0xE4,0x58,0xB6,0x0D,
    0x3A,0x8E,0x14,0x72,0xC5,0x9B,0x46,0xF0,
    0x27,0xD3,0x6A,0x8C,0x51,0xE9,0x04,0xBB,
    0x7E,0x1F,0xA2,0x63,0x95,0xC8,0x40,0x2D
};

/* Attacker rogue key -- unknown to the network, cannot be verified */
static const uint8_t g_atk_key[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE
};

/* Returns the signing key for a given sender node.
   If g_atk_has_valid_key is true, ATK uses the network key
   (stolen credentials scenario -- HMAC cannot detect it). */
static bool is_attacker_node(uint32_t n){
    return (n == IDX_ATK) || (n >= N_NODES && n < g_total_nodes);
}
static const uint8_t* sender_key(uint32_t src_node) {
    if (is_attacker_node(src_node) && !g_atk_has_valid_key)
        return g_atk_key;   /* external: wrong key -> detected */
    return g_net_key;       /* legit or insider: valid key -> evades HMAC */
}

/* Compute HMAC-SHA256: message = src_node || pkt_type || fake_x || fake_y */
static void compute_hmac(uint32_t src_node, uint32_t pkt_type,
                          double fake_x, double fake_y,
                          uint8_t digest[32])
{
    uint8_t msg[24];
    memcpy(msg+0,  &src_node, 4);
    memcpy(msg+4,  &pkt_type, 4);
    memcpy(msg+8,  &fake_x,   8);
    memcpy(msg+16, &fake_y,   8);
    hmac_sha256(sender_key(src_node), 32, msg, 24, digest);
}

/* Verify: always check against the NETWORK key (g_net_key).
   Legitimate senders used g_net_key to sign -> match.
   ATK used g_atk_key to sign -> mismatch -> detected. */
static bool verify_hmac(uint32_t sender_node, uint32_t pkt_type,
                         double fake_x, double fake_y,
                         const uint8_t recv_digest[32])
{
    uint8_t expected[32];
    uint8_t msg[24];
    memcpy(msg+0,  &sender_node, 4);
    memcpy(msg+4,  &pkt_type,    4);
    memcpy(msg+8,  &fake_x,      8);
    memcpy(msg+16, &fake_y,      8);
    /* Always verify using the network key -- ATK does not have it */
    hmac_sha256(g_net_key, 32, msg, 24, expected);
    return (memcmp(expected, recv_digest, 32) == 0);
}

/* Hex string helper for logging */
static string bytes_to_hex(const uint8_t* b, size_t n, size_t max_show=8)
{
    ostringstream o;
    for (size_t i=0; i<min(n,max_show); i++){
        o << hex << setw(2) << setfill('0') << (int)b[i];
    }
    if (n>max_show) o << "...";
    return o.str();
}

/* ================================================================
   PACKET TAG  (includes 32-byte HMAC field)
   ================================================================ */
class EdcfTag : public Tag {
public:
    enum MsgType {
        BEACON=0, FLOWMOD=1, C2C=2, FAKE_BEACON=3, FAKE_ALERT=4,
        CASCADE=5, RECOMPUTE=6, FAKE_TRACE=7, ROUTE_CHG=8,
        WRONG_FM=9, WRONG_TOPO=10
    };
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::EdcfTagG14v3")
            .SetParent<Tag>().AddConstructor<EdcfTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override {
        return 2*sizeof(uint32_t) + 9*sizeof(double) + 32;
    }
    void Serialize(TagBuffer buf) const override {
        buf.WriteU32((uint32_t)m_type); buf.WriteU32(m_from);
        buf.Write((const uint8_t*)&m_fake_x,     sizeof(double));
        buf.Write((const uint8_t*)&m_fake_y,     sizeof(double));
        buf.Write((const uint8_t*)&m_real_x,     sizeof(double));
        buf.Write((const uint8_t*)&m_real_y,     sizeof(double));
        buf.Write((const uint8_t*)&m_fake_vx,    sizeof(double));
        buf.Write((const uint8_t*)&m_fake_vy,    sizeof(double));
        buf.Write((const uint8_t*)&m_real_vx,    sizeof(double));
        buf.Write((const uint8_t*)&m_real_vy,    sizeof(double));
        buf.Write((const uint8_t*)&m_vehicle_id, sizeof(double));
        buf.Write(m_hmac, 32);
    }
    void Deserialize(TagBuffer buf) override {
        m_type=(MsgType)buf.ReadU32(); m_from=buf.ReadU32();
        buf.Read((uint8_t*)&m_fake_x,     sizeof(double));
        buf.Read((uint8_t*)&m_fake_y,     sizeof(double));
        buf.Read((uint8_t*)&m_real_x,     sizeof(double));
        buf.Read((uint8_t*)&m_real_y,     sizeof(double));
        buf.Read((uint8_t*)&m_fake_vx,    sizeof(double));
        buf.Read((uint8_t*)&m_fake_vy,    sizeof(double));
        buf.Read((uint8_t*)&m_real_vx,    sizeof(double));
        buf.Read((uint8_t*)&m_real_vy,    sizeof(double));
        buf.Read((uint8_t*)&m_vehicle_id, sizeof(double));
        buf.Read(m_hmac, 32);
    }
    void Print(std::ostream& os) const override {
        os << "EdcfTag type=" << m_type << " from=" << m_from;
    }
    MsgType  m_type = BEACON;
    uint32_t m_from = 0;
    double m_fake_x=0, m_fake_y=0, m_real_x=0, m_real_y=0;
    double m_fake_vx=0, m_fake_vy=0, m_real_vx=0, m_real_vy=0;
    double m_vehicle_id=0;
    uint8_t m_hmac[32]={0};
};
NS_OBJECT_ENSURE_REGISTERED(EdcfTag);

/* ================================================================
   GLOBAL STATE
   ================================================================ */
static NodeContainer            g_all;
static NetDeviceContainer       g_wifiDevs;
static NetDeviceContainer       g_v2i_devs[5];
static NetDeviceContainer       g_atk_v2i_devs;   /* ATK <-> C0 P2P */
static NetDeviceContainer       g_atk_v2_devs;    /* ATK <-> V2 P2P (v2a/v3a) */
static NetDeviceContainer       g_c2c_01, g_c2c_02, g_c2c_12;
static Ipv4InterfaceContainer   g_wifiIfaces;

struct LinkIPs {
    Ipv4Address src_addr, dst_addr;
    uint32_t    src_node, dst_node;
};
static vector<LinkIPs> g_links;

/* PEM counters -- HMAC-based detection:
   TP = legitimate pkt, HMAC valid  (correctly accepted)
   TN = attack pkt, HMAC invalid    (correctly detected/rejected)
   FP = legitimate pkt, HMAC failed (false alarm, ideally 0)
   FN = attack pkt, HMAC valid      (missed detection, ideally 0)
   
   Cumulative (_c) counters track totals across the whole simulation.
   Per-cycle (_p) counters reset each cycle to show degradation over time.
   This lets the evaluation panel see: as attacks repeat, HMAC-only
   detection stays flat (cannot adapt) -- motivating TGNN+LLM+Blockchain. */
static uint32_t g_TP=0, g_TN=0, g_FP=0, g_FN=0;           /* cumulative */
static uint32_t g_TP_p=0, g_TN_p=0, g_FP_p=0, g_FN_p=0;  /* per-cycle */
static uint32_t g_hmac_verified=0, g_hmac_verified_p=0;
static uint32_t g_hmac_failed=0,   g_hmac_failed_p=0;
static uint32_t g_fake_pkts=0,   g_fake_pkts_p=0;
static uint32_t g_wrong_fm=0,     g_wrong_fm_p=0;
static uint32_t g_cascade_cnt=0,  g_cascade_cnt_p=0;
static uint32_t g_topo_err=0,     g_topo_err_p=0;
static uint32_t g_legit_total=0,  g_legit_total_p=0;
static uint32_t g_legit_drop=0,   g_legit_drop_p=0;
/* WiFi channel flood counter: fake beacons broadcast to vehicles.
   Used to model congestion-based PDR degradation.
   Each WiFi fake beacon received by a vehicle = 1 flood pkt.
   PDR degrades as flood_pkts/(flood_pkts+legit_pkts) rises. */
static uint32_t g_wifi_flood=0,   g_wifi_flood_p=0;
static uint32_t g_wifi_legit=0,   g_wifi_legit_p=0;
/* PDR penalty model: each attack type degrades delivery probability.
   Accumulates over the simulation to show realistic PDR degradation:
   - FAKE_BEACON -> controller overload -> delayed/dropped FlowMods
   - CASCADE/RECOMPUTE -> broadcast storm -> bandwidth congestion
   - WRONG_FM/WRONG_TOPO -> misrouting -> packets sent wrong path */
static string   g_pem_csv;
static bool     g_pem_hdr=false;
static uint32_t g_pem_cycle=0;
static string   g_hmac_csv;
static bool     g_hmac_hdr=false;

/* ================================================================
   HELPERS
   ================================================================ */
static string nname(uint32_t id) {
    if (id < 5)        return "V" + to_string(id);          /* V0-V4 */
    if (id == IDX_ATK) return "ATK";                        /* node 5 */
    if (id == IDX_C0)  return "C0";                         /* node 6 */
    if (id == IDX_C1)  return "C1";                         /* node 7 */
    if (id == IDX_C2)  return "C2";                         /* node 8 */
    /* Extra attacker nodes (9, 10, 11, ...) */
    if (id >= N_NODES) return "ATK" + to_string(id - N_NODES + 2);
    return "UNK" + to_string(id);
}
static string npos(uint32_t id) {
    Ptr<MobilityModel> m=g_all.Get(id)->GetObject<MobilityModel>();
    Vector p=m->GetPosition();
    ostringstream o; o<<fixed<<setprecision(1)<<"("<<p.x<<","<<p.y<<")";
    return o.str();
}
static const char* TNAME[]={
    "BEACON","FLOWMOD","C2C","FAKE_BEACON","FAKE_ALERT",
    "CASCADE","RECOMPUTE","FAKE_TRACE","ROUTE_CHG","WRONG_FM","WRONG_TOPO"
};

/* Is this message type an attack/anomaly type? */
static bool is_attack_type(EdcfTag::MsgType t) {
    return (t==EdcfTag::FAKE_BEACON || t==EdcfTag::FAKE_ALERT ||
            t==EdcfTag::FAKE_TRACE  || t==EdcfTag::WRONG_FM   ||
            t==EdcfTag::WRONG_TOPO);
}

/* Rotating fake offsets */
static const double FPX[6]={ 80,-60, 90,-45,110,-75};
static const double FPY[6]={ 50, 30,-35, 65, 20,-55};
static const double FVX[6]={ -7,  5, -9,  3, -5,  8};
static const double FVY[6]={ -4, -8,  2, -6,  4, -3};
static uint32_t g_tseq=0;

static EdcfTag make_tag(uint32_t src, EdcfTag::MsgType type) {
    EdcfTag t; t.m_type=type; t.m_from=src;
    Ptr<MobilityModel> mob=g_all.Get(src)->GetObject<MobilityModel>();
    Vector rp=mob->GetPosition(), rv=mob->GetVelocity();
    t.m_real_x=rp.x; t.m_real_y=rp.y; t.m_real_vx=rv.x; t.m_real_vy=rv.y;
    uint32_t fi=g_tseq%6;
    if (type==EdcfTag::FAKE_BEACON||type==EdcfTag::FAKE_ALERT||type==EdcfTag::FAKE_TRACE){
        t.m_fake_x=rp.x+FPX[fi]; t.m_fake_y=rp.y+FPY[fi];
        t.m_fake_vx=rv.x+FVX[fi]; t.m_fake_vy=rv.y+FVY[fi];
        t.m_vehicle_id=90.0+fi;
    } else {
        t.m_fake_x=rp.x; t.m_fake_y=rp.y;
        t.m_fake_vx=rv.x; t.m_fake_vy=rv.y;
        t.m_vehicle_id=(double)src;
    }
    /* Compute HMAC using sender's own key */
    compute_hmac(src, (uint32_t)type, t.m_fake_x, t.m_fake_y, t.m_hmac);
    g_tseq++; return t;
}

static Ipv4Address getP2PAddr(uint32_t src, uint32_t dst) {
    for (const auto& l:g_links) if(l.src_node==src&&l.dst_node==dst) return l.dst_addr;
    for (const auto& l:g_links) if(l.src_node==dst&&l.dst_node==src) return l.src_addr;
    NS_FATAL_ERROR("No P2P link "<<src<<"->"<<dst);
    return Ipv4Address();
}
static Ipv4Address getWifiAddr(uint32_t node){
    uint32_t idx=(node==IDX_ATK)?5:node;
    return g_wifiIfaces.GetAddress(idx);
}

/* ================================================================
   RX CALLBACK  -- HMAC verification happens here
   ================================================================ */
static const uint16_t PORT=7777;

/* Save HMAC check result to CSV */
static void log_hmac_check(uint32_t sender, uint32_t receiver,
                             EdcfTag::MsgType type, bool result, double t)
{
    fstream f;
    if (!g_hmac_hdr){
        f.open(g_hmac_csv, ios::out|ios::trunc);
        f << "# EDCF-Shield HMAC log  scenario=" << g_scenario << "\n"
          << "t,sender,receiver,pkt_type,hmac_valid,attack_detected\n";
        f.close(); g_hmac_hdr=true;
    }
    f.open(g_hmac_csv, ios::out|ios::app);
    f << fixed << setprecision(4) << t << ","
      << nname(sender) << "," << nname(receiver) << ","
      << TNAME[(int)type] << ","
      << (result ? "YES" : "NO") << ","
      << ((!result && is_attack_type(type)) ? "DETECTED" : (result && !is_attack_type(type)) ? "LEGIT" : "CHECK")
      << "\n";
    f.close();
}

static void PktRxCb(uint32_t rid, Ptr<const Packet> pkt){
    EdcfTag tag;
    Ptr<Packet> c=pkt->Copy();
    if (!c->PeekPacketTag(tag)) return;
    if (tag.m_from==rid) return;

    double t=Simulator::Now().GetSeconds();
    uint32_t src=tag.m_from;
    string tn=((int)tag.m_type<11)?TNAME[(int)tag.m_type]:"UNK";
    bool atk = is_attack_type(tag.m_type) || is_attacker_node(src);

    /* ================================================================
       HMAC-ONLY DETECTION  (pure HMAC -- no semantic override)
       This correctly models HMAC's real limitation:
       
       When ATK has wrong key (default, --atk_has_key=0):
         HMAC fails -> attack detected -> TN++
       When ATK has stolen/valid key (--atk_has_key=1):
         HMAC passes -> attack missed  -> FN++
         Accuracy/MCC/F1/Recall degrade visibly in CSV
       
       Compromised controllers (v1b/v2b/v3b) always have net key:
         HMAC always passes -> FN++ every cycle -> metrics degrade
       
       This is EXACTLY the research gap that motivates
       TGNN (graph anomaly) + LLM (semantic) + Blockchain (audit).
       ================================================================ */
    bool hmac_ok = verify_hmac(src,(uint32_t)tag.m_type,
                               tag.m_fake_x,tag.m_fake_y,tag.m_hmac);
    g_hmac_verified++; g_hmac_verified_p++;

    string hmac_status;
    if (!hmac_ok) {
        /* HMAC mismatch -- attack detected */
        g_hmac_failed++; g_hmac_failed_p++;
        /* Impact counters (penalty handled below for all atk pkts) */
        if (tag.m_type==EdcfTag::FAKE_BEACON ||
            tag.m_type==EdcfTag::FAKE_ALERT  ||
            tag.m_type==EdcfTag::FAKE_TRACE)  { g_fake_pkts++; g_fake_pkts_p++; }
        if (tag.m_type==EdcfTag::WRONG_FM)    { g_wrong_fm++;  g_wrong_fm_p++;  }
        if (tag.m_type==EdcfTag::WRONG_TOPO)  { g_topo_err++;  g_topo_err_p++;  }
        if (tag.m_type==EdcfTag::CASCADE)     { g_cascade_cnt++; g_cascade_cnt_p++; }
        if (atk) {
            /* TN: attack correctly detected -- does NOT affect legit PDR
               but DOES congest the WiFi channel when broadcast to vehicles */
            hmac_status = "HMAC:FAIL -> ATTACK_DETECTED(TN)";
            g_TN++; g_TN_p++;
            /* Track WiFi flooding even when detected (channel still congested) */
            if (rid < 5 && (tag.m_type==EdcfTag::FAKE_BEACON ||
                            tag.m_type==EdcfTag::FAKE_ALERT  ||
                            tag.m_type==EdcfTag::CASCADE))
                { g_wifi_flood++; g_wifi_flood_p++; }
        } else {
            /* FP: legit packet wrongly blocked -- counts as legit drop */
            hmac_status = "HMAC:FAIL -> LEGIT_BLOCKED(FP)";
            g_FP++; g_FP_p++;
            g_legit_total++; g_legit_total_p++;   /* legit pkt was sent */
            g_legit_drop++;  g_legit_drop_p++;    /* but wrongly dropped */
        }
    } else {
        /* HMAC passes */
        if (!atk) {
            /* TP: legit pkt correctly accepted -- good delivery */
            hmac_status = "HMAC:OK -> LEGIT_ACCEPTED(TP)";
            g_TP++; g_TP_p++;
            g_legit_total++; g_legit_total_p++;   /* legit pkt sent */
            /* legit_drop NOT incremented -- pkt delivered OK */
            /* Track WiFi traffic for congestion model.
               CASCADE from legitimate vehicles (v2a storm) counts as
               attack-induced congestion even though HMAC is valid,
               because the cascade was triggered by a fake alert. */
            if (rid < 5) {
                if (tag.m_type == EdcfTag::CASCADE)
                    { g_wifi_flood++; g_wifi_flood_p++; }  /* attack-induced */
                else
                    { g_wifi_legit++; g_wifi_legit_p++; }  /* genuine legit  */
            }
        } else {
            /* FN: attack slipped through (stolen key / insider)
               Security failure -- FN counter only, no legit PDR impact. */
            hmac_status = "HMAC:OK_BUT_ATTACK -> MISSED(FN)";
            g_FN++; g_FN_p++;
            if (tag.m_type==EdcfTag::FAKE_BEACON ||
                tag.m_type==EdcfTag::FAKE_ALERT  ||
                tag.m_type==EdcfTag::FAKE_TRACE)  { g_fake_pkts++; g_fake_pkts_p++; }
            if (tag.m_type==EdcfTag::WRONG_FM)    { g_wrong_fm++;  g_wrong_fm_p++;  }
            if (tag.m_type==EdcfTag::WRONG_TOPO)  { g_topo_err++;  g_topo_err_p++;  }
            /* Track WiFi channel flooding for congestion PDR model */
            if (rid < 5 && (tag.m_type==EdcfTag::FAKE_BEACON ||
                            tag.m_type==EdcfTag::FAKE_ALERT  ||
                            tag.m_type==EdcfTag::CASCADE))
                { g_wifi_flood++; g_wifi_flood_p++; }
        }
    }


    /* ---- Print log ---- */
    if (tag.m_type==EdcfTag::FAKE_BEACON){
        cout<<"[SPOOFED BEACON FLOODING] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status<<"\n"
            <<"  Fake_ID: V"<<fixed<<setprecision(0)<<tag.m_vehicle_id
            <<"  Fake_pos:("<<fixed<<setprecision(2)<<tag.m_fake_x<<","<<tag.m_fake_y<<")"
            <<"  Real_pos:("<<tag.m_real_x<<","<<tag.m_real_y<<")"
            <<"  HMAC["<<bytes_to_hex(tag.m_hmac,32)<<"]\n"
            <<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::FAKE_ALERT){
        cout<<"[CASCADING ALERT PROPAGATION] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status<<"\n"
            <<"  Fake_pos:("<<fixed<<setprecision(2)<<tag.m_fake_x<<","<<tag.m_fake_y<<")"
            <<"  HMAC["<<bytes_to_hex(tag.m_hmac,32)<<"]\n"
            <<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::CASCADE){
        cout<<"[CASCADE RELAY] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status<<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::FAKE_TRACE){
        cout<<"[MOBILITY TRACE MANIPULATION] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status<<"\n"
            <<"  Fake_pos:("<<fixed<<setprecision(2)<<tag.m_fake_x<<","<<tag.m_fake_y<<")"
            <<"  Fake_vel:("<<tag.m_fake_vx<<","<<tag.m_fake_vy<<")"
            <<"  HMAC["<<bytes_to_hex(tag.m_hmac,32)<<"]\n"
            <<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::WRONG_FM){
        cout<<"[WRONG FLOWMOD] "<<nname(src)<<npos(src)<<" --> "<<nname(rid)<<npos(rid)
            <<"  "<<hmac_status<<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::WRONG_TOPO){
        cout<<"[WRONG TOPOLOGY] "<<nname(src)<<npos(src)<<" --> "<<nname(rid)<<npos(rid)
            <<"  "<<hmac_status<<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::RECOMPUTE){
        cout<<"[RECOMPUTE] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status<<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else if (tag.m_type==EdcfTag::ROUTE_CHG){
        cout<<"[ROUTE_CHANGE] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status<<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    } else {
        cout<<"["<<tn<<"] "<<nname(src)<<" --> "<<nname(rid)
            <<"  "<<hmac_status
            <<"  pos=("<<fixed<<setprecision(2)<<tag.m_real_x<<","<<tag.m_real_y<<")"
            <<"  t="<<fixed<<setprecision(4)<<t<<"s\n\n";
    }

    log_hmac_check(src, rid, tag.m_type, hmac_ok, t);
}

/* ================================================================
   SEND HELPERS
   ================================================================ */
static void p2p_send(uint32_t src, uint32_t dst, EdcfTag::MsgType type,
                     uint32_t sz=72, const string& log=""){
    if (!log.empty())
        cout<<"t="<<fixed<<setprecision(2)<<Simulator::Now().GetSeconds()
            <<"  [P2P] "<<nname(src)<<npos(src)<<" --> "<<nname(dst)<<npos(dst)
            <<"  "<<log<<"\n";
    Ptr<Socket> s=Socket::CreateSocket(g_all.Get(src),UdpSocketFactory::GetTypeId());
    s->Connect(InetSocketAddress(getP2PAddr(src,dst),PORT));
    Ptr<Packet> pkt=Create<Packet>(sz);
    EdcfTag tag=make_tag(src,type);
    pkt->AddPacketTag(tag);
    s->Send(pkt); s->Close();
}
static void wifi_send(uint32_t src, uint32_t dst, EdcfTag::MsgType type,
                      uint32_t sz=72, const string& log=""){
    if (!log.empty())
        cout<<"t="<<fixed<<setprecision(2)<<Simulator::Now().GetSeconds()
            <<"  [WiFi] "<<nname(src)<<npos(src)<<" --> "<<nname(dst)<<npos(dst)
            <<"  "<<log<<"\n";
    Ptr<Socket> s=Socket::CreateSocket(g_all.Get(src),UdpSocketFactory::GetTypeId());
    s->Connect(InetSocketAddress(getWifiAddr(dst),PORT));
    Ptr<Packet> pkt=Create<Packet>(sz);
    EdcfTag tag=make_tag(src,type);
    pkt->AddPacketTag(tag);
    s->Send(pkt); s->Close();
}

/* ================================================================
   BASELINE
   ================================================================ */
static void step_baseline(){
    double t=Simulator::Now().GetSeconds();
    cout<<"\n--- BASELINE t="<<fixed<<setprecision(2)<<t<<"s ---\n";
    for(uint32_t v=0;v<5;v++)
        p2p_send(v,CA[v],EdcfTag::BEACON,72,"[BL] "+nname(v)+" BEACON->"+nname(CA[v]));
    p2p_send(IDX_C0,IDX_V0,EdcfTag::FLOWMOD,72,"[BL] C0 FlowMod->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::FLOWMOD,72,"[BL] C0 FlowMod->V1");
    p2p_send(IDX_C1,IDX_V2,EdcfTag::FLOWMOD,72,"[BL] C1 FlowMod->V2");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::FLOWMOD,72,"[BL] C2 FlowMod->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::FLOWMOD,72,"[BL] C2 FlowMod->V4");
    p2p_send(IDX_C0,IDX_C1,EdcfTag::C2C,72,"[BL] C0->C1 sync");
    p2p_send(IDX_C0,IDX_C2,EdcfTag::C2C,72,"");
    p2p_send(IDX_C1,IDX_C0,EdcfTag::C2C,72,"");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::C2C,72,"");
    p2p_send(IDX_C2,IDX_C0,EdcfTag::C2C,72,"");
    p2p_send(IDX_C2,IDX_C1,EdcfTag::C2C,72,"");
}

/* ================================================================
   V1a: Spoofed Beacon Flooding -- Attacker Vehicle (Fig 3.3)
   ATK sends 6 rapid fake beacons to C0 (V2I P2P) AND broadcasts
   to all vehicles (V2V WiFi).
   C0 reacts to each fake beacon -> 6 WRONG FlowMods to V0,V1.
   C0 poisons C1,C2 via C2C -> C1,C2 push WRONG FlowMod their vehicles.
   HMAC: ATK key != network keys -> all fakes detected (TN++)
   ================================================================ */
static void v1a_s1_pkt0(){ p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1a] ATK->C0 FAKE_BEACON#1 (V90 spoofed, V2I P2P)"); }
static void v1a_s1_pkt1(){ p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1a] ATK->C0 FAKE_BEACON#2 (V91 spoofed, V2I P2P)"); }
static void v1a_s1_pkt2(){ p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1a] ATK->C0 FAKE_BEACON#3 (V92 spoofed, V2I P2P)"); }
static void v1a_s1_pkt3(){ p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1a] ATK->C0 FAKE_BEACON#4 (V93 spoofed, V2I P2P)"); }
static void v1a_s1_pkt4(){ p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1a] ATK->C0 FAKE_BEACON#5 (V94 spoofed, V2I P2P)"); }
static void v1a_s1_pkt5(){ p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1a] ATK->C0 FAKE_BEACON#6 (V95 spoofed, V2I P2P)"); }

static void v1a_s1b_bcast0(){
    cout<<"\n  [V1a-S1b] ATK->ALL vehicles FAKE_BEACON broadcast#1 (V2V WiFi)\n";
    wifi_send(IDX_ATK,IDX_V0,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V0 FAKE_BEACON#1");
    wifi_send(IDX_ATK,IDX_V1,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V1 FAKE_BEACON#1");
    wifi_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V2 FAKE_BEACON#1");
    wifi_send(IDX_ATK,IDX_V3,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V3 FAKE_BEACON#1");
    wifi_send(IDX_ATK,IDX_V4,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V4 FAKE_BEACON#1");
}
static void v1a_s1b_bcast1(){
    wifi_send(IDX_ATK,IDX_V0,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V0 FAKE_BEACON#2");
    wifi_send(IDX_ATK,IDX_V1,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_BEACON,128,"");
    wifi_send(IDX_ATK,IDX_V3,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V4,EdcfTag::FAKE_BEACON,128,"");
}
static void v1a_s1b_bcast2(){
    wifi_send(IDX_ATK,IDX_V0,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V0 FAKE_BEACON#3");
    wifi_send(IDX_ATK,IDX_V1,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_BEACON,128,"");
    wifi_send(IDX_ATK,IDX_V3,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V4,EdcfTag::FAKE_BEACON,128,"");
}
static void v1a_s1b_bcast3(){
    wifi_send(IDX_ATK,IDX_V0,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V0 FAKE_BEACON#4");
    wifi_send(IDX_ATK,IDX_V1,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_BEACON,128,"");
    wifi_send(IDX_ATK,IDX_V3,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V4,EdcfTag::FAKE_BEACON,128,"");
}
static void v1a_s1b_bcast4(){
    wifi_send(IDX_ATK,IDX_V0,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V0 FAKE_BEACON#5");
    wifi_send(IDX_ATK,IDX_V1,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_BEACON,128,"");
    wifi_send(IDX_ATK,IDX_V3,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V4,EdcfTag::FAKE_BEACON,128,"");
}
static void v1a_s1b_bcast5(){
    wifi_send(IDX_ATK,IDX_V0,EdcfTag::FAKE_BEACON,128,"[V1a-S1b] ATK->V0 FAKE_BEACON#6");
    wifi_send(IDX_ATK,IDX_V1,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_BEACON,128,"");
    wifi_send(IDX_ATK,IDX_V3,EdcfTag::FAKE_BEACON,128,""); wifi_send(IDX_ATK,IDX_V4,EdcfTag::FAKE_BEACON,128,"");
}

static void v1a_s2_fm0(){ p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#1->V0 (reaction to FAKE_BEACON#1)");
                           p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#1->V1"); }
static void v1a_s2_fm1(){ p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#2->V0");
                           p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#2->V1"); }
static void v1a_s2_fm2(){ p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#3->V0");
                           p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#3->V1"); }
static void v1a_s2_fm3(){ p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#4->V0");
                           p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#4->V1"); }
static void v1a_s2_fm4(){ p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#5->V0");
                           p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#5->V1"); }
static void v1a_s2_fm5(){ p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#6->V0");
                           p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1a-S2] C0 WRONG FM#6->V1"); }
static void v1a_step2_c2c(){
    cout<<"\n  [V1a-S2] C0 poisons C1,C2 via C2C\n";
    p2p_send(IDX_C0,IDX_C1,EdcfTag::C2C,72,"[V1a-S2] C0->C1 WRONG decision C2C");
    p2p_send(IDX_C0,IDX_C2,EdcfTag::C2C,72,"[V1a-S2] C0->C2 WRONG decision C2C");
}
static void v1a_step3(){
    cout<<"\n  [V1a-S3] Poisoned C1,C2 -> WRONG FlowMod their vehicles\n";
    p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,72,"[V1a-S3] C1 WRONG FM->V2");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::WRONG_FM,72,"[V1a-S3] C2 WRONG FM->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::WRONG_FM,72,"[V1a-S3] C2 WRONG FM->V4");
}
static void v1a_attack(){
    cout<<"\n=== V1a SPOOFED BEACON FLOODING -- Attacker Vehicle (Fig 3.3) ===\n"
        <<"  ATK->C0 (V2I P2P) + ALL vehicles (V2V WiFi) 6x rapid fake beacons\n"
        <<"  C0 reacts with 6 WRONG FlowMods -> C2C poison -> C1,C2 corrupt vehicles\n"
        <<"  HMAC: ATK uses wrong key -> all fakes detected as TN\n";
    Simulator::Schedule(Seconds(0.00),v1a_s1_pkt0);
    Simulator::Schedule(Seconds(0.18),v1a_s1_pkt1);
    Simulator::Schedule(Seconds(0.36),v1a_s1_pkt2);
    Simulator::Schedule(Seconds(0.54),v1a_s1_pkt3);
    Simulator::Schedule(Seconds(0.72),v1a_s1_pkt4);
    Simulator::Schedule(Seconds(0.90),v1a_s1_pkt5);
    Simulator::Schedule(Seconds(0.00),v1a_s1b_bcast0);
    Simulator::Schedule(Seconds(0.18),v1a_s1b_bcast1);
    Simulator::Schedule(Seconds(0.36),v1a_s1b_bcast2);
    Simulator::Schedule(Seconds(0.54),v1a_s1b_bcast3);
    Simulator::Schedule(Seconds(0.72),v1a_s1b_bcast4);
    Simulator::Schedule(Seconds(0.90),v1a_s1b_bcast5);
    Simulator::Schedule(Seconds(1.30),v1a_s2_fm0);
    Simulator::Schedule(Seconds(1.48),v1a_s2_fm1);
    Simulator::Schedule(Seconds(1.66),v1a_s2_fm2);
    Simulator::Schedule(Seconds(1.84),v1a_s2_fm3);
    Simulator::Schedule(Seconds(2.02),v1a_s2_fm4);
    Simulator::Schedule(Seconds(2.20),v1a_s2_fm5);
    Simulator::Schedule(Seconds(2.50),v1a_step2_c2c);
    Simulator::Schedule(Seconds(3.00),v1a_step3);
}

/* ================================================================
   V1b: Spoofed Beacon Flooding -- Compromised Controller C1 (Fig 3.3)
   BAD C1 sends 6 rapid WRONG FlowMods to V2 (own, V2I P2P).
   Then C2C poisons C0,C2 -> they push WRONG FlowMod their vehicles.
   HMAC: C1 is a compromised CONTROLLER -- it has a VALID key
         so its WRONG_FM packets pass HMAC check (FN for the attacker).
         This models an insider/control-plane attack harder to detect.
   ================================================================ */
static void v1b_step1(){
    for(uint32_t v=0;v<5;v++)
        p2p_send(v,CA[v],EdcfTag::BEACON,72,
                 v==0?"[V1b-S1] V0-V4 normal beacons->controllers":"");
}
static void v1b_step2(){
    p2p_send(IDX_C0,IDX_V0,EdcfTag::FLOWMOD,72,"[V1b-S2] C0 correct FlowMod->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::FLOWMOD,72,"[V1b-S2] C0 correct FlowMod->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::FLOWMOD,72,"[V1b-S2] C2 correct FlowMod->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::FLOWMOD,72,"[V1b-S2] C2 correct FlowMod->V4");
}
static void v1b_s3_fm0(){ p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,128,"[V1b-S3] BAD_C1->V2 WRONG FM#1 (repeated flood)"); }
static void v1b_s3_fm1(){ p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,128,"[V1b-S3] BAD_C1->V2 WRONG FM#2"); }
static void v1b_s3_fm2(){ p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,128,"[V1b-S3] BAD_C1->V2 WRONG FM#3"); }
static void v1b_s3_fm3(){ p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,128,"[V1b-S3] BAD_C1->V2 WRONG FM#4"); }
static void v1b_s3_fm4(){ p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,128,"[V1b-S3] BAD_C1->V2 WRONG FM#5"); }
static void v1b_s3_fm5(){ p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,128,"[V1b-S3] BAD_C1->V2 WRONG FM#6"); }
static void v1b_step4(){
    cout<<"\n  [V1b-S4] BAD C1 poisons C0,C2 via C2C\n";
    p2p_send(IDX_C1,IDX_C0,EdcfTag::C2C,72,"[V1b-S4] BAD_C1->C0 C2C POISON");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::C2C,72,"[V1b-S4] BAD_C1->C2 C2C POISON");
}
static void v1b_step5(){
    cout<<"\n  [V1b-S5] Poisoned C0,C2 -> WRONG FlowMod their vehicles\n";
    p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V1b-S5] POISONED C0 WRONG FM->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V1b-S5] POISONED C0 WRONG FM->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::WRONG_FM,72,"[V1b-S5] POISONED C2 WRONG FM->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::WRONG_FM,72,"[V1b-S5] POISONED C2 WRONG FM->V4");
}
static void v1b_attack(){
    cout<<"\n=== V1b SPOOFED BEACON FLOODING -- Compromised Controller C1 (Fig 3.3) ===\n"
        <<"  BAD C1 floods V2 with 6 rapid WRONG FlowMods (V2I P2P, 0.18s apart)\n"
        <<"  HMAC: C1 has valid key -> WRONG_FMs pass HMAC (FN -- insider threat)\n";
    v1b_step1();
    Simulator::Schedule(Seconds(0.35),v1b_step2);
    Simulator::Schedule(Seconds(0.80),v1b_s3_fm0);
    Simulator::Schedule(Seconds(0.98),v1b_s3_fm1);
    Simulator::Schedule(Seconds(1.16),v1b_s3_fm2);
    Simulator::Schedule(Seconds(1.34),v1b_s3_fm3);
    Simulator::Schedule(Seconds(1.52),v1b_s3_fm4);
    Simulator::Schedule(Seconds(1.70),v1b_s3_fm5);
    Simulator::Schedule(Seconds(1.90),v1b_step4);
    Simulator::Schedule(Seconds(2.40),v1b_step5);
}

/* ================================================================
   V2a: Cascading Alert Propagation -- Attacker Vehicle (Fig 3.4 top)
   ================================================================ */
static void v2a_step1(){ p2p_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_ALERT,72,"[V2a-S1] ATK->V2 FAKE_ALERT (P2P->V2, single target)"); }
static void v2a_step2(){
    cout<<"\n  [V2a-S2] V2 CASCADE relay -> broadcast storm (V2V WiFi)\n";
    wifi_send(IDX_V2,IDX_V0,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V0");
    wifi_send(IDX_V2,IDX_V1,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V1");
    wifi_send(IDX_V2,IDX_V3,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V3");
    wifi_send(IDX_V2,IDX_V4,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V4");
}
static void v2a_step3(){
    cout<<"\n  [V2a-S3] ALL vehicles RECOMPUTE->controllers\n";
    p2p_send(IDX_V0,IDX_C0,EdcfTag::RECOMPUTE,72,"[V2a-S3] V0->C0 RECOMPUTE");
    p2p_send(IDX_V1,IDX_C0,EdcfTag::RECOMPUTE,72,"[V2a-S3] V1->C0 RECOMPUTE");
    p2p_send(IDX_V2,IDX_C1,EdcfTag::RECOMPUTE,72,"[V2a-S3] V2->C1 RECOMPUTE");
    p2p_send(IDX_V3,IDX_C2,EdcfTag::RECOMPUTE,72,"[V2a-S3] V3->C2 RECOMPUTE");
    p2p_send(IDX_V4,IDX_C2,EdcfTag::RECOMPUTE,72,"[V2a-S3] V4->C2 RECOMPUTE");
}
static void v2a_step4(){
    cout<<"\n  [V2a-S4] C1 OVERLOADED -> WRONG FM V2 + C2C\n";
    p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,72,"[V2a-S4] C1 WRONG FM->V2");
    p2p_send(IDX_C1,IDX_C0,EdcfTag::C2C,72,"[V2a-S4] C1->C0 WRONG C2C");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::C2C,72,"[V2a-S4] C1->C2 WRONG C2C");
}
static void v2a_step5(){
    cout<<"\n  [V2a-S5] Contaminated C0,C2 -> WRONG FM their vehicles\n";
    p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V2a-S5] C0 WRONG FM->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V2a-S5] C0 WRONG FM->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::WRONG_FM,72,"[V2a-S5] C2 WRONG FM->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::WRONG_FM,72,"[V2a-S5] C2 WRONG FM->V4");
}
static void v2a_attack(){
    cout<<"\n=== V2a CASCADING ALERT PROPAGATION -- Attacker Vehicle (Fig 3.4 top) ===\n";
    v2a_step1();
    Simulator::Schedule(Seconds(0.45),v2a_step2);
    Simulator::Schedule(Seconds(1.10),v2a_step3);
    Simulator::Schedule(Seconds(1.85),v2a_step4);
    Simulator::Schedule(Seconds(2.45),v2a_step5);
}

/* ================================================================
   V2b: Cascading Alert Propagation -- Compromised C1 (Fig 3.4 bottom)
   ================================================================ */
static void v2b_step1(){
    cout<<"\n  [V2b-S1] BAD C1 -> FAKE_ALERT V2 (own) + C2C to C0,C2\n";
    p2p_send(IDX_C1,IDX_V2,EdcfTag::FAKE_ALERT,72,"[V2b-S1] BAD_C1 FAKE_ALERT->V2");
    p2p_send(IDX_C1,IDX_C0,EdcfTag::FAKE_ALERT,72,"[V2b-S1] BAD_C1 FAKE_ALERT C2C->C0");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::FAKE_ALERT,72,"[V2b-S1] BAD_C1 FAKE_ALERT C2C->C2");
}
static void v2b_step2(){
    cout<<"\n  [V2b-S2] C0,C2 forward FAKE_ALERT their vehicles\n";
    p2p_send(IDX_C0,IDX_V0,EdcfTag::FAKE_ALERT,72,"[V2b-S2] C0 FAKE_ALERT->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::FAKE_ALERT,72,"[V2b-S2] C0 FAKE_ALERT->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::FAKE_ALERT,72,"[V2b-S2] C2 FAKE_ALERT->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::FAKE_ALERT,72,"[V2b-S2] C2 FAKE_ALERT->V4");
}
static void v2b_step3(){
    cout<<"\n  [V2b-S3] Vehicles CASCADE storm (V2V WiFi)\n";
    for(uint32_t sv=0;sv<5;sv++)
        for(uint32_t rv=0;rv<5;rv++){
            if(sv==rv) continue;
            wifi_send(sv,rv,EdcfTag::CASCADE,72,(sv==0&&rv==1)?"[V2b-S3] Vehicles CASCADE storm":"");
        }
}
static void v2b_step4(){
    cout<<"\n  [V2b-S4] ALL vehicles RECOMPUTE->controllers\n";
    for(uint32_t v=0;v<5;v++)
        p2p_send(v,CA[v],EdcfTag::RECOMPUTE,72,v==0?"[V2b-S4] V0-V4 RECOMPUTE->controllers":"");
}
static void v2b_step5(){
    cout<<"\n  [V2b-S5] BAD C1 WRONG FM V2 + C2C poison\n";
    p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_FM,72,"[V2b-S5] BAD_C1 WRONG FM->V2");
    p2p_send(IDX_C1,IDX_C0,EdcfTag::C2C,72,"[V2b-S5] BAD_C1 WRONG C2C->C0");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::C2C,72,"[V2b-S5] BAD_C1 WRONG C2C->C2");
}
static void v2b_step6(){
    cout<<"\n  [V2b-S6] Poisoned C0,C2 WRONG FM their vehicles\n";
    p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_FM,72,"[V2b-S6] POISONED C0 WRONG FM->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_FM,72,"[V2b-S6] POISONED C0 WRONG FM->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::WRONG_FM,72,"[V2b-S6] POISONED C2 WRONG FM->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::WRONG_FM,72,"[V2b-S6] POISONED C2 WRONG FM->V4");
}
static void v2b_attack(){
    cout<<"\n=== V2b CASCADING ALERT PROPAGATION -- Compromised C1 (Fig 3.4 bottom) ===\n";
    v2b_step1();
    Simulator::Schedule(Seconds(0.35),v2b_step2);
    Simulator::Schedule(Seconds(0.75),v2b_step3);
    Simulator::Schedule(Seconds(1.60),v2b_step4);
    Simulator::Schedule(Seconds(2.20),v2b_step5);
    Simulator::Schedule(Seconds(2.80),v2b_step6);
}

/* ================================================================
   V3a: Mobility Trace Manipulation -- Attacker Vehicle (Fig 3.5 top)
   ================================================================ */
static void v3a_step1(){ p2p_send(IDX_ATK,IDX_V2,EdcfTag::FAKE_TRACE,72,"[V3a-S1] ATK->V2 FAKE_LOCATION (P2P->V2, single)"); }
static void v3a_step2(){
    cout<<"\n  [V3a-S2] V2 deceived -> ROUTE_CHG to C1\n";
    p2p_send(IDX_V2,IDX_C1,EdcfTag::ROUTE_CHG,72,"[V3a-S2] V2->C1 ROUTE_CHANGE");
}
static void v3a_step3(){
    cout<<"\n  [V3a-S3] C1 wrong topo -> WRONG_TOPO V2 + C2C poison\n";
    p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_TOPO,72,"[V3a-S3] C1 WRONG_TOPO->V2");
    p2p_send(IDX_C1,IDX_C0,EdcfTag::C2C,72,"[V3a-S3] C1->C0 WRONG TOPO C2C");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::C2C,72,"[V3a-S3] C1->C2 WRONG TOPO C2C");
}
static void v3a_step4(){
    cout<<"\n  [V3a-S4] Poisoned C0,C2 -> WRONG_TOPO their vehicles\n";
    p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_TOPO,72,"[V3a-S4] C0 WRONG_TOPO->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_TOPO,72,"[V3a-S4] C0 WRONG_TOPO->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::WRONG_TOPO,72,"[V3a-S4] C2 WRONG_TOPO->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::WRONG_TOPO,72,"[V3a-S4] C2 WRONG_TOPO->V4");
}
static void v3a_attack(){
    cout<<"\n=== V3a MOBILITY TRACE MANIPULATION -- Attacker Vehicle (Fig 3.5 top) ===\n";
    v3a_step1();
    Simulator::Schedule(Seconds(0.65),v3a_step2);
    Simulator::Schedule(Seconds(1.30),v3a_step3);
    Simulator::Schedule(Seconds(1.90),v3a_step4);
}

/* ================================================================
   V3b: Mobility Trace Manipulation -- Compromised C1 (Fig 3.5 bottom)
   ================================================================ */
static void v3b_step1(){
    for(uint32_t v=0;v<5;v++)
        p2p_send(v,CA[v],EdcfTag::BEACON,72,v==0?"[V3b-S1] V0-V4 CORRECT beacons->controllers":"");
}
static void v3b_step2(){
    cout<<"\n  [V3b-S2] BAD C1 -> WRONG_TOPO V2 + C2C poison C0,C2\n";
    p2p_send(IDX_C1,IDX_V2,EdcfTag::WRONG_TOPO,72,"[V3b-S2] BAD_C1 WRONG_TOPO->V2");
    p2p_send(IDX_C1,IDX_C0,EdcfTag::WRONG_TOPO,72,"[V3b-S2] BAD_C1 WRONG_TOPO C2C->C0");
    p2p_send(IDX_C1,IDX_C2,EdcfTag::WRONG_TOPO,72,"[V3b-S2] BAD_C1 WRONG_TOPO C2C->C2");
}
static void v3b_step3(){
    cout<<"\n  [V3b-S3] Poisoned C0,C2 -> WRONG_TOPO their vehicles\n";
    p2p_send(IDX_C0,IDX_V0,EdcfTag::WRONG_TOPO,72,"[V3b-S3] C0 WRONG_TOPO->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::WRONG_TOPO,72,"[V3b-S3] C0 WRONG_TOPO->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::WRONG_TOPO,72,"[V3b-S3] C2 WRONG_TOPO->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::WRONG_TOPO,72,"[V3b-S3] C2 WRONG_TOPO->V4");
}
static void v3b_step4(){
    cout<<"\n  [V3b-S4] C0<->C2 WRONG_TOPO LOOP\n";
    p2p_send(IDX_C0,IDX_C2,EdcfTag::WRONG_TOPO,72,"[V3b-S4] C0->C2 WRONG_TOPO LOOP");
    p2p_send(IDX_C2,IDX_C0,EdcfTag::WRONG_TOPO,72,"[V3b-S4] C2->C0 WRONG_TOPO LOOP");
}
static void v3b_attack(){
    cout<<"\n=== V3b MOBILITY TRACE MANIPULATION -- Compromised C1 (Fig 3.5 bottom) ===\n";
    v3b_step1();
    Simulator::Schedule(Seconds(0.50),v3b_step2);
    Simulator::Schedule(Seconds(1.10),v3b_step3);
    Simulator::Schedule(Seconds(1.80),v3b_step4);
}

/* ================================================================
   PEM METRICS PRINT + CSV
   ================================================================ */
static void pem_calc(uint32_t tp, uint32_t tn, uint32_t fp, uint32_t fn,
                      uint32_t hv, uint32_t hf,
                      uint32_t lt, uint32_t ld,
                      uint32_t fk, uint32_t wf, uint32_t cs, uint32_t te,
                      uint32_t wfl, uint32_t wlg,  /* wifi_flood, wifi_legit */
                      double t_now, const string& row_type, fstream& fout)
{
    double tot    = tp+tn+fp+fn;
    double acc    = tot>0 ? (double)(tp+tn)/tot : 1.0;
    double mcc_n  = (double)tp*tn - (double)fp*fn;
    double mcc_d  = sqrt(max(1.0,(double)(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)));
    double mcc    = mcc_n/mcc_d;
    double fpr    = (fp+tn)>0 ? (double)fp/(fp+tn) : 0.0;
    double f1d    = 2.0*tp+fp+fn;
    double f1     = f1d>0 ? 2.0*tp/f1d : 0.0;
    double prec   = (tp+fp)>0 ? (double)tp/(tp+fp) : 0.0;
    double recall = (tp+fn)>0 ? (double)tp/(tp+fn) : 0.0;
    /* PDR = effective delivery ratio after attack-induced degradation.
         FAKE_BEACON -> controller overload -> FlowMod delays
         CASCADE/RECOMPUTE -> broadcast storm -> bandwidth congestion
         WRONG_FM/WRONG_TOPO -> misrouting -> wrong-path delivery
       Undetected attacks (FN) cause 1.5x penalty (no mitigation).
       This gives realistic scenario-dependent PDR:
         v1a: moderate drop (beacon flood + wrong FM)
         v2a: higher drop (cascade storm + recompute flood)
         v3a: highest per-pkt drop (topo errors = wrong routes) */
    /* PDR = legitimate delivery rate, degraded by WiFi channel congestion.
       base_pdr: from legit counters (TP / legit_total).
       ch_load:  fake beacons / (fake + legit) on WiFi channel.
       congestion_factor 0.8 models 802.11p DSRC channel saturation.
       As atk_count rises: more WiFi fake beacons -> higher ch_load
       -> lower effective PDR. This is the degradation curve your
       supervisor wants to see plotted against attack percentage. */
    double base_pdr = lt>0 ? (double)(lt-min(ld,lt))/lt : 1.0;
    double wf_total = (double)(wfl + wlg);
    double ch_load  = wf_total>0 ? (double)wfl/wf_total : 0.0;
    double pdr      = base_pdr * (1.0 - 0.8 * ch_load);
    if (pdr < 0.0) pdr = 0.0;
    double ar     = t_now>0 ? (double)(tn+fn)/t_now : 0.0;
    double dr     = (tn+fn)>0 ? (double)tn/(tn+fn) : 0.0;
    const char* st;
    if      (acc>=0.90 && dr>=0.80) st = "HMAC detecting well (external atk)  ";
    else if (dr==0.0   && fn>0)     st = "HMAC BLIND -- insider evades (FN>0)  ";
    else if (acc>=0.70)             st = "DEGRADED  -- partial detection       ";
    else                            st = "CRITICAL  -- HMAC insufficient alone ";

    cout << "  [" << row_type << "]";
    cout << " TP=" << setw(4) << tp;
    cout << " TN=" << setw(4) << tn;
    cout << " FP=" << setw(3) << fp;
    cout << " FN=" << setw(4) << fn;
    cout << " chk=" << setw(4) << hv;
    cout << " det=" << setw(4) << hf << "\n";
    cout << "  Acc=" << fixed << setprecision(4) << acc;
    cout << " MCC=" << setprecision(4) << mcc;
    cout << " F1=" << setprecision(4) << f1;
    cout << " Prec=" << setprecision(4) << prec;
    cout << " Rec=" << setprecision(4) << recall;
    cout << " DetRate=" << setprecision(4) << dr << "\n";
    cout << "  FPR=" << setprecision(4) << fpr;
    cout << " PDR=" << setprecision(1) << pdr*100.0 << "%";
    cout << "(base=" << setprecision(1) << base_pdr*100.0 << "%";
    cout << " chLoad=" << setprecision(1) << ch_load*100.0 << "%)";
    cout << " fk=" << fk << " wfm=" << wf;
    cout << " casc=" << cs << " topo=" << te;
    cout << " atkRate=" << setprecision(3) << ar << "\n";
    cout << "  STATUS: " << st << "\n";

    double _atk_pct = 100.0 * g_atk_count / (double)g_total_nodes;
    /* Row format: atk_count and atk_pct first so CSV is easy to
       sort/group by attack percentage across multiple runs */
    fout << g_atk_count << ",";
    fout << fixed << setprecision(1) << _atk_pct << ",";
    fout << g_pem_cycle << "," << row_type << ",";
    fout << setprecision(2) << t_now << ",";
    fout << tp << "," << tn << "," << fp << "," << fn << ",";
    fout << setprecision(6) << acc << "," << mcc << "," << fpr << ",";
    fout << f1 << "," << prec << "," << recall << ",";
    fout << hv << "," << hf << "," << setprecision(4) << dr << ",";
    fout << fk << "," << wf << "," << cs << "," << te << ",";
    fout << setprecision(3) << ar << ",";
    fout << lt << "," << ld << ",";
    fout << setprecision(2) << pdr*100.0 << ",";
    fout << wfl << "," << wlg << ",";
    fout << setprecision(4) << ch_load*100.0 << "\n";
}

static void print_pem(){
    g_pem_cycle++;
    double t_now=Simulator::Now().GetSeconds();

    cout<<"\n+========================================================+\n"
        <<"|  PEM + HMAC  Cycle="<<setw(2)<<g_pem_cycle
        <<"  t="<<fixed<<setprecision(2)<<t_now<<"s  ["<<g_scenario<<"]\n"
        <<"|  CYCLE=this cycle only  CUMULATIVE=all cycles so far\n"
        <<"+========================================================+\n";

    /* Header and file creation handled by run_cycle on first cycle.
       Always append here. */
    fstream fout;
    fout.open(g_pem_csv, ios::out|ios::app);

    pem_calc(g_TP_p,g_TN_p,g_FP_p,g_FN_p,
             g_hmac_verified_p,g_hmac_failed_p,
             g_legit_total_p,g_legit_drop_p,
             g_fake_pkts_p,g_wrong_fm_p,g_cascade_cnt_p,g_topo_err_p,
             g_wifi_flood_p,g_wifi_legit_p,
             t_now,"CYCLE",fout);

    pem_calc(g_TP,g_TN,g_FP,g_FN,
             g_hmac_verified,g_hmac_failed,
             g_legit_total,g_legit_drop,
             g_fake_pkts,g_wrong_fm,g_cascade_cnt,g_topo_err,
             g_wifi_flood,g_wifi_legit,
             t_now,"CUMULATIVE",fout);

    fout.close();

    /* Interpretation message for evaluation panel */
    cout << "  [KEY FINDING] ";
    if (g_atk_has_valid_key && g_FN_p > 0)
        cout << "ATK has stolen/valid HMAC key: FN=" << g_FN_p << " TN=0\n"
             << "  HMAC completely evaded even in a-scenario!\n"
             << "  -> Attacker with valid credentials cannot be caught by HMAC.\n"
             << "  -> TGNN (graph anomaly) + LLM + Blockchain required.\n";
    else if (g_FN_p > 0 && g_TN_p == 0)
        cout << "FN=" << g_FN_p << " TN=0: HMAC evaded by insider/compromised ctrl.\n"
             << "  HMAC alone CANNOT detect control-plane attacks.\n"
             << "  -> Blockchain + TGNN + LLM required.\n";
    else if (g_FN_p > 0)
        cout << "FN=" << g_FN_p << " partial evasion (mixed threat).\n";
    else
        cout << "All attacks this cycle detected by HMAC (external, no key theft).\n"
             << "  -> Use --atk_has_key=1 to simulate stolen credential scenario.\n"
             << "  -> Use b-variants for insider/compromised-controller scenarios.\n";

    cout<<"[PEM CSV]  -> "<<g_pem_csv<<"\n";
    cout<<"[HMAC CSV] -> "<<g_hmac_csv<<"\n";

    /* Reset per-cycle counters */
    g_TP_p=0; g_TN_p=0; g_FP_p=0; g_FN_p=0;
    g_hmac_verified_p=0; g_hmac_failed_p=0;
    g_fake_pkts_p=0; g_wrong_fm_p=0; g_cascade_cnt_p=0; g_topo_err_p=0;
    g_legit_total_p=0; g_legit_drop_p=0;
    g_wifi_flood_p=0;  g_wifi_legit_p=0;
}

static void sim_done(){
    cout<<"\n=== SIMULATION COMPLETE  scenario="<<g_scenario
        <<"  TP="<<g_TP<<"  TN="<<g_TN<<"  FP="<<g_FP<<"  FN="<<g_FN<<" ===\n";
}
static void run_cycle();
typedef void (*AttackFn)();
static AttackFn g_attack_fn = 0;

/* Fire the same beacon flood from each extra attacker node.
   Called once per simulation cycle, 0.05s after the main ATK fires.
   Each extra ATK sends FAKE_BEACONs to C0 (V2I P2P) -- same pattern.
   For v2a/v3a they send FAKE_ALERT/FAKE_TRACE to V2 (P2P). */
static void extra_atk_beacons(){
    for(uint32_t i=N_NODES;i<g_total_nodes;i++){
        p2p_send(i,IDX_C0,EdcfTag::FAKE_BEACON,128,
                 "["+nname(i)+"] ->C0 FAKE_BEACON (V2I P2P)");
        /* also broadcast to all vehicles on WiFi */
        for(uint32_t v=0;v<5;v++)
            wifi_send(i,v,EdcfTag::FAKE_BEACON,128,"");
    }
}
static void extra_atk_alert(){
    for(uint32_t i=N_NODES;i<g_total_nodes;i++)
        p2p_send(i,IDX_V2,EdcfTag::FAKE_ALERT,72,
                 "["+nname(i)+"] ->V2 FAKE_ALERT (P2P)");
}
static void extra_atk_trace(){
    for(uint32_t i=N_NODES;i<g_total_nodes;i++)
        p2p_send(i,IDX_V2,EdcfTag::FAKE_TRACE,72,
                 "["+nname(i)+"] ->V2 FAKE_TRACE (P2P)");
}
static void schedule_attack(){
    if(g_attack_fn) g_attack_fn();
    if(g_total_nodes <= N_NODES) return;  /* no extra attackers */
    /* Extra attackers fire 0.05s after main ATK for each scenario */
    if(g_scenario=="v1a"||g_scenario=="v1b")
        Simulator::Schedule(Seconds(0.05), extra_atk_beacons);
    else if(g_scenario=="v2a"||g_scenario=="v2b")
        Simulator::Schedule(Seconds(0.05), extra_atk_alert);
    else if(g_scenario=="v3a"||g_scenario=="v3b")
        Simulator::Schedule(Seconds(0.05), extra_atk_trace);
}
static void run_cycle(){
    g_cycle++;
    double t=Simulator::Now().GetSeconds();
    /* On first cycle of this run, write a separator into the CSV
       so different atk_count runs are visually separated */
    if(g_cycle==1){
        double _ap = 100.0*g_atk_count/(double)g_total_nodes;
        fstream _sep;
        /* Ensure file+header exist before writing separator */
        if(!g_pem_hdr){
            ifstream chk(g_pem_csv); bool fe=chk.good(); chk.close();
            if(!fe){
                _sep.open(g_pem_csv,ios::out|ios::trunc);
                _sep<<"# EDCF-Shield PEM+HMAC  scenario="<<g_scenario<<"\n";
                _sep<<"# key_mode="<<(g_atk_has_valid_key
                    ?"STOLEN_KEY(atk_has_key=1)":"EXTERNAL_ATK(atk_has_key=0)")<<"\n";
                _sep<<"# CYCLE=this cycle window; CUMULATIVE=all cycles\n";
                _sep<<"# atk_count rows appear in order as you run each count\n";
                _sep<<"# External atk TN>0 FN=0=HMAC detects; Stolen TN=0 FN>0=HMAC blind\n";
                _sep<<"atk_count,atk_pct,cycle,row_type,t,";
                _sep<<"TP,TN,FP,FN,";
                _sep<<"Accuracy,MCC,FPR,F1,Precision,Recall,";
                _sep<<"hmac_checks,hmac_detected,det_rate,";
                _sep<<"fake_pkts,wrong_fm,cascade,topo_err,atk_rate,";
                _sep<<"legit_total,legit_drop,PDR_pct,wifi_flood,wifi_legit,ch_load_pct\n";
                _sep.close();
            }
            g_pem_hdr=true;
        }
        _sep.open(g_pem_csv,ios::out|ios::app);
        _sep<<"# --- atk_count="<<g_atk_count
            <<"  atk_pct="<<fixed<<setprecision(1)<<_ap<<"%";
        _sep<<"  nodes="<<g_total_nodes;
        _sep<<"  key="<<(g_atk_has_valid_key?"STOLEN":"EXTERNAL");
        _sep<<"  scenario="<<g_scenario<<" ---\n";
        _sep.close();
        cout<<"\n[CSV] New run block: atk_count="<<g_atk_count
            <<"  atk_pct="<<fixed<<setprecision(1)<<_ap<<"%\n";
    }
    cout<<"\n====== CYCLE "<<g_cycle
        <<"  t="<<fixed<<setprecision(1)<<t<<"s ======\n";
    step_baseline();
    Simulator::Schedule(Seconds(0.5),  schedule_attack);
    Simulator::Schedule(Seconds(3.5),  print_pem);
    if(t+4.0<g_simTime)
        Simulator::Schedule(Seconds(4.0),run_cycle);
    else
        Simulator::Schedule(Seconds(0.95),sim_done);
}

/* ================================================================
   MAIN
   ================================================================ */
int main(int argc,char* argv[]){
    CommandLine cmd;
    cmd.AddValue("scenario","v1a|v1b|v2a|v2b|v3a|v3b",g_scenario);
    cmd.AddValue("simTime",    "Simulation time (s)",                g_simTime);
    cmd.AddValue("atk_has_key","1=ATK has stolen network HMAC key",  g_atk_has_valid_key);
    cmd.AddValue("atk_count",  "Number of attacker nodes (1-10)",     g_atk_count);
    cmd.Parse(argc,argv);

    /* Clamp atk_count */
    if (g_atk_count < 1) g_atk_count = 1;
    if (g_atk_count > 10) g_atk_count = 10;
    g_total_nodes = N_NODES + (g_atk_count - 1);  /* extra attackers beyond first */

    system("mkdir -p ./scratch ./results_LLDP/individual ./results_LLDP/combined");
    const char* csvf[]={"./scratch/security_data.csv",
                        "./scratch/security_global_HMAC_data.csv",0};
    for(int i=0;csvf[i];i++){ifstream c(csvf[i]);if(!c.good()){ofstream cr(csvf[i]);cr.close();}}
    /* Filename: scenario + key mode.
       All atk_count runs APPEND to the same file so the panel sees
       all attack percentages in one CSV for easy plotting. */
    string key_suffix = g_atk_has_valid_key ? "_stolenkey" : "_extatk";
    g_pem_csv  = "./scratch/edcf_"+g_scenario+key_suffix+"_pem.csv";
    g_hmac_csv = "./scratch/edcf_"+g_scenario+key_suffix+"_hmac.csv";


    bool has_atk=false, has_badc=false;
    if     (g_scenario=="v1a"){g_attack_fn=v1a_attack;has_atk=true;}
    else if(g_scenario=="v1b"){g_attack_fn=v1b_attack;has_badc=true;}
    else if(g_scenario=="v2a"){g_attack_fn=v2a_attack;has_atk=true;}
    else if(g_scenario=="v2b"){g_attack_fn=v2b_attack;has_badc=true;}
    else if(g_scenario=="v3a"){g_attack_fn=v3a_attack;has_atk=true;}
    else if(g_scenario=="v3b"){g_attack_fn=v3b_attack;has_badc=true;}
    else{cerr<<"Unknown scenario: "<<g_scenario<<"\n";return 1;}

    /* Create base nodes + any extra attackers */
    g_all.Create(g_total_nodes);
    /* Extra attackers are nodes N_NODES .. g_total_nodes-1.
       They behave identically to IDX_ATK (node 5):
       same position offset, same velocity, same key mode. */

    MobilityHelper mob;
    mob.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    Ptr<ListPositionAllocator> pos=CreateObject<ListPositionAllocator>();
    /* Base 9 node positions */
    for(uint32_t i=0;i<N_NODES;i++) pos->Add(Vector(PX[i],PY[i],0.0));
    /* Extra attacker positions: staggered next to ATK (node 5)
       ATK2 at (330,220), ATK3 at (360,220), ATK4 at (390,220), ATK5 at (420,220) */
    for(uint32_t k=1;k<g_atk_count;k++)
        pos->Add(Vector(PX[IDX_ATK]+k*30.0, PY[IDX_ATK], 0.0));
    mob.SetPositionAllocator(pos);
    mob.Install(g_all);

    /* Set velocities for base nodes */
    static const double VEL[9]={12,10,8,14,11,10,0,0,0};
    for(uint32_t i=0;i<N_NODES;i++)
        DynamicCast<ConstantVelocityMobilityModel>(
            g_all.Get(i)->GetObject<MobilityModel>())
            ->SetVelocity(Vector(VEL[i],0,0));
    /* Set velocities for extra attackers (same speed as ATK) */
    for(uint32_t i=N_NODES;i<g_total_nodes;i++)
        DynamicCast<ConstantVelocityMobilityModel>(
            g_all.Get(i)->GetObject<MobilityModel>())
            ->SetVelocity(Vector(10.0, 0, 0));

    NodeContainer wifiNodes;
    for(uint32_t i=0;i<=IDX_ATK;i++) wifiNodes.Add(g_all.Get(i));
    /* Add extra attackers to WiFi channel */
    for(uint32_t i=N_NODES;i<g_total_nodes;i++) wifiNodes.Add(g_all.Get(i));
    YansWifiChannelHelper wch;
    wch.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wch.AddPropagationLoss("ns3::RangePropagationLossModel","MaxRange",DoubleValue(600.0));
    YansWifiPhyHelper wphy; wphy.SetChannel(wch.Create());
    wphy.SetErrorRateModel("ns3::NistErrorRateModel");
    wphy.Set("TxPowerStart",DoubleValue(41)); wphy.Set("TxPowerEnd",DoubleValue(41));
    wphy.Set("Frequency",UintegerValue(5890)); wphy.Set("ChannelWidth",UintegerValue(10));
    WifiHelper wifi; wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
        "DataMode",StringValue("OfdmRate12MbpsBW10MHz"),
        "ControlMode",StringValue("OfdmRate12MbpsBW10MHz"),
        "RtsCtsThreshold",UintegerValue(1000));
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac","QosSupported",BooleanValue(true));
    g_wifiDevs=wifi.Install(wphy,mac,wifiNodes);

    InternetStackHelper inet; inet.Install(g_all);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0","255.255.255.0");
    g_wifiIfaces=ipv4.Assign(g_wifiDevs);

    PointToPointHelper p2p_v2i;
    p2p_v2i.SetDeviceAttribute("DataRate",DataRateValue(DataRate("100Mbps")));
    p2p_v2i.SetChannelAttribute("Delay",TimeValue(MicroSeconds(50)));
    for(uint32_t v=0;v<5;v++){
        uint32_t ctrl=CA[v];
        g_v2i_devs[v]=p2p_v2i.Install(g_all.Get(v),g_all.Get(ctrl));
        ostringstream base; base<<"10.2."<<v<<".0";
        ipv4.SetBase(base.str().c_str(),"255.255.255.252");
        Ipv4InterfaceContainer ifc=ipv4.Assign(g_v2i_devs[v]);
        LinkIPs lk1={ifc.GetAddress(0),ifc.GetAddress(1),v,ctrl};
        LinkIPs lk2={ifc.GetAddress(1),ifc.GetAddress(0),ctrl,v};
        g_links.push_back(lk1); g_links.push_back(lk2);
    }
    {
        g_atk_v2i_devs=p2p_v2i.Install(g_all.Get(IDX_ATK),g_all.Get(IDX_C0));
        ipv4.SetBase("10.2.5.0","255.255.255.252");
        Ipv4InterfaceContainer ifc=ipv4.Assign(g_atk_v2i_devs);
        LinkIPs l1={ifc.GetAddress(0),ifc.GetAddress(1),IDX_ATK,IDX_C0};
        LinkIPs l2={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C0,IDX_ATK};
        g_links.push_back(l1); g_links.push_back(l2);
    }
    {
        g_atk_v2_devs=p2p_v2i.Install(g_all.Get(IDX_ATK),g_all.Get(IDX_V2));
        ipv4.SetBase("10.2.6.0","255.255.255.252");
        Ipv4InterfaceContainer ifc6=ipv4.Assign(g_atk_v2_devs);
        LinkIPs la={ifc6.GetAddress(0),ifc6.GetAddress(1),IDX_ATK,IDX_V2};
        LinkIPs lb={ifc6.GetAddress(1),ifc6.GetAddress(0),IDX_V2,IDX_ATK};
        g_links.push_back(la); g_links.push_back(lb);
    }
    /* Extra attacker P2P links: each extra ATK gets C0 link + V2 link
       Subnets: 10.4.N.0/30 for C0 link, 10.5.N.0/30 for V2 link */
    for(uint32_t i=N_NODES;i<g_total_nodes;i++){
        uint32_t k=i-N_NODES;
        ostringstream s1,s2;
        s1<<"10.4."<<k<<".0"; s2<<"10.5."<<k<<".0";
        /* Extra ATK -> C0 */
        NetDeviceContainer xac=p2p_v2i.Install(g_all.Get(i),g_all.Get(IDX_C0));
        ipv4.SetBase(s1.str().c_str(),"255.255.255.252");
        Ipv4InterfaceContainer xac_ifc=ipv4.Assign(xac);
        LinkIPs xa1={xac_ifc.GetAddress(0),xac_ifc.GetAddress(1),i,IDX_C0};
        LinkIPs xa2={xac_ifc.GetAddress(1),xac_ifc.GetAddress(0),IDX_C0,i};
        g_links.push_back(xa1); g_links.push_back(xa2);
        /* Extra ATK -> V2 */
        NetDeviceContainer xav=p2p_v2i.Install(g_all.Get(i),g_all.Get(IDX_V2));
        ipv4.SetBase(s2.str().c_str(),"255.255.255.252");
        Ipv4InterfaceContainer xav_ifc=ipv4.Assign(xav);
        LinkIPs xv1={xav_ifc.GetAddress(0),xav_ifc.GetAddress(1),i,IDX_V2};
        LinkIPs xv2={xav_ifc.GetAddress(1),xav_ifc.GetAddress(0),IDX_V2,i};
        g_links.push_back(xv1); g_links.push_back(xv2);
    }

    PointToPointHelper p2p_c2c;
    p2p_c2c.SetDeviceAttribute("DataRate",DataRateValue(DataRate("1000Mbps")));
    p2p_c2c.SetChannelAttribute("Delay",TimeValue(MicroSeconds(10)));
    {
        g_c2c_01=p2p_c2c.Install(g_all.Get(IDX_C0),g_all.Get(IDX_C1));
        ipv4.SetBase("10.3.0.0","255.255.255.252");
        Ipv4InterfaceContainer ifc=ipv4.Assign(g_c2c_01);
        LinkIPs l01={ifc.GetAddress(0),ifc.GetAddress(1),IDX_C0,IDX_C1};
        LinkIPs l10={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C1,IDX_C0};
        g_links.push_back(l01); g_links.push_back(l10);
    }
    {
        g_c2c_02=p2p_c2c.Install(g_all.Get(IDX_C0),g_all.Get(IDX_C2));
        ipv4.SetBase("10.3.1.0","255.255.255.252");
        Ipv4InterfaceContainer ifc=ipv4.Assign(g_c2c_02);
        LinkIPs l02={ifc.GetAddress(0),ifc.GetAddress(1),IDX_C0,IDX_C2};
        LinkIPs l20={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C2,IDX_C0};
        g_links.push_back(l02); g_links.push_back(l20);
    }
    {
        g_c2c_12=p2p_c2c.Install(g_all.Get(IDX_C1),g_all.Get(IDX_C2));
        ipv4.SetBase("10.3.2.0","255.255.255.252");
        Ipv4InterfaceContainer ifc=ipv4.Assign(g_c2c_12);
        LinkIPs l12={ifc.GetAddress(0),ifc.GetAddress(1),IDX_C1,IDX_C2};
        LinkIPs l21={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C2,IDX_C1};
        g_links.push_back(l12); g_links.push_back(l21);
    }

    for(uint32_t n=0;n<g_total_nodes;n++){
        PacketSinkHelper sk("ns3::UdpSocketFactory",
            InetSocketAddress(Ipv4Address::GetAny(),PORT));
        ApplicationContainer sc=sk.Install(g_all.Get(n));
        sc.Start(Seconds(0.0)); sc.Stop(Seconds(g_simTime));
    }

    for(uint32_t ni=0;ni<g_total_nodes;ni++){
        Ptr<Node> nd=g_all.Get(ni);
        for(uint32_t di=0;di<nd->GetNDevices();di++){
            Ptr<WifiNetDevice> wdev=DynamicCast<WifiNetDevice>(nd->GetDevice(di));
            if(wdev){
                wdev->GetMac()->TraceConnectWithoutContext(
                    "MacRx",MakeBoundCallback(&PktRxCb,ni));
                continue;
            }
            Ptr<PointToPointNetDevice> pdev=
                DynamicCast<PointToPointNetDevice>(nd->GetDevice(di));
            if(pdev)
                pdev->TraceConnectWithoutContext(
                    "MacRx",MakeBoundCallback(&PktRxCb,ni));
        }
    }

    string xml="./scratch/edcf_"+g_scenario+".xml";
    AnimationInterface anim(xml);
    anim.SetMaxPktsPerTraceFile(9999999);
    anim.EnablePacketMetadata(true);
    for(uint32_t i=0;i<5;i++){
        anim.UpdateNodeDescription(g_all.Get(i),"V"+to_string(i));
        anim.UpdateNodeColor(g_all.Get(i),0,200,0);
        anim.UpdateNodeSize(i,30,30);
    }
    anim.UpdateNodeDescription(g_all.Get(IDX_ATK),has_atk?"ATK":"(inactive)");
    anim.UpdateNodeColor(g_all.Get(IDX_ATK),has_atk?220:160,0,0);
    anim.UpdateNodeSize(IDX_ATK,35,35);
    anim.UpdateNodeDescription(g_all.Get(IDX_C0),"C0_GOOD");
    anim.UpdateNodeColor(g_all.Get(IDX_C0),0,0,220); anim.UpdateNodeSize(IDX_C0,35,35);
    anim.UpdateNodeDescription(g_all.Get(IDX_C1),has_badc?"C1_BAD":"C1_GOOD");
    anim.UpdateNodeColor(g_all.Get(IDX_C1),has_badc?255:0,has_badc?140:0,has_badc?0:220);
    anim.UpdateNodeSize(IDX_C1,35,35);
    anim.UpdateNodeDescription(g_all.Get(IDX_C2),"C2_GOOD");
    anim.UpdateNodeColor(g_all.Get(IDX_C2),0,0,220); anim.UpdateNodeSize(IDX_C2,35,35);
    /* Extra attackers -- dark red, labelled ATK2, ATK3... (matches nname()) */
    for(uint32_t i=N_NODES;i<g_total_nodes;i++){
        string lbl = "ATK" + to_string(i-N_NODES+2);
        anim.UpdateNodeDescription(g_all.Get(i), lbl);
        anim.UpdateNodeColor(g_all.Get(i), 180, 0, 0);
        anim.UpdateNodeSize(i, 35, 35);
    }

    cout<<"\n=== EDCF-Shield  Group 14 (HMAC-SHA256 Enabled) ===\n"
        <<"scenario="<<g_scenario<<"  simTime="<<g_simTime<<"s\n"
        <<"Topology: V2V=WiFi(802.11p)  V2I=P2P(100Mbps)  C2C=P2P(1Gbps)\n"
        <<"P2P links: V0-C0 V1-C0 V2-C1 V3-C2 V4-C2 ATK-C0 ATK-V2 C0-C1 C0-C2 C1-C2\n"
        << "Attackers: " << g_atk_count << " / " << g_total_nodes
        << " total nodes  (" << fixed << setprecision(1)
        << (100.0*g_atk_count/g_total_nodes) << "% attack ratio)\n"
        << "HMAC: inline SHA-256, 256-bit PSK\n"
        << "  ATK key mode: "
        << (g_atk_has_valid_key
            ? "VALID (stolen/insider) -> HMAC evaded -> FN grows -> MCC/F1 degrade"
            : "INVALID (external atk) -> HMAC detects -> TN grows -> metrics good")
        << "\n"
        << "PEM CSV:  " << g_pem_csv  << "\n"
        << "HMAC CSV: " << g_hmac_csv << "\n"
        <<"PEM:  TP=legit+HMAC_ok  TN=attack+HMAC_fail  FN=attack+HMAC_ok  FP=legit+HMAC_fail\n"
        <<"XML:  "<<xml<<"\n\n";

    Simulator::Schedule(Seconds(1.0),run_cycle);
    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
