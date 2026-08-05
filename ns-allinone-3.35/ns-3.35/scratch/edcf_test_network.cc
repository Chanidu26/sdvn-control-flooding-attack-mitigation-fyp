/**
 * EDCF-Shield Test Network -- Group 14
 *
 * TOPOLOGY:
 *   V2V : 802.11p WiFi (V0-V4 + ATK on shared DSRC channel)
 *   V2I : PointToPoint per vehicle-controller association
 *         V0->C0, V1->C0, V2->C1, V3->C2, V4->C2, ATK->C0
 *   C2C : PointToPoint full mesh (C0-C1, C0-C2, C1-C2)
 *
 * IMPORTANT: Each controller only has P2P links to its OWN vehicles.
 *   C0 owns V0,V1   C1 owns V2   C2 owns V3,V4
 *   When an attack controller sends to a vehicle it does NOT own,
 *   it must relay via C2C to the vehicle's real controller.
 *   Helper ctrl_of(v) returns the owning controller index.
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

/* Vehicle -> owning controller */
static const uint32_t CA[5] = {IDX_C0, IDX_C0, IDX_C1, IDX_C2, IDX_C2};

/* Controller -> list of owned vehicles */
/* C0: {0,1}  C1: {2}  C2: {3,4} */

static string   g_scenario = "v1a";
static double   g_simTime  = 12.0;
static uint32_t g_cycle    = 0;

/* ================================================================
   PACKET TAG
   ================================================================ */
class EdcfTag : public Tag {
public:
    enum MsgType {
        BEACON=0, FLOWMOD=1, C2C=2, FAKE_BEACON=3, FAKE_ALERT=4,
        CASCADE=5, RECOMPUTE=6, FAKE_TRACE=7, ROUTE_CHG=8,
        WRONG_FM=9, WRONG_TOPO=10
    };
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::EdcfTagG14v2")
            .SetParent<Tag>().AddConstructor<EdcfTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override {
        return 2*sizeof(uint32_t) + 9*sizeof(double);
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
    }
    void Deserialize(TagBuffer buf) override {
        m_type = (MsgType)buf.ReadU32(); m_from = buf.ReadU32();
        buf.Read((uint8_t*)&m_fake_x,     sizeof(double));
        buf.Read((uint8_t*)&m_fake_y,     sizeof(double));
        buf.Read((uint8_t*)&m_real_x,     sizeof(double));
        buf.Read((uint8_t*)&m_real_y,     sizeof(double));
        buf.Read((uint8_t*)&m_fake_vx,    sizeof(double));
        buf.Read((uint8_t*)&m_fake_vy,    sizeof(double));
        buf.Read((uint8_t*)&m_real_vx,    sizeof(double));
        buf.Read((uint8_t*)&m_real_vy,    sizeof(double));
        buf.Read((uint8_t*)&m_vehicle_id, sizeof(double));
    }
    void Print(std::ostream& os) const override {
        os << "EdcfTag type=" << m_type << " from=" << m_from;
    }
    MsgType  m_type = BEACON;
    uint32_t m_from = 0;
    double m_fake_x=0, m_fake_y=0, m_real_x=0, m_real_y=0;
    double m_fake_vx=0, m_fake_vy=0, m_real_vx=0, m_real_vy=0;
    double m_vehicle_id=0;
};
NS_OBJECT_ENSURE_REGISTERED(EdcfTag);

/* ================================================================
   GLOBAL STATE
   ================================================================ */
static NodeContainer            g_all;
static NetDeviceContainer       g_wifiDevs;
static NetDeviceContainer       g_v2i_devs[5];
static NetDeviceContainer       g_atk_v2i_devs;   /* ATK <-> C0 P2P */
static NetDeviceContainer       g_atk_v2_devs;    /* ATK <-> V2 P2P (v2a/v3a single arrow) */
static NetDeviceContainer       g_c2c_01, g_c2c_02, g_c2c_12;
static Ipv4InterfaceContainer   g_wifiIfaces;

struct LinkIPs {
    Ipv4Address src_addr, dst_addr;
    uint32_t    src_node, dst_node;
};
static vector<LinkIPs> g_links;

static uint32_t g_TP=0, g_TN=0, g_FP=0, g_FN=0;
static uint32_t g_fake_pkts=0, g_legit_drop=0, g_wrong_fm=0;
static uint32_t g_cascade_cnt=0, g_topo_err=0, g_legit_total=0;
static string   g_pem_csv;
static bool     g_pem_hdr=false;
static uint32_t g_pem_cycle=0;

/* ================================================================
   HELPERS
   ================================================================ */
static string nname(uint32_t id) {
    if (id < 5)        return "V" + to_string(id);
    if (id == IDX_ATK) return "ATK";
    return "C" + to_string(id - IDX_C0);
}
static string npos(uint32_t id) {
    Ptr<MobilityModel> m = g_all.Get(id)->GetObject<MobilityModel>();
    Vector p = m->GetPosition();
    ostringstream o;
    o << fixed << setprecision(1) << "(" << p.x << "," << p.y << ")";
    return o.str();
}
static const char* TNAME[] = {
    "BEACON","FLOWMOD","C2C","FAKE_BEACON","FAKE_ALERT",
    "CASCADE","RECOMPUTE","FAKE_TRACE","ROUTE_CHG","WRONG_FM","WRONG_TOPO"
};

static Ipv4Address getP2PAddr(uint32_t src, uint32_t dst) {
    for (const auto& l : g_links)
        if (l.src_node==src && l.dst_node==dst) return l.dst_addr;
    for (const auto& l : g_links)
        if (l.src_node==dst && l.dst_node==src) return l.src_addr;
    NS_FATAL_ERROR("No P2P link " << src << "->" << dst);
    return Ipv4Address();
}
static Ipv4Address getWifiAddr(uint32_t node) {
    uint32_t idx = (node == IDX_ATK) ? 5 : node;
    return g_wifiIfaces.GetAddress(idx);
}


/* Rotating fake offsets */
static const double FPX[6] = { 80,-60, 90,-45,110,-75};
static const double FPY[6] = { 50, 30,-35, 65, 20,-55};
static const double FVX[6] = { -7,  5, -9,  3, -5,  8};
static const double FVY[6] = { -4, -8,  2, -6,  4, -3};
static uint32_t g_tseq = 0;

static EdcfTag make_tag(uint32_t src, EdcfTag::MsgType type) {
    EdcfTag t; t.m_type = type; t.m_from = src;
    Ptr<MobilityModel> mob = g_all.Get(src)->GetObject<MobilityModel>();
    Vector rp = mob->GetPosition(), rv = mob->GetVelocity();
    t.m_real_x=rp.x; t.m_real_y=rp.y; t.m_real_vx=rv.x; t.m_real_vy=rv.y;
    uint32_t fi = g_tseq % 6;
    if (type==EdcfTag::FAKE_BEACON || type==EdcfTag::FAKE_ALERT || type==EdcfTag::FAKE_TRACE) {
        t.m_fake_x=rp.x+FPX[fi]; t.m_fake_y=rp.y+FPY[fi];
        t.m_fake_vx=rv.x+FVX[fi]; t.m_fake_vy=rv.y+FVY[fi];
        t.m_vehicle_id = 90.0 + fi;
    } else {
        t.m_fake_x=rp.x; t.m_fake_y=rp.y;
        t.m_fake_vx=rv.x; t.m_fake_vy=rv.y;
        t.m_vehicle_id = (double)src;
    }
    g_tseq++; return t;
}

/* ================================================================
   RX CALLBACK
   ================================================================ */
static const uint16_t PORT = 7777;

static void PktRxCb(uint32_t rid, Ptr<const Packet> pkt) {
    EdcfTag tag;
    Ptr<Packet> c = pkt->Copy();
    if (!c->PeekPacketTag(tag)) return;
    if (tag.m_from == rid) return;
    double t = Simulator::Now().GetSeconds();
    uint32_t src = tag.m_from;
    string tn = ((int)tag.m_type < 11) ? TNAME[(int)tag.m_type] : "UNK";

    if (tag.m_type == EdcfTag::FAKE_BEACON) {
        cout << "This is source node. DSRC data Unicasting from " << nname(src) << " from port 0\n"
             << "[SPOOFED BEACON FLOODING] " << nname(src) << " --> " << nname(rid) << "\n"
             << "  Fake_ID      : V" << fixed << setprecision(0) << tag.m_vehicle_id << "\n"
             << "  Fake_position: (" << fixed << setprecision(2) << tag.m_fake_x << ", " << tag.m_fake_y << ")\n"
             << "  Real_position: (" << tag.m_real_x << ", " << tag.m_real_y << ")\n"
             << "  Fake_velocity: (" << tag.m_fake_vx << ", " << tag.m_fake_vy << ") m/s\n"
             << "  Real_velocity: (" << tag.m_real_vx << ", " << tag.m_real_vy << ") m/s\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n"
             << "  next hop exists: " << (rid < N_NODES ? 1 : 0) << "\n\n";
    } else if (tag.m_type == EdcfTag::FAKE_ALERT) {
        cout << "This is source node. DSRC data Unicasting from " << nname(src) << " from port 0\n"
             << "[CASCADING ALERT PROPAGATION] " << nname(src) << " --> " << nname(rid) << "\n"
             << "  Fake_event   : accident_at\n"
             << "  Fake_position: (" << fixed << setprecision(2) << tag.m_fake_x << ", " << tag.m_fake_y << ")\n"
             << "  Real_position: (" << tag.m_real_x << ", " << tag.m_real_y << ")\n"
             << "  broadcast_storm_triggered\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n"
             << "  next hop exists: " << (rid < N_NODES ? 1 : 0) << "\n\n";
    } else if (tag.m_type == EdcfTag::CASCADE) {
        cout << "This is source node. DSRC data Unicasting from " << nname(src) << " from port 0\n"
             << "[CASCADE RELAY] " << nname(src) << " --> " << nname(rid)
             << "  (re-broadcast fake alert, broadcast_storm)\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n"
             << "  next hop exists: " << (rid < N_NODES ? 1 : 0) << "\n\n";
    } else if (tag.m_type == EdcfTag::FAKE_TRACE) {
        cout << "This is source node. DSRC data Unicasting from " << nname(src) << " from port 0\n"
             << "[MOBILITY TRACE MANIPULATION] " << nname(src) << " --> " << nname(rid) << "\n"
             << "  Fake_position: (" << fixed << setprecision(2) << tag.m_fake_x << ", " << tag.m_fake_y << ")\n"
             << "  Real_position: (" << tag.m_real_x << ", " << tag.m_real_y << ")\n"
             << "  Fake_velocity: (" << tag.m_fake_vx << ", " << tag.m_fake_vy << ") m/s\n"
             << "  Real_velocity: (" << tag.m_real_vx << ", " << tag.m_real_vy << ") m/s\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n"
             << "  next hop exists: " << (rid < N_NODES ? 1 : 0) << "\n\n";
    } else if (tag.m_type == EdcfTag::WRONG_FM) {
        cout << "This is source node. DSRC data Unicasting from " << nname(src) << " from port 1\n"
             << "[WRONG FLOWMOD] " << nname(src) << npos(src) << " --> " << nname(rid) << npos(rid) << "\n"
             << "  Cause: corrupted topology / overloaded controller\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n\n";
    } else if (tag.m_type == EdcfTag::WRONG_TOPO) {
        cout << "This is source node. DSRC data Unicasting from " << nname(src) << " from port 1\n"
             << "[WRONG TOPOLOGY UPDATE] " << nname(src) << npos(src) << " --> " << nname(rid) << npos(rid) << "\n"
             << "  Cause: fake mobility trace accepted by controller\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n\n";
    } else if (tag.m_type == EdcfTag::RECOMPUTE) {
        cout << "This is source node. DSRC data Unicasting from "
             << nname(src) << npos(src) << " to " << nname(rid) << npos(rid) << "\n"
             << "[ROUTE_RECOMPUTE_REQUEST] " << nname(src) << " --> " << nname(rid)
             << "  (flood from fake alert)\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n\n";
    } else if (tag.m_type == EdcfTag::ROUTE_CHG) {
        cout << "This is source node. DSRC data Unicasting from "
             << nname(src) << npos(src) << " to " << nname(rid) << npos(rid) << "\n"
             << "[ROUTE_CHANGE_REQUEST] " << nname(src) << " --> " << nname(rid)
             << "  (wrong location from fake trace)\n"
             << "  Data unicast: transmitting packet at t=" << fixed << setprecision(4) << t << "s\n\n";
    } else {
        cout << "This is source node. DSRC data Unicasting from "
             << nname(src) << npos(src) << " to " << nname(rid) << npos(rid) << "\n"
             << "[" << tn << "] " << nname(src) << " --> " << nname(rid)
             << "  pos=(" << fixed << setprecision(2) << tag.m_real_x << "," << tag.m_real_y << ")"
             << "  vel=(" << tag.m_real_vx << "," << tag.m_real_vy << ")"
             << "  t=" << fixed << setprecision(4) << t << "s\n\n";
    }

    switch (tag.m_type) {
        case EdcfTag::BEACON: case EdcfTag::FLOWMOD: case EdcfTag::C2C:
        case EdcfTag::ROUTE_CHG: case EdcfTag::RECOMPUTE:
            g_TN++; g_legit_total++; break;
        case EdcfTag::CASCADE:
            g_TN++; g_legit_total++; g_cascade_cnt++; break;
        case EdcfTag::FAKE_BEACON: case EdcfTag::FAKE_ALERT: case EdcfTag::FAKE_TRACE:
            g_FN++; g_fake_pkts++; g_legit_drop++; break;
        case EdcfTag::WRONG_FM:
            g_FN++; g_wrong_fm++; g_legit_drop++; break;
        case EdcfTag::WRONG_TOPO:
            g_FN++; g_topo_err++; g_legit_drop++; break;
        default: break;
    }
}

/* ================================================================
   SEND HELPERS
   ================================================================ */
static void p2p_send(uint32_t src, uint32_t dst, EdcfTag::MsgType type,
                     uint32_t sz = 72, const string& log = "") {
    if (!log.empty())
        cout << "t=" << fixed << setprecision(2) << Simulator::Now().GetSeconds()
             << "  [P2P] " << nname(src) << npos(src)
             << " --> " << nname(dst) << npos(dst) << "  " << log << "\n";
    Ptr<Socket> s = Socket::CreateSocket(g_all.Get(src), UdpSocketFactory::GetTypeId());
    s->Connect(InetSocketAddress(getP2PAddr(src, dst), PORT));
    Ptr<Packet> pkt = Create<Packet>(sz);
    EdcfTag tag = make_tag(src, type);
    pkt->AddPacketTag(tag);
    s->Send(pkt); s->Close();
}

static void wifi_send(uint32_t src, uint32_t dst, EdcfTag::MsgType type,
                      uint32_t sz = 72, const string& log = "") {
    if (!log.empty())
        cout << "t=" << fixed << setprecision(2) << Simulator::Now().GetSeconds()
             << "  [WiFi] " << nname(src) << npos(src)
             << " --> " << nname(dst) << npos(dst) << "  " << log << "\n";
    Ptr<Socket> s = Socket::CreateSocket(g_all.Get(src), UdpSocketFactory::GetTypeId());
    s->Connect(InetSocketAddress(getWifiAddr(dst), PORT));
    Ptr<Packet> pkt = Create<Packet>(sz);
    EdcfTag tag = make_tag(src, type);
    pkt->AddPacketTag(tag);
    s->Send(pkt); s->Close();
}

/* ================================================================
   BASELINE
   ================================================================ */
static void step_baseline() {
    double t = Simulator::Now().GetSeconds();
    cout << "\n--- BASELINE t=" << fixed << setprecision(2) << t << "s ---\n";
    /* V2I beacons: each vehicle -> its controller */
    for (uint32_t v = 0; v < 5; v++)
        p2p_send(v, CA[v], EdcfTag::BEACON, 72,
                 "[BL] " + nname(v) + " BEACON -> " + nname(CA[v]));
    /* V2I FlowMod: each controller -> its vehicles */
    p2p_send(IDX_C0, IDX_V0, EdcfTag::FLOWMOD, 72, "[BL] C0 FlowMod->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::FLOWMOD, 72, "[BL] C0 FlowMod->V1");
    p2p_send(IDX_C1, IDX_V2, EdcfTag::FLOWMOD, 72, "[BL] C1 FlowMod->V2");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::FLOWMOD, 72, "[BL] C2 FlowMod->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::FLOWMOD, 72, "[BL] C2 FlowMod->V4");
    /* C2C full mesh */
    p2p_send(IDX_C0, IDX_C1, EdcfTag::C2C, 72, "[BL] C0->C1 sync");
    p2p_send(IDX_C0, IDX_C2, EdcfTag::C2C, 72, "");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::C2C, 72, "");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::C2C, 72, "");
    p2p_send(IDX_C2, IDX_C0, EdcfTag::C2C, 72, "");
    p2p_send(IDX_C2, IDX_C1, EdcfTag::C2C, 72, "");
}

/* ================================================================
   V1a: Spoofed Beacon Flooding -- Attacker Vehicle (Fig 3.3)
   Step 1: ATK -> C0 : 6 rapid fake-ID beacons (V2I P2P, ATK owns C0 link)
   Step 2: C0 overloaded -> WRONG FlowMod -> V0,V1 (own vehicles, P2P)
           C0 relays bad decision to C1,C2 via C2C
   Step 3: C1,C2 push WRONG FlowMod to their own vehicles
   ================================================================ */
static void v1a_s1_pkt0() { p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1] ATK->C0 FAKE_BEACON#1 (V90 spoofed)"); }
static void v1a_s1_pkt1() { p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1] ATK->C0 FAKE_BEACON#2 (V91 spoofed)"); }
static void v1a_s1_pkt2() { p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1] ATK->C0 FAKE_BEACON#3 (V92 spoofed)"); }
static void v1a_s1_pkt3() { p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1] ATK->C0 FAKE_BEACON#4 (V93 spoofed)"); }
static void v1a_s1_pkt4() { p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1] ATK->C0 FAKE_BEACON#5 (V94 spoofed)"); }
static void v1a_s1_pkt5() { p2p_send(IDX_ATK,IDX_C0,EdcfTag::FAKE_BEACON,128,"[V1a-S1] ATK->C0 FAKE_BEACON#6 (V95 spoofed)"); }

static void v1a_step2() {
    cout << "\n  [V1a-S2] C0 OVERLOADED -> WRONG FlowMod own vehicles + C2C contamination\n";
    /* C0 pushes wrong rules to its own vehicles directly */
    p2p_send(IDX_C0, IDX_V0, EdcfTag::WRONG_FM, 72, "[V1a-S2] C0 WRONG FlowMod->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::WRONG_FM, 72, "[V1a-S2] C0 WRONG FlowMod->V1");
    /* C0 poisons C1,C2 via C2C */
    p2p_send(IDX_C0, IDX_C1, EdcfTag::C2C, 72, "[V1a-S2] C0->C1 WRONG decision C2C");
    p2p_send(IDX_C0, IDX_C2, EdcfTag::C2C, 72, "[V1a-S2] C0->C2 WRONG decision C2C");
}
static void v1a_step3() {
    cout << "\n  [V1a-S3] Poisoned C1,C2 -> WRONG FlowMod their own vehicles\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::WRONG_FM, 72, "[V1a-S3] C1 WRONG FlowMod->V2");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::WRONG_FM, 72, "[V1a-S3] C2 WRONG FlowMod->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::WRONG_FM, 72, "[V1a-S3] C2 WRONG FlowMod->V4");
}
static void v1a_attack() {
    cout << "\n=== V1a SPOOFED BEACON FLOODING -- Attacker Vehicle (Fig 3.3) ===\n"
         << "  ATK floods C0 (V2I P2P) -> C0 overloaded -> WRONG FlowMod own vehicles\n"
         << "  C0 poisons C1,C2 via C2C -> C1,C2 push WRONG FlowMod their vehicles\n";
    Simulator::Schedule(Seconds(0.00), v1a_s1_pkt0);
    Simulator::Schedule(Seconds(0.18), v1a_s1_pkt1);
    Simulator::Schedule(Seconds(0.36), v1a_s1_pkt2);
    Simulator::Schedule(Seconds(0.54), v1a_s1_pkt3);
    Simulator::Schedule(Seconds(0.72), v1a_s1_pkt4);
    Simulator::Schedule(Seconds(0.90), v1a_s1_pkt5);
    Simulator::Schedule(Seconds(1.30), v1a_step2);
    Simulator::Schedule(Seconds(1.90), v1a_step3);
}

/* ================================================================
   V1b: Spoofed Beacon Flooding -- Compromised Controller C1 (Fig 3.3)
   Step 1: V0-V4 normal beacons to their controllers (V2I P2P)
   Step 2: C0,C2 correct FlowMod to their own vehicles
   Step 3: BAD C1 -> WRONG FlowMod -> V2 (own vehicle, V2I P2P)
           BAD C1 -> C2C poison to C0,C2
   Step 4: Poisoned C0 -> WRONG FlowMod -> V0,V1
           Poisoned C2 -> WRONG FlowMod -> V3,V4
   ================================================================ */
static void v1b_step1() {
    for (uint32_t v = 0; v < 5; v++)
        p2p_send(v, CA[v], EdcfTag::BEACON, 72,
                 v==0 ? "[V1b-S1] V0-V4 normal beacons->controllers" : "");
}
static void v1b_step2() {
    p2p_send(IDX_C0,IDX_V0,EdcfTag::FLOWMOD,72,"[V1b-S2] C0 correct FlowMod->V0");
    p2p_send(IDX_C0,IDX_V1,EdcfTag::FLOWMOD,72,"[V1b-S2] C0 correct FlowMod->V1");
    p2p_send(IDX_C2,IDX_V3,EdcfTag::FLOWMOD,72,"[V1b-S2] C2 correct FlowMod->V3");
    p2p_send(IDX_C2,IDX_V4,EdcfTag::FLOWMOD,72,"[V1b-S2] C2 correct FlowMod->V4");
}
static void v1b_step3() {
    cout << "\n  [V1b-S3] BAD C1 -> WRONG FlowMod V2 (own) + C2C poison to C0,C2\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::WRONG_FM, 72, "[V1b-S3] BAD_C1 WRONG FlowMod->V2 (own)");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::C2C, 72, "[V1b-S3] BAD_C1->C0 C2C POISON");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::C2C, 72, "[V1b-S3] BAD_C1->C2 C2C POISON");
}
static void v1b_step4() {
    cout << "\n  [V1b-S4] Poisoned C0,C2 -> WRONG FlowMod their own vehicles\n";
    p2p_send(IDX_C0, IDX_V0, EdcfTag::WRONG_FM, 72, "[V1b-S4] POISONED C0 WRONG FlowMod->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::WRONG_FM, 72, "[V1b-S4] POISONED C0 WRONG FlowMod->V1");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::WRONG_FM, 72, "[V1b-S4] POISONED C2 WRONG FlowMod->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::WRONG_FM, 72, "[V1b-S4] POISONED C2 WRONG FlowMod->V4");
}
static void v1b_attack() {
    cout << "\n=== V1b SPOOFED BEACON FLOODING -- Compromised Controller C1 (Fig 3.3) ===\n"
         << "  BAD C1 -> WRONG FM own vehicle + C2C poison -> C0,C2 corrupt their vehicles\n";
    v1b_step1();
    Simulator::Schedule(Seconds(0.35), v1b_step2);
    Simulator::Schedule(Seconds(0.80), v1b_step3);
    Simulator::Schedule(Seconds(1.40), v1b_step4);
}

/* ================================================================
   V2a: Cascading Alert Propagation -- Attacker Vehicle (Fig 3.4 top)
   Step 1: ATK -> V2 ONE fake alert (V2V WiFi, single target)
   Step 2: V2 CASCADE relay to V0,V1,V3,V4 (V2V WiFi, broadcast storm)
   Step 3: ALL vehicles -> their OWN controller RECOMPUTE (V2I P2P)
   Step 4: C1 overloaded -> WRONG FlowMod -> V2 (own)
           C1 -> C2C -> C0,C2 -> those push WRONG FM their vehicles
   ================================================================ */
static void v2a_step1() {
    /* Use P2P link so NetAnim arrow goes ONLY to V2, not all WiFi nodes */
    p2p_send(IDX_ATK, IDX_V2, EdcfTag::FAKE_ALERT, 72,
             "[V2a-S1] ATK->V2 FAKE_ACCIDENT_ALERT (P2P->V2, single target)");
}
static void v2a_step2() {
    cout << "\n  [V2a-S2] V2 CASCADE relay -> broadcast storm (V2V WiFi)\n";
    wifi_send(IDX_V2,IDX_V0,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V0");
    wifi_send(IDX_V2,IDX_V1,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V1");
    wifi_send(IDX_V2,IDX_V3,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V3");
    wifi_send(IDX_V2,IDX_V4,EdcfTag::CASCADE,72,"[V2a-S2] V2 CASCADE->V4");
}
static void v2a_step3() {
    cout << "\n  [V2a-S3] ALL vehicles RECOMPUTE -> their controllers (V2I P2P)\n";
    p2p_send(IDX_V0,IDX_C0,EdcfTag::RECOMPUTE,72,"[V2a-S3] V0->C0 RECOMPUTE");
    p2p_send(IDX_V1,IDX_C0,EdcfTag::RECOMPUTE,72,"[V2a-S3] V1->C0 RECOMPUTE");
    p2p_send(IDX_V2,IDX_C1,EdcfTag::RECOMPUTE,72,"[V2a-S3] V2->C1 RECOMPUTE");
    p2p_send(IDX_V3,IDX_C2,EdcfTag::RECOMPUTE,72,"[V2a-S3] V3->C2 RECOMPUTE");
    p2p_send(IDX_V4,IDX_C2,EdcfTag::RECOMPUTE,72,"[V2a-S3] V4->C2 RECOMPUTE");
}
static void v2a_step4() {
    cout << "\n  [V2a-S4] C1 OVERLOADED -> WRONG FM V2 (own) + C2C -> C0,C2\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::WRONG_FM, 72, "[V2a-S4] C1 OVERLOADED WRONG FM->V2");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::C2C, 72, "[V2a-S4] C1->C0 WRONG decision C2C");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::C2C, 72, "[V2a-S4] C1->C2 WRONG decision C2C");
}
static void v2a_step5() {
    cout << "\n  [V2a-S5] Contaminated C0,C2 -> WRONG FM their vehicles\n";
    p2p_send(IDX_C0, IDX_V0, EdcfTag::WRONG_FM, 72, "[V2a-S5] C0 WRONG FM->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::WRONG_FM, 72, "[V2a-S5] C0 WRONG FM->V1");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::WRONG_FM, 72, "[V2a-S5] C2 WRONG FM->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::WRONG_FM, 72, "[V2a-S5] C2 WRONG FM->V4");
}
static void v2a_attack() {
    cout << "\n=== V2a CASCADING ALERT PROPAGATION -- Attacker Vehicle (Fig 3.4 top) ===\n"
         << "  ATK->V2 fake alert (WiFi), V2 cascades (storm), RECOMPUTE flood\n"
         << "  C1 overloaded -> WRONG FM own vehicle + C2C -> C0,C2 contaminated\n";
    v2a_step1();
    Simulator::Schedule(Seconds(0.45), v2a_step2);
    Simulator::Schedule(Seconds(1.10), v2a_step3);
    Simulator::Schedule(Seconds(1.85), v2a_step4);
    Simulator::Schedule(Seconds(2.45), v2a_step5);
}

/* ================================================================
   V2b: Cascading Alert Propagation -- Compromised C1 (Fig 3.4 bottom)
   Step 1: BAD C1 -> FAKE_ALERT -> V2 (own, V2I P2P) + C2C to C0,C2
   Step 2: C0,C2 forward FAKE_ALERT to their own vehicles (V2I P2P)
   Step 3: Vehicles CASCADE among each other (V2V WiFi storm)
   Step 4: ALL vehicles -> RECOMPUTE -> their controllers (V2I P2P)
   Step 5: BAD C1 -> WRONG FM -> V2 (own) + C2C -> C0,C2
   Step 6: C0,C2 push WRONG FM their vehicles
   ================================================================ */
static void v2b_step1() {
    cout << "\n  [V2b-S1] BAD C1 -> FAKE_ALERT V2 (own) + C2C to C0,C2\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::FAKE_ALERT, 72, "[V2b-S1] BAD_C1 FAKE_ALERT->V2 (own)");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::FAKE_ALERT, 72, "[V2b-S1] BAD_C1 FAKE_ALERT C2C->C0");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::FAKE_ALERT, 72, "[V2b-S1] BAD_C1 FAKE_ALERT C2C->C2");
}
static void v2b_step2() {
    cout << "\n  [V2b-S2] C0,C2 forward FAKE_ALERT to own vehicles\n";
    p2p_send(IDX_C0, IDX_V0, EdcfTag::FAKE_ALERT, 72, "[V2b-S2] C0 FAKE_ALERT->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::FAKE_ALERT, 72, "[V2b-S2] C0 FAKE_ALERT->V1");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::FAKE_ALERT, 72, "[V2b-S2] C2 FAKE_ALERT->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::FAKE_ALERT, 72, "[V2b-S2] C2 FAKE_ALERT->V4");
}
static void v2b_step3() {
    cout << "\n  [V2b-S3] Vehicles CASCADE storm (V2V WiFi)\n";
    for (uint32_t sv = 0; sv < 5; sv++)
        for (uint32_t rv = 0; rv < 5; rv++) {
            if (sv == rv) continue;
            wifi_send(sv, rv, EdcfTag::CASCADE, 72,
                      (sv==0&&rv==1) ? "[V2b-S3] Vehicles CASCADE storm" : "");
        }
}
static void v2b_step4() {
    cout << "\n  [V2b-S4] ALL vehicles RECOMPUTE -> their controllers\n";
    for (uint32_t v = 0; v < 5; v++)
        p2p_send(v, CA[v], EdcfTag::RECOMPUTE, 72,
                 v==0 ? "[V2b-S4] V0-V4 RECOMPUTE->controllers" : "");
}
static void v2b_step5() {
    cout << "\n  [V2b-S5] BAD C1 WRONG FM V2 (own) + C2C poison C0,C2\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::WRONG_FM, 72, "[V2b-S5] BAD_C1 WRONG FM->V2");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::C2C, 72, "[V2b-S5] BAD_C1 WRONG C2C->C0");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::C2C, 72, "[V2b-S5] BAD_C1 WRONG C2C->C2");
}
static void v2b_step6() {
    cout << "\n  [V2b-S6] Poisoned C0,C2 WRONG FM their vehicles\n";
    p2p_send(IDX_C0, IDX_V0, EdcfTag::WRONG_FM, 72, "[V2b-S6] POISONED C0 WRONG FM->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::WRONG_FM, 72, "[V2b-S6] POISONED C0 WRONG FM->V1");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::WRONG_FM, 72, "[V2b-S6] POISONED C2 WRONG FM->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::WRONG_FM, 72, "[V2b-S6] POISONED C2 WRONG FM->V4");
}
static void v2b_attack() {
    cout << "\n=== V2b CASCADING ALERT PROPAGATION -- Compromised C1 (Fig 3.4 bottom) ===\n";
    v2b_step1();
    Simulator::Schedule(Seconds(0.35), v2b_step2);
    Simulator::Schedule(Seconds(0.75), v2b_step3);
    Simulator::Schedule(Seconds(1.60), v2b_step4);
    Simulator::Schedule(Seconds(2.20), v2b_step5);
    Simulator::Schedule(Seconds(2.80), v2b_step6);
}

/* ================================================================
   V3a: Mobility Trace Manipulation -- Attacker Vehicle (Fig 3.5 top)
   Step 1: ATK -> V2 FAKE_TRACE (V2V WiFi, single target)
   Step 2: V2 -> C1 ROUTE_CHG (V2I P2P, V2 is C1's own vehicle)
   Step 3: C1 wrong topo -> WRONG_TOPO -> V2 (own)
           C1 C2C poisons C0,C2 -> they push WRONG_TOPO their vehicles
   ================================================================ */
static void v3a_step1() {
    /* Use P2P link so NetAnim arrow goes ONLY to V2, not all WiFi nodes */
    p2p_send(IDX_ATK, IDX_V2, EdcfTag::FAKE_TRACE, 72,
             "[V3a-S1] ATK->V2 FAKE_LOCATION (P2P->V2, single target)");
}
static void v3a_step2() {
    cout << "\n  [V3a-S2] V2 deceived -> ROUTE_CHG to C1 (V2I P2P)\n";
    p2p_send(IDX_V2, IDX_C1, EdcfTag::ROUTE_CHG, 72,
             "[V3a-S2] V2->C1 ROUTE_CHANGE_REQUEST (wrong location)");
}
static void v3a_step3() {
    cout << "\n  [V3a-S3] C1 wrong topo -> WRONG_TOPO V2 (own) + C2C poison\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::WRONG_TOPO, 72, "[V3a-S3] C1 WRONG_TOPO->V2");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::C2C, 72, "[V3a-S3] C1->C0 WRONG TOPO C2C");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::C2C, 72, "[V3a-S3] C1->C2 WRONG TOPO C2C");
}
static void v3a_step4() {
    cout << "\n  [V3a-S4] Poisoned C0,C2 -> WRONG_TOPO their vehicles\n";
    p2p_send(IDX_C0, IDX_V0, EdcfTag::WRONG_TOPO, 72, "[V3a-S4] C0 WRONG_TOPO->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::WRONG_TOPO, 72, "[V3a-S4] C0 WRONG_TOPO->V1");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::WRONG_TOPO, 72, "[V3a-S4] C2 WRONG_TOPO->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::WRONG_TOPO, 72, "[V3a-S4] C2 WRONG_TOPO->V4");
}
static void v3a_attack() {
    cout << "\n=== V3a MOBILITY TRACE MANIPULATION -- Attacker Vehicle (Fig 3.5 top) ===\n"
         << "  ATK->V2 fake trace (WiFi), V2->C1 ROUTE_CHG, C1 wrong topo spreads\n";
    v3a_step1();
    Simulator::Schedule(Seconds(0.65), v3a_step2);
    Simulator::Schedule(Seconds(1.30), v3a_step3);
    Simulator::Schedule(Seconds(1.90), v3a_step4);
}

/* ================================================================
   V3b: Mobility Trace Manipulation -- Compromised C1 (Fig 3.5 bottom)
   Step 1: V0-V4 correct beacons to their controllers
   Step 2: BAD C1 -> WRONG_TOPO -> V2 (own, V2I P2P)
           BAD C1 -> C2C -> C0,C2 (poison)
   Step 3: Poisoned C0 -> WRONG_TOPO -> V0,V1
           Poisoned C2 -> WRONG_TOPO -> V3,V4
   Step 4: C0 <-> C2 WRONG_TOPO loop (both poisoned by C1)
   ================================================================ */
static void v3b_step1() {
    for (uint32_t v = 0; v < 5; v++)
        p2p_send(v, CA[v], EdcfTag::BEACON, 72,
                 v==0 ? "[V3b-S1] V0-V4 CORRECT beacons->controllers" : "");
}
static void v3b_step2() {
    cout << "\n  [V3b-S2] BAD C1 -> WRONG_TOPO V2 (own) + C2C poison C0,C2\n";
    p2p_send(IDX_C1, IDX_V2, EdcfTag::WRONG_TOPO, 72, "[V3b-S2] BAD_C1 WRONG_TOPO->V2");
    p2p_send(IDX_C1, IDX_C0, EdcfTag::WRONG_TOPO, 72, "[V3b-S2] BAD_C1 WRONG_TOPO C2C->C0");
    p2p_send(IDX_C1, IDX_C2, EdcfTag::WRONG_TOPO, 72, "[V3b-S2] BAD_C1 WRONG_TOPO C2C->C2");
}
static void v3b_step3() {
    cout << "\n  [V3b-S3] Poisoned C0,C2 -> WRONG_TOPO their vehicles\n";
    p2p_send(IDX_C0, IDX_V0, EdcfTag::WRONG_TOPO, 72, "[V3b-S3] C0 WRONG_TOPO->V0");
    p2p_send(IDX_C0, IDX_V1, EdcfTag::WRONG_TOPO, 72, "[V3b-S3] C0 WRONG_TOPO->V1");
    p2p_send(IDX_C2, IDX_V3, EdcfTag::WRONG_TOPO, 72, "[V3b-S3] C2 WRONG_TOPO->V3");
    p2p_send(IDX_C2, IDX_V4, EdcfTag::WRONG_TOPO, 72, "[V3b-S3] C2 WRONG_TOPO->V4");
}
static void v3b_step4() {
    cout << "\n  [V3b-S4] C0<->C2 WRONG_TOPO LOOP (both poisoned by BAD C1)\n";
    p2p_send(IDX_C0, IDX_C2, EdcfTag::WRONG_TOPO, 72, "[V3b-S4] C0->C2 WRONG_TOPO LOOP");
    p2p_send(IDX_C2, IDX_C0, EdcfTag::WRONG_TOPO, 72, "[V3b-S4] C2->C0 WRONG_TOPO LOOP");
}
static void v3b_attack() {
    cout << "\n=== V3b MOBILITY TRACE MANIPULATION -- Compromised C1 (Fig 3.5 bottom) ===\n";
    v3b_step1();
    Simulator::Schedule(Seconds(0.50), v3b_step2);
    Simulator::Schedule(Seconds(1.10), v3b_step3);
    Simulator::Schedule(Seconds(1.80), v3b_step4);
}

/* ================================================================
   PEM METRICS
   ================================================================ */
static void print_pem() {
    g_pem_cycle++;
    double t_now = Simulator::Now().GetSeconds();
    double tot  = g_TP + g_TN + g_FP + g_FN;
    double acc  = tot > 0 ? (double)(g_TP + g_TN) / tot : 1.0;
    double mcc_num = (double)g_TP*g_TN - (double)g_FP*g_FN;
    double mcc_den = sqrt(max(1.0, (double)(g_TP+g_FP)*(g_TP+g_FN)*(g_TN+g_FP)*(g_TN+g_FN)));
    double mcc  = mcc_num / mcc_den;
    double fpr  = (g_FP+g_TN) > 0 ? (double)g_FP/(g_FP+g_TN) : 0.0;
    double f1d  = 2.0*g_TP + g_FP + g_FN;
    double f1   = f1d > 0 ? 2.0*g_TP/f1d : 0.0;
    double prec = (g_TP+g_FP) > 0 ? (double)g_TP/(g_TP+g_FP) : 0.0;
    double pdr  = g_legit_total > 0
                ? (double)(g_legit_total - min(g_legit_drop,g_legit_total)) / g_legit_total
                : 1.0;
    double atk_rate = t_now > 0 ? (double)g_FN / t_now : 0.0;
    const char* status;
    if      (acc >= 0.85) status = "NORMAL   (attack impact low)   ";
    else if (acc >= 0.60) status = "DEGRADED (attack detected)     ";
    else                  status = "CRITICAL (network under attack) ";

    cout << "\n+------------------------------------------------------+\n"
         << "|  PEM METRICS  Cycle=" << setw(2) << g_pem_cycle
         << "  t=" << fixed << setprecision(2) << t_now
         << "s  scenario=" << g_scenario << "\n"
         << "+------------------------------------------------------+\n"
         << "|  TP=" << setw(4) << g_TP << "  TN(legit)=" << setw(5) << g_TN
         << "  FP=" << setw(3) << g_FP << "  FN(attack)=" << setw(5) << g_FN << "\n"
         << "+------------------------------------------------------+\n"
         << "|  Accuracy  = " << fixed << setprecision(6) << setw(10) << acc
         << (acc  < 0.9 ? "  <- DEGRADING " : "  (normal)    ") << "\n"
         << "|  MCC       = " << setw(10) << mcc
         << (mcc  < 0.5 ? "  <- DEGRADING " : "  (normal)    ") << "\n"
         << "|  FPR       = " << setw(10) << fpr << "\n"
         << "|  F1-score  = " << setw(10) << f1  << "\n"
         << "|  Precision = " << setw(10) << prec << "\n"
         << "+------------------------------------------------------+\n"
         << "|  fake_pkts_injected = " << setw(6) << g_fake_pkts   << "\n"
         << "|  wrong_flowmod_count= " << setw(6) << g_wrong_fm    << "\n"
         << "|  cascade_relay_count= " << setw(6) << g_cascade_cnt << "\n"
         << "|  topology_err_count = " << setw(6) << g_topo_err    << "\n"
         << "|  attack_rate/s      = " << setw(6) << fixed << setprecision(3) << atk_rate << "\n"
         << "+------------------------------------------------------+\n"
         << "|  PDR = " << fixed << setprecision(2) << setw(6) << pdr*100.0 << "%"
         << (pdr < 0.8 ? "  <- DEGRADING " : "  (normal)    ")
         << "  legit_total=" << setw(4) << g_legit_total << "\n"
         << "|  legit_delivered=" << setw(4)
         << (g_legit_total > g_legit_drop ? g_legit_total - g_legit_drop : 0)
         << "  legit_dropped=" << setw(4) << g_legit_drop << "\n"
         << "+------------------------------------------------------+\n"
         << "|  STATUS: " << status << "\n"
         << "+------------------------------------------------------+\n";

    fstream fout;
    if (!g_pem_hdr) {
        fout.open(g_pem_csv, ios::out | ios::trunc);
        fout << "# EDCF-Shield PEM  scenario=" << g_scenario << "\n"
             << "cycle,t,TP,TN,FP,FN,Accuracy,MCC,FPR,F1,Precision,"
             << "fake_pkts,wrong_fm,cascade,topo_err,atk_rate,"
             << "legit_total,legit_drop,PDR_pct\n";
        fout.close(); g_pem_hdr = true;
    }
    fout.open(g_pem_csv, ios::out | ios::app);
    fout << fixed << g_pem_cycle << "," << setprecision(2) << t_now << ","
         << g_TP << "," << g_TN << "," << g_FP << "," << g_FN << ","
         << setprecision(6) << acc << "," << mcc << "," << fpr << "," << f1 << "," << prec << ","
         << g_fake_pkts << "," << g_wrong_fm << "," << g_cascade_cnt << "," << g_topo_err << ","
         << setprecision(3) << atk_rate << ","
         << g_legit_total << "," << g_legit_drop << ","
         << setprecision(2) << pdr*100.0 << "\n";
    fout.close();
    cout << "[PEM CSV] saved -> " << g_pem_csv << "\n";
}

/* ================================================================
   SIMULATION CYCLE
   ================================================================ */
typedef void (*AttackFn)();
static AttackFn g_attack_fn = 0;

static void sim_done() {
    cout << "\n=== SIMULATION COMPLETE  scenario=" << g_scenario
         << "  TN=" << g_TN << "  FN=" << g_FN << " ===\n";
}

static void run_cycle();
static void schedule_attack() { if (g_attack_fn) g_attack_fn(); }

static void run_cycle() {
    g_cycle++;
    double t = Simulator::Now().GetSeconds();
    cout << "\n====== CYCLE " << g_cycle
         << "  t=" << fixed << setprecision(1) << t << "s ======\n";
    step_baseline();
    Simulator::Schedule(Seconds(0.5),  schedule_attack);
    Simulator::Schedule(Seconds(3.5),  print_pem);
    if (t + 4.0 < g_simTime)
        Simulator::Schedule(Seconds(4.0), run_cycle);
    else
        Simulator::Schedule(Seconds(0.95), sim_done);
}

/* ================================================================
   MAIN
   ================================================================ */
int main(int argc, char* argv[]) {
    CommandLine cmd;
    cmd.AddValue("scenario", "v1a|v1b|v2a|v2b|v3a|v3b", g_scenario);
    cmd.AddValue("simTime",  "Simulation time (s)",       g_simTime);
    cmd.Parse(argc, argv);

    system("mkdir -p ./scratch ./results_LLDP/individual ./results_LLDP/combined");
    const char* csvf[] = {"./scratch/security_data.csv",
                          "./scratch/security_global_HMAC_data.csv", 0};
    for (int i = 0; csvf[i]; i++) {
        ifstream c(csvf[i]);
        if (!c.good()) { ofstream cr(csvf[i]); cr.close(); }
    }
    g_pem_csv = "./scratch/edcf_" + g_scenario + "_pem.csv";

    bool has_atk = false, has_badc = false;
    if      (g_scenario == "v1a") { g_attack_fn = v1a_attack; has_atk  = true; }
    else if (g_scenario == "v1b") { g_attack_fn = v1b_attack; has_badc = true; }
    else if (g_scenario == "v2a") { g_attack_fn = v2a_attack; has_atk  = true; }
    else if (g_scenario == "v2b") { g_attack_fn = v2b_attack; has_badc = true; }
    else if (g_scenario == "v3a") { g_attack_fn = v3a_attack; has_atk  = true; }
    else if (g_scenario == "v3b") { g_attack_fn = v3b_attack; has_badc = true; }
    else { cerr << "Unknown scenario: " << g_scenario << "\n"; return 1; }

    g_all.Create(N_NODES);

    /* Mobility */
    MobilityHelper mob;
    mob.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < N_NODES; i++) pos->Add(Vector(PX[i], PY[i], 0.0));
    mob.SetPositionAllocator(pos);
    mob.Install(g_all);
    static const double VEL[9] = {12, 10, 8, 14, 11, 10, 0, 0, 0};
    for (uint32_t i = 0; i < N_NODES; i++)
        DynamicCast<ConstantVelocityMobilityModel>(
            g_all.Get(i)->GetObject<MobilityModel>())
            ->SetVelocity(Vector(VEL[i], 0, 0));

    /* WiFi 802.11p (V2V only: V0-V4 + ATK) */
    NodeContainer wifiNodes;
    for (uint32_t i = 0; i <= IDX_ATK; i++) wifiNodes.Add(g_all.Get(i));
    YansWifiChannelHelper wch;
    wch.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wch.AddPropagationLoss("ns3::RangePropagationLossModel","MaxRange",DoubleValue(600.0));
    YansWifiPhyHelper wphy;
    wphy.SetChannel(wch.Create());
    wphy.SetErrorRateModel("ns3::NistErrorRateModel");
    wphy.Set("TxPowerStart", DoubleValue(41));
    wphy.Set("TxPowerEnd",   DoubleValue(41));
    wphy.Set("Frequency",    UintegerValue(5890));
    wphy.Set("ChannelWidth", UintegerValue(10));
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
        "DataMode",        StringValue("OfdmRate12MbpsBW10MHz"),
        "ControlMode",     StringValue("OfdmRate12MbpsBW10MHz"),
        "RtsCtsThreshold", UintegerValue(1000));
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac","QosSupported",BooleanValue(true));
    g_wifiDevs = wifi.Install(wphy, mac, wifiNodes);

    /* Internet stack on ALL nodes */
    InternetStackHelper inet; inet.Install(g_all);

    /* WiFi IPs: 10.1.1.x  (wifiNodes: V0..V4=idx0..4, ATK=idx5) */
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0","255.255.255.0");
    g_wifiIfaces = ipv4.Assign(g_wifiDevs);

    /* V2I P2P: one link per vehicle-controller association */
    PointToPointHelper p2p_v2i;
    p2p_v2i.SetDeviceAttribute ("DataRate", DataRateValue(DataRate("100Mbps")));
    p2p_v2i.SetChannelAttribute("Delay",    TimeValue(MicroSeconds(50)));
    for (uint32_t v = 0; v < 5; v++) {
        uint32_t ctrl = CA[v];
        g_v2i_devs[v] = p2p_v2i.Install(g_all.Get(v), g_all.Get(ctrl));
        ostringstream base; base << "10.2." << v << ".0";
        ipv4.SetBase(base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifc = ipv4.Assign(g_v2i_devs[v]);
        LinkIPs lk1 = {ifc.GetAddress(0), ifc.GetAddress(1), v,    ctrl};
        LinkIPs lk2 = {ifc.GetAddress(1), ifc.GetAddress(0), ctrl, v   };
        g_links.push_back(lk1); g_links.push_back(lk2);
    }

    /* ATK V2I link -> C0 (subnet 10.2.5.0/30) */
    {
        g_atk_v2i_devs = p2p_v2i.Install(g_all.Get(IDX_ATK), g_all.Get(IDX_C0));
        ipv4.SetBase("10.2.5.0","255.255.255.252");
        Ipv4InterfaceContainer ifc = ipv4.Assign(g_atk_v2i_devs);
        LinkIPs l1 = {ifc.GetAddress(0), ifc.GetAddress(1), IDX_ATK, IDX_C0};
        LinkIPs l2 = {ifc.GetAddress(1), ifc.GetAddress(0), IDX_C0,  IDX_ATK};
        g_links.push_back(l1); g_links.push_back(l2);
    }

    /* ATK <-> V2 P2P link (subnet 10.2.6.0/30)
     * Dedicated P2P so NetAnim draws arrow ONLY ATK->V2 in v2a/v3a. */
    {
        g_atk_v2_devs = p2p_v2i.Install(g_all.Get(IDX_ATK), g_all.Get(IDX_V2));
        ipv4.SetBase("10.2.6.0","255.255.255.252");
        Ipv4InterfaceContainer ifc6 = ipv4.Assign(g_atk_v2_devs);
        LinkIPs la = {ifc6.GetAddress(0), ifc6.GetAddress(1), IDX_ATK, IDX_V2};
        LinkIPs lb = {ifc6.GetAddress(1), ifc6.GetAddress(0), IDX_V2,  IDX_ATK};
        g_links.push_back(la); g_links.push_back(lb);
    }

    /* C2C P2P full mesh */
    PointToPointHelper p2p_c2c;
    p2p_c2c.SetDeviceAttribute ("DataRate", DataRateValue(DataRate("1000Mbps")));
    p2p_c2c.SetChannelAttribute("Delay",    TimeValue(MicroSeconds(10)));
    {
        g_c2c_01 = p2p_c2c.Install(g_all.Get(IDX_C0), g_all.Get(IDX_C1));
        ipv4.SetBase("10.3.0.0","255.255.255.252");
        Ipv4InterfaceContainer ifc = ipv4.Assign(g_c2c_01);
        LinkIPs l01={ifc.GetAddress(0),ifc.GetAddress(1),IDX_C0,IDX_C1};
        LinkIPs l10={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C1,IDX_C0};
        g_links.push_back(l01); g_links.push_back(l10);
    }
    {
        g_c2c_02 = p2p_c2c.Install(g_all.Get(IDX_C0), g_all.Get(IDX_C2));
        ipv4.SetBase("10.3.1.0","255.255.255.252");
        Ipv4InterfaceContainer ifc = ipv4.Assign(g_c2c_02);
        LinkIPs l02={ifc.GetAddress(0),ifc.GetAddress(1),IDX_C0,IDX_C2};
        LinkIPs l20={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C2,IDX_C0};
        g_links.push_back(l02); g_links.push_back(l20);
    }
    {
        g_c2c_12 = p2p_c2c.Install(g_all.Get(IDX_C1), g_all.Get(IDX_C2));
        ipv4.SetBase("10.3.2.0","255.255.255.252");
        Ipv4InterfaceContainer ifc = ipv4.Assign(g_c2c_12);
        LinkIPs l12={ifc.GetAddress(0),ifc.GetAddress(1),IDX_C1,IDX_C2};
        LinkIPs l21={ifc.GetAddress(1),ifc.GetAddress(0),IDX_C2,IDX_C1};
        g_links.push_back(l12); g_links.push_back(l21);
    }

    /* PacketSink on all nodes */
    for (uint32_t n = 0; n < N_NODES; n++) {
        PacketSinkHelper sk("ns3::UdpSocketFactory",
            InetSocketAddress(Ipv4Address::GetAny(), PORT));
        ApplicationContainer sc = sk.Install(g_all.Get(n));
        sc.Start(Seconds(0.0)); sc.Stop(Seconds(g_simTime));
    }

    /* RX trace on all net-devices */
    for (uint32_t ni = 0; ni < N_NODES; ni++) {
        Ptr<Node> nd = g_all.Get(ni);
        for (uint32_t di = 0; di < nd->GetNDevices(); di++) {
            Ptr<WifiNetDevice> wdev = DynamicCast<WifiNetDevice>(nd->GetDevice(di));
            if (wdev) {
                wdev->GetMac()->TraceConnectWithoutContext(
                    "MacRx", MakeBoundCallback(&PktRxCb, ni));
                continue;
            }
            Ptr<PointToPointNetDevice> pdev =
                DynamicCast<PointToPointNetDevice>(nd->GetDevice(di));
            if (pdev)
                pdev->TraceConnectWithoutContext(
                    "MacRx", MakeBoundCallback(&PktRxCb, ni));
        }
    }

    /* NetAnim */
    string xml = "./scratch/edcf_" + g_scenario + ".xml";
    AnimationInterface anim(xml);
    anim.SetMaxPktsPerTraceFile(9999999);
    anim.EnablePacketMetadata(true);
    for (uint32_t i = 0; i < 5; i++) {
        anim.UpdateNodeDescription(g_all.Get(i), "V" + to_string(i));
        anim.UpdateNodeColor(g_all.Get(i), 0, 200, 0);
        anim.UpdateNodeSize(i, 30, 30);
    }
    anim.UpdateNodeDescription(g_all.Get(IDX_ATK), has_atk ? "ATK" : "(inactive)");
    anim.UpdateNodeColor(g_all.Get(IDX_ATK), has_atk ? 220 : 160, 0, 0);
    anim.UpdateNodeSize(IDX_ATK, 35, 35);
    anim.UpdateNodeDescription(g_all.Get(IDX_C0), "C0_GOOD");
    anim.UpdateNodeColor(g_all.Get(IDX_C0), 0, 0, 220);
    anim.UpdateNodeSize(IDX_C0, 35, 35);
    anim.UpdateNodeDescription(g_all.Get(IDX_C1), has_badc ? "C1_BAD" : "C1_GOOD");
    anim.UpdateNodeColor(g_all.Get(IDX_C1), has_badc ? 255 : 0, has_badc ? 140 : 0, has_badc ? 0 : 220);
    anim.UpdateNodeSize(IDX_C1, 35, 35);
    anim.UpdateNodeDescription(g_all.Get(IDX_C2), "C2_GOOD");
    anim.UpdateNodeColor(g_all.Get(IDX_C2), 0, 0, 220);
    anim.UpdateNodeSize(IDX_C2, 35, 35);

    cout << "\n=== EDCF-Shield  Group 14 ===\n"
         << "scenario=" << g_scenario << "  simTime=" << g_simTime << "s\n"
         << "Topology: V2V=WiFi(802.11p)  V2I=P2P(100Mbps)  C2C=P2P(1Gbps)\n"
         << "P2P links: V0-C0  V1-C0  V2-C1  V3-C2  V4-C2  ATK-C0  ATK-V2\n"
         << "           C0-C1  C0-C2  C1-C2\n"
         << "XML: " << xml << "\n\n";

    Simulator::Schedule(Seconds(1.0), run_cycle);
    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
