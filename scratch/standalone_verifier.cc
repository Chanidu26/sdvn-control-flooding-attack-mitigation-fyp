// ============================================================================
//  standalone_verifier.cc -- independently verifies a FALCON-1024 signature
//  pulled from the live ledger, using ONLY the exported RSU public key file
//  and raw FALCON math. No ns-3, no simulation state, no trust assumed.
//
//  Usage: standalone_verifier <pubkey_file> <rsu_id> <payload_string> <sig_hex>
// ============================================================================
#define EDCF_HAVE_FALCON
#include "edcf_crypto.h"
#include "edcf_falcon.h"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <map>
using namespace edcf;

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage: %s <pubkey_file> <rsu_id> <payload> <sig_hex>\n", argv[0]);
        return 2;
    }
    std::string pubkey_file = argv[1], rsu_id = argv[2], payload = argv[3], sig_hex = argv[4];

    std::map<std::string, Bytes> pubkeys;
    std::ifstream f(pubkey_file);
    std::string id, hex;
    while (f >> id >> hex) pubkeys[id] = from_hex(hex);

    if (pubkeys.find(rsu_id) == pubkeys.end()) {
        printf("ERROR: %s not found in %s\n", rsu_id.c_str(), pubkey_file.c_str());
        return 1;
    }

    Bytes pk = pubkeys[rsu_id];
    Bytes sig = from_hex(sig_hex);
    Bytes msg = to_bytes(payload);

    printf("Verifying signature from %s\n", rsu_id.c_str());
    printf("  public key:  %zu bytes\n", pk.size());
    printf("  signature:   %zu bytes\n", sig.size());
    printf("  payload:     \"%s\"\n", payload.c_str());

    bool valid = falcon1024_verify(pk, msg, sig);
    printf("\nRESULT: signature is %s\n", valid ? "VALID (cryptographically authentic)" : "INVALID");
    return valid ? 0 : 1;
}