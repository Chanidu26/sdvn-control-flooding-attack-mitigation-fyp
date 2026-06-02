#!/bin/bash
cd ~/ns-allinone-3.35/ns-3.35/

echo "=== V1a: Spoofed Beacon Flooding (external) ==="
for n in 1 2 3 4 5; do
    echo "  atk_count=$n"
    ./waf --run "routing --edcf_scenario=v1a --edcf_atk_count=$n" 2>/dev/null
done

echo "=== V1b: Spoofed Beacon Flooding (internal) ==="
for n in 1 2 3 4 5; do
    echo "  atk_count=$n stolen"
    ./waf --run "routing --edcf_scenario=v1b --edcf_atk_count=$n --edcf_has_key=1" 2>/dev/null
done

echo "=== V1b: Compromised Controller ==="
for c in 0 1 2; do
    echo "  bad_ctrl=C$c"
    ./waf --run "routing --edcf_scenario=v1b --edcf_bad_ctrl=$c" 2>/dev/null
done



echo "=== V2a: Cascading Alert (external) ==="
for n in 1 2 3 4 5; do
    echo "  atk_count=$n"
    ./waf --run "routing --edcf_scenario=v2a --edcf_atk_count=$n" 2>/dev/null
done


echo "=== V2a: Cascading Alert (internal) ==="
for n in 1 2 3 4 5; do
    echo "  atk_count=$n"
    ./waf --run "routing --edcf_scenario=v2b --edcf_atk_count=$n --edcf_has_key=1" 2>/dev/null
done

echo "=== V2b: Compromised Controller ==="
for c in 0 1 2; do
    echo "  bad_ctrl=C$c"
    ./waf --run "routing --edcf_scenario=v2b --edcf_bad_ctrl=$c" 2>/dev/null
done



echo "=== V3a: Mobility Trace (external, SUMO positions) ==="
for n in 1 2 3 4 5; do
    echo "  atk_count=$n"
    ./waf --run "routing --edcf_scenario=v3a --edcf_atk_count=$n" 2>/dev/null
done

echo "=== V3a: Mobility Trace (internal, SUMO positions) ==="
for n in 1 2 3 4 5; do
    echo "  atk_count=$n"
    ./waf --run "routing --edcf_scenario=v3b --edcf_atk_count=$n --edcf_has_key=1" 2>/dev/null
done

echo "=== V3b: Compromised Controller ==="
for c in 0 1 2; do
    echo "  bad_ctrl=C$c"
    ./waf --run "routing --edcf_scenario=v3b --edcf_bad_ctrl=$c" 2>/dev/null
done