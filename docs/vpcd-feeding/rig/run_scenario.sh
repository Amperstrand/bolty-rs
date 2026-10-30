#!/bin/bash
# run_scenario.sh NAME DRV_BINARY VPICC_MODE IDX [extra harness args...]
set -u
NAME=$1; DRV=$2; MODE=$3; IDX=$4; shift 4
cd "$(dirname "$0")"
DP=$((36100+IDX)); PP=$((36200+IDX))

timeout -s KILL 15 ./drv_$DRV $DP 3 "$@" > ../captures/${NAME}.driver.log 2>&1 &
DPID=$!
sleep 0.3
python3 recproxy.py --listen $PP --driver $DP --out ../captures/${NAME}.pcap > ../captures/${NAME}.proxy.log 2>&1 &
RXPID=$!
sleep 0.3
python3 vpicc_sim.py --port $PP --mode $MODE > ../captures/${NAME}.vpicc.log 2>&1 &
VPID=$!
wait $DPID; RC=$?
sleep 0.5
kill $RXPID $VPID 2>/dev/null
wait $RXPID $VPID 2>/dev/null
echo "== $NAME (driver=drv_$DRV vpicc=$MODE) driver-exit=$RC"
cat ../captures/${NAME}.driver.log
