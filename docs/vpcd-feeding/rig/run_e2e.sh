#!/bin/bash
# E2E: real upstream vpcd.c driver (drv_up) x the REAL bench emulator (vpicc_table.py)
set -u
NAME=$1; EMU=$2; IDX=$3
DP=$((36100+IDX)); PP=$((36200+IDX))
cd "$(dirname "$0")"
timeout -s KILL 20 ./drv_upstream $DP 3 > ../captures/${NAME}.driver.log 2>&1 &
DPID=$!
sleep 0.3
python3 recproxy.py --listen $PP --driver $DP --out ../captures/${NAME}.pcap > ../captures/${NAME}.proxy.log 2>&1 &
RXPID=$!
sleep 0.3
python3 "$EMU" --port $PP > ../captures/${NAME}.emu.log 2>&1 &
EPID=$!
wait $DPID; RC=$?
sleep 0.5
kill $RXPID $EPID 2>/dev/null; wait $RXPID $EPID 2>/dev/null
echo "== $NAME driver-exit=$RC"; cat results/${NAME}.driver.log
