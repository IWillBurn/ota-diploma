#!/bin/bash
# after B11: replay on a quiet host the only state of the RAUC 1.15.2 whole-window run
# (results/pilot-ab-20261102-123644) with an unreadable environment: all-but-2127 in
# [2100; 2128], i.e. every write before 2127 (an in-order prefix), at the final grubenv rewrite
cd /p/Projects/ota-diploma/bench
while ! grep -q '^exit' /p/vm/pilot-b11.log 2>/dev/null; do sleep 60; done
.venv/Scripts/python.exe -u -I scripts/replay_state.py --base P:/vm/variants/rauc1.15.2-grub-ext4-c5-f18f0a89.qcow2 --log P:/vm/pilot/20261102-123644/reorder-ext4-c5/golden.log --base-end 2127 --liveness --updater rauc1.15.2-grub --work P:/vm/postmortem/rauc1152-2127 < /dev/null > /p/vm/replay-rauc1152-2127.log 2>&1
echo "exit $? $(date)" >> /p/vm/replay-b11.log
