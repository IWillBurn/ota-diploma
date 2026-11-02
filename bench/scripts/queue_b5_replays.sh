#!/bin/bash
# after the read-only-root rerun: replay on a quiet host the two other B5 states
# (RAUC 1.8, ext4, whole install window, results/pilot-ab-20261101-200437) that were
# recorded with an unreadable boot environment while four VMs ran in parallel.
# State 1535 (kept-all, prefix) did not reproduce that way on a quiet host
# (replay-rauc18-1535b.log: grubenv readable, ORDER=B A, liveness OK).
cd /p/Projects/ota-diploma/bench
while ! grep -q '^exit' /p/vm/pilot-q5.log 2>/dev/null; do sleep 60; done
B=P:/vm/variants/rauc-grub-ext4-c5-e1102cb0.qcow2
G=P:/vm/pilot/20261101-200437/reorder-ext4-c5/golden.log
# only-1339 in barrier interval [1152; 1480]
.venv/Scripts/python.exe -u -I scripts/replay_state.py --base $B --log $G --base-end 1153 --extra 1339 --liveness --updater rauc-grub --work P:/vm/postmortem/rauc18-1339 < /dev/null > /p/vm/replay-rauc18-1339.log 2>&1
# lost-all in barrier interval [1525; 1527]
.venv/Scripts/python.exe -u -I scripts/replay_state.py --base $B --log $G --base-end 1526 --liveness --updater rauc-grub --work P:/vm/postmortem/rauc18-1525 < /dev/null > /p/vm/replay-rauc18-1525.log 2>&1
echo "exit $? $(date)" >> /p/vm/replay-b5.log
