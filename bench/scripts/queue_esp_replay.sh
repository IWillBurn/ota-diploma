#!/bin/bash
# after the SWUpdate vfat replay: replay on a quiet host the prefix state 1614 of the UEFI ESP
# window run (results/pilot-ab-20261101-125344, window:uefi-esp), the only prefix state recorded
# with an unreadable boot environment on the ESP; that run predates the mount-job wait (R26).
cd /p/Projects/ota-diploma/bench
while ! grep -q '^exit' /p/vm/replay-swu.log 2>/dev/null; do sleep 60; done
.venv/Scripts/python.exe -u -I scripts/replay_state.py --uefi --base P:/vm/variants/ab-uefi-esp.qcow2 --log P:/vm/pilot/20261101-125344/window-uefi-esp/golden.log --base-end 1615 --liveness --updater rauc-grub --work P:/vm/postmortem/esp-1614 < /dev/null > /p/vm/replay-esp-1614.log 2>&1
echo "exit $? $(date)" >> /p/vm/replay-esp.log
