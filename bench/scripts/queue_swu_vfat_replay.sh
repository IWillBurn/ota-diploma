#!/bin/bash
# after the B5 replays: replay on a quiet host the final prefix state of the SWUpdate vfat
# reorder run (results/pilot-ab-20261101-202805, kept-all in [2474; 2487], i.e. every write
# up to 35 s after success). That run recorded the boot environment as unreadable for the OS
# in all 38 states while other VMs ran; the quiet-host window run (pilot-ab-20261102-110256)
# shows the new state for both views from +5 s.
cd /p/Projects/ota-diploma/bench
while ! grep -q '^exit' /p/vm/replay-b5.log 2>/dev/null; do sleep 60; done
.venv/Scripts/python.exe -u -I scripts/replay_state.py --base P:/vm/variants/swupdate-grub-vfat-e4559cfd.qcow2 --log P:/vm/pilot/20261101-202805/reorder-vfat/golden.log --base-end 2487 --liveness --updater swupdate-grub --work P:/vm/postmortem/swu-vfat-2487 < /dev/null > /p/vm/replay-swu-vfat-2487.log 2>&1
echo "exit $? $(date)" >> /p/vm/replay-swu.log
