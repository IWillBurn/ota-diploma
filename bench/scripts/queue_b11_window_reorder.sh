#!/bin/bash
# B11: reordering model over the whole install window (as B5 for RAUC 1.8) for RAUC 1.15.2 and
# SWUpdate on the default ext4 /boot-ab. One VM at a time; R24 (BRICK retry) and R26 (status
# after mount jobs) in effect. SWUpdate never flushes its environment: the end marker comes
# 35 s after success so that background writeback is inside the window.
cd /p/Projects/ota-diploma/bench
busy() { powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { \$_.CommandLine -match 'pilot_ab|replay_state' }).Count"; }
while [ "$(busy | tr -d '\r')" != "0" ]; do sleep 60; done
L=/p/vm/pilot-b11.log
echo "start $(date)" > $L
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater rauc1.15.2-grub --only reorder:ext4-c5 --region-at window --sample-intervals 0 < /dev/null >> $L 2>&1
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater swupdate-grub --only reorder:ext4-c5 --region-at window --sample-intervals 0 --settle 35 < /dev/null >> $L 2>&1
echo "exit $? $(date)" >> $L
