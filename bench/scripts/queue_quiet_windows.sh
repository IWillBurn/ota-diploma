#!/bin/bash
# waits until no other pilot_ab.py / replay_state.py runs, then measures windows on a quiet host
cd /p/Projects/ota-diploma/bench
busy() { powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { \$_.CommandLine -match 'pilot_ab|replay_state' }).Count"; }
while [ "$(busy | tr -d '\r')" != "0" ]; do sleep 60; done
L=/p/vm/pilot-quiet.log
echo "quiet from $(date)" > $L
OFF=0,1,2,3,4,5,6,8,10,15,20,30,45,60,90
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater rauc1.15.2-grub --only net-slow:stream < /dev/null >> $L 2>&1
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater rauc-grub --offsets $OFF --only window:ext4-c5,window:ext4-redundant < /dev/null >> $L 2>&1
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater rauc1.15.2-grub --offsets $OFF --only window:ext4-c5,window:ext4-exponly,window:ext4-wbonly < /dev/null >> $L 2>&1
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater swupdate-grub --offsets $OFF --only window:ext4-c5,window:vfat < /dev/null >> $L 2>&1
.venv/Scripts/python.exe -u -I scripts/replay_state.py --base P:/vm/variants/rauc-grub-ext4-c5-e1102cb0.qcow2 --log P:/vm/pilot/20261101-200437/reorder-ext4-c5/golden.log --base-end 1536 --liveness --updater rauc-grub --work P:/vm/postmortem/rauc18-1535b < /dev/null > /p/vm/replay-rauc18-1535b.log 2>&1
echo "exit $? $(date)" >> $L
