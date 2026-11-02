#!/bin/bash
# three more SWUpdate window:vfat runs on a quiet host: does the vfat window length vary
# between runs? (window run 20261102-110256: new from +5 s; reorder run 20261101-202805:
# environment still not on disk 35 s after success, confirmed by a replay)
cd /p/Projects/ota-diploma/bench
busy() { powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { \$_.CommandLine -match 'pilot_ab|replay_state' }).Count"; }
while [ "$(busy | tr -d '\r')" != "0" ]; do sleep 60; done
L=/p/vm/pilot-swu-vfat.log
echo "start $(date)" > $L
for i in 1 2 3; do
  echo "== run $i" >> $L
  .venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater swupdate-grub --offsets 0,1,2,3,4,5,6,8,10,15,20,30,45,60,90 --only window:vfat < /dev/null >> $L 2>&1
done
echo "exit $? $(date)" >> $L
