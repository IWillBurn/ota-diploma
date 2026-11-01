#!/bin/bash
# after the quiet batch: rerun the read-only-root torn model with the BRICK re-check
cd /p/Projects/ota-diploma/bench
while ! grep -q '^exit' /p/vm/pilot-quiet.log 2>/dev/null; do sleep 60; done
L=/p/vm/pilot-q5.log
.venv/Scripts/python.exe -u -I scripts/pilot_ab.py --updater rauc-grub --torn --only reorder:ext4-inplace-rootro < /dev/null > $L 2>&1
echo "exit $? $(date)" >> $L
