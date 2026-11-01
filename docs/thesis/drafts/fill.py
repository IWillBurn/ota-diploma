"""Fill placeholders of the ch4 drafts. Values that are still unknown stay as placeholders;
the script reports which ones are left."""
import json
import re
import sys
from pathlib import Path

SCR = Path(__file__).parent
VALUES = json.loads((SCR / "fill_values.json").read_text(encoding="utf-8"))
left = set()
for name in ("ch4_new_43.md", "ch4_new_43_net.md", "ch4_tail.md", "pilot_new_sections.md"):
    p = SCR / name
    s = p.read_text(encoding="utf-8")
    for k, v in VALUES.items():
        s = s.replace(f"<<{k}>>", v)
    p.write_text(s, encoding="utf-8", newline="\n")
    left |= set(re.findall(r"<<([A-Z0-9_]+)>>", s))
print("left:", sorted(left))
sys.exit(1 if left else 0)
