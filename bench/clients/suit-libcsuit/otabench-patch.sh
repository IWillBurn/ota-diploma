#!/bin/sh
# Build the otabench adapter from libcsuit's examples/process (BSD-2-Clause, SECOM CO., LTD.).
set -e
cd /libcsuit/examples
rm -rf otabench && cp -r process otabench && cd otabench
M=suit_manifest_process_main.c
# 1. identifier conditions the example does not implement: treated as matched
awk '
/case SUIT_CONDITION_VENDOR_IDENTIFIER:/ {vid=1}
/case SUIT_CONDITION_CLASS_IDENTIFIER:/  {vid=1}
/case SUIT_CONDITION_DEVICE_IDENTIFIER:/ {vid=1}
vid && /result = SUIT_ERR_NOT_IMPLEMENTED;/ { sub(/SUIT_ERR_NOT_IMPLEMENTED/, "SUIT_SUCCESS /* otabench: identifiers not under test */"); vid=0 }
{ print }
' "$M" > "$M.new" && mv "$M.new" "$M"
# 2. failed conditions are not suppressed (OTABENCH_SUPPRESS=1 restores the upstream example)
awk '
/printf\("callback : suppress it for testing.\\n\\n"\);/ {
  print "        if (getenv(\"OTABENCH_SUPPRESS\") && getenv(\"OTABENCH_SUPPRESS\")[0] == 0x31) {"; print; getline; print; print "        }"; next }
{ print }
' "$M" > "$M.new" && mv "$M.new" "$M"
# 3. an empty report (manifest rejected before a report exists) is not printed
awk '
/^suit_err_t __wrap_suit_report_callback\(suit_report_args_t report_args\)/ { print; getline; print;
  print "    if (report_args.suit_report.ptr == NULL || report_args.suit_report.len == 0) {";
  print "        printf(\"callback : empty SUIT report, not printed (otabench)\\n\");";
  print "        return SUIT_SUCCESS;"; print "    }"; next }
{ print }
' "$M" > "$M.new" && mv "$M.new" "$M"
grep -q 'getenv("OTABENCH_SUPPRESS")' "$M"
grep -q 'identifiers not under test' "$M"
grep -q 'empty SUIT report' "$M"
grep -q '#include <stdlib.h>' "$M" || sed -i '1i #include <stdlib.h>' "$M"
make clean >/dev/null 2>&1 || true
make >/dev/null
ls -l suit_manifest_process
