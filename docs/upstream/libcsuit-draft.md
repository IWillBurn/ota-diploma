# Draft issue for kentakayama/libcsuit

> **Status: draft, not posted.** Post only after the author has reviewed it. Found with the
> otabench SUIT profile (`bench/scripts/suit_bench.py`, `bench/clients/suit-libcsuit/`) on
> libcsuit `00f5609` (master, 2026-02), OpenSSL build (`ossl.Dockerfile`, Ubuntu 22.04).

---

**Title:** `suit_process_envelope()` returns success for some undecodable inputs; empty report crashes `suit_print_report()`

**Body:**

Two robustness observations from feeding malformed envelopes to the process example.

**1. Success for inputs that are not SUIT envelopes.** For 20 random 300-byte inputs and one
envelope truncated to 50 bytes, `suit_process_envelope()` returned `SUIT_SUCCESS` for 6 of
them (e.g. inputs starting with `b4…` or `1e…`): no manifest is processed, the report
callback receives an empty report, and the process example exits 0. The parser example
rejects the same inputs (`SUIT_ERR_FATAL`, `SUIT_INVALID_TYPE_OF_VALUE`). An integrator who
reports the result of `suit_process_envelope()` to a status tracker would report success for
an update that was never decoded. Expected: an error whenever no authenticated manifest
could be decoded.

A structured run confirms it: of 436 mutations of the genuine `suit_manifest_expU.suit` envelope
(every byte inverted, truncations every 8 bytes), processed with the genuine payload, none
crashed and none installed anything, but 52 returned `SUIT_SUCCESS` without processing: all 48
truncations from 8 to 384 bytes, and an inverted byte in the outer map key of the authentication
wrapper (offset 1), of the manifest (offset 119) or in the manifest's length (offsets 121, 122).

**2. NULL dereference in the default report printing.** With the unmodified process example,
a truncated envelope, random input, or a valid envelope with one byte of the COSE signature
flipped crash with SIGSEGV:

```
#0 suit_judge_cose_tag_from_buf ()
#1 suit_print_report ()
#2 __wrap_suit_report_callback () at suit_manifest_process_main.c:614
#3 suit_process_envelope ()
```

`suit_judge_cose_tag_from_buf()` (`src/suit_cose.c`) reads `signed_cose.ptr[0]` (and `[1]`)
without checking `ptr`/`len`; the report is empty when the envelope was rejected before a
report was built. The same function is used on authentication blocks in
`suit_manifest_decode.c` (around line 1185), where a zero-length block would read one byte
past it (not verified with a sanitizer).

Suggested fix: return `COSE_TAG_INVALID` when `signed_cose.ptr == NULL || signed_cose.len < 1`
(and `< 2` before reading the second byte); skip printing an empty report.

The image-match check itself behaves correctly once failed conditions are not suppressed:
a payload with a wrong digest is rejected (the process example suppresses failed conditions
"for testing", which is expected for an example).

---

## Notes for the author (not part of the issue)

* Results: `bench/results/suit-2026-11-01/`; crash backtrace taken with gdb in the
  `libcsuit_ossl` image built from `ossl.Dockerfile`.
* Severity is low (no code runs, nothing is installed); it is a status/robustness issue.
