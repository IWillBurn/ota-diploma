# Coverage-guided fuzzing (D5)

Budget per target: 300 s.

| Implementation | Version | Target | Verdict | Execs | Detail |
|---|---|---|---|---|---|
| go-tuf | v2.4.2 | FuzzParse | FAIL | 133541 | --- FAIL: FuzzParse (26.44s) at /go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/metadata.go:408 +0x1206; /go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/trusted |
| go-tuf | v2.4.2 | FuzzTimestampFirst | PASS | 2826905 | no failure in 300 s |
| go-tuf | v2.4.2 | FuzzTimestampSecond | FAIL | 42048 | --- FAIL: FuzzTimestampSecond (7.13s) at /go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/trustedmetadata/trustedmetadata.go:144 +0x934 |
| go-tuf | v2.4.2 | FuzzSnapshot | PASS | 3481367 | no failure in 300 s |
| go-tuf | v2.4.2 | FuzzTargets | PASS | 2755653 | no failure in 300 s |
| go-tuf | v2.4.2 | FuzzRootUpdate | FAIL | 89792 | --- FAIL: FuzzRootUpdate (18.39s) at /go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/metadata.go:408 +0x1206; /go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/tr |
| python-tuf | 7.0.1 | parse | PASS | 6148306 | no unexpected exception in 300 s |
| python-tuf | 7.0.1 | timestamp_first | PASS | 2995793 | no unexpected exception in 300 s |
| python-tuf | 7.0.1 | timestamp_second | PASS | 3796308 | no unexpected exception in 300 s |
| python-tuf | 7.0.1 | snapshot | PASS | 5534853 | no unexpected exception in 300 s |
| python-tuf | 7.0.1 | targets | PASS | 5835017 | no unexpected exception in 300 s |
| python-tuf | 7.0.1 | root_update | PASS | 2867976 | no unexpected exception in 300 s |
| go-tuf | master-923b304 | FuzzParse | PASS | 984368 | no failure in 300 s |
| go-tuf | master-923b304 | FuzzTimestampFirst | PASS | 3673855 | no failure in 300 s |
| go-tuf | master-923b304 | FuzzTimestampSecond | PASS | 3138013 | no failure in 300 s |
| go-tuf | master-923b304 | FuzzSnapshot | PASS | 3525208 | no failure in 300 s |
| go-tuf | master-923b304 | FuzzTargets | PASS | 3498635 | no failure in 300 s |
| go-tuf | master-923b304 | FuzzRootUpdate | PASS | 659060 | no failure in 300 s |
