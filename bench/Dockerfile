# Linux image for otabench (final experiments should run on Linux).
# NOTE: written on 2026-10-31 on a host without a running Docker daemon -> not yet built/tested.
#   docker build -t otabench -f bench/Dockerfile .      (context = repository root)
#   docker run --rm -v "$PWD/bench/results:/work/bench/results" otabench run --quick
FROM golang:1.25-bookworm AS gobuild
ARG TUF_CONFORMANCE_COMMIT=3d3fbb8164a7b0d404cff08b13594104ec3fef4f
RUN git clone https://github.com/theupdateframework/tuf-conformance /src/tuf-conformance \
 && git -C /src/tuf-conformance checkout ${TUF_CONFORMANCE_COMMIT} \
 && cd /src/tuf-conformance/clients/go-tuf && go build -o /out/go-tuf .

FROM python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm git strace \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gobuild /src/tuf-conformance /work/third_party/tuf-conformance
COPY --from=gobuild /out/go-tuf /work/bench/clients/bin/go-tuf
WORKDIR /work/bench
COPY bench/ /work/bench/
RUN python -m venv .venv \
 && .venv/bin/pip install --no-cache-dir "tuf==7.0.1" "securesystemslib[crypto]==1.6.0" pyyaml /work/third_party/tuf-conformance \
 && cd clients/tuf-js && npm install --no-audit --no-fund \
 && sed -i 's#{root}/clients/bin/go-tuf.exe#{root}/clients/bin/go-tuf#' /work/bench/clients.yaml
ENTRYPOINT [".venv/bin/python", "-m", "otabench"]
