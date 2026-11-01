# Linux image for otabench (final experiments should run on Linux).
# NOTE: written on 2026-10-31 on a host without a running Docker daemon -> not yet built/tested.
#   docker build -t otabench -f bench/Dockerfile .      (context = repository root)
#   docker run --rm -v "$PWD/bench/results:/work/bench/results" otabench run --quick
FROM golang:1.25-bookworm AS gobuild
ARG TUF_CONFORMANCE_COMMIT=3d3fbb8164a7b0d404cff08b13594104ec3fef4f
RUN git clone https://github.com/theupdateframework/tuf-conformance /src/tuf-conformance \
 && git -C /src/tuf-conformance checkout ${TUF_CONFORMANCE_COMMIT} \
 && cd /src/tuf-conformance/clients/go-tuf && go build -o /out/go-tuf .

FROM rust:1-bookworm AS toughbuild
COPY bench/clients/tough /src/tough
RUN cd /src/tough && cargo build --release --locked && mkdir -p /out && cp target/release/tough /out/tough

FROM python:3.13-slim-bookworm
# tuf-js 6.0.1 needs Node ^22.22.2 or ^24.15.0; Debian bookworm ships 18.x
COPY --from=node:24-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:24-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gobuild /src/tuf-conformance /work/third_party/tuf-conformance
COPY --from=gobuild /out/go-tuf /work/bench/clients/bin/go-tuf
COPY --from=toughbuild /out/tough /work/bench/clients/bin/tough
WORKDIR /work/bench
COPY bench/ /work/bench/
RUN python -m venv .venv \
 && .venv/bin/pip install --no-cache-dir "tuf==7.0.1" "securesystemslib[crypto]==1.6.0" "pyyaml==6.0.3" "jsonschema==4.23.0" "pytest==9.1.1" /work/third_party/tuf-conformance \
 && cd clients/tuf-js && npm ci --no-audit --no-fund
ENTRYPOINT [".venv/bin/python", "-m", "otabench"]
