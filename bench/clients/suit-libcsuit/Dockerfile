# libcsuit (SUIT manifest processor, C) with an otabench adapter, backlog A6.
#   docker build -t otabench-suit bench/clients/suit-libcsuit
# The adapter is libcsuit's own examples/process program with three changes
# (otabench-patch.sh): conditions the example does not implement (vendor/class/device
# identifiers) count as matched, failed conditions are NOT suppressed any more (the upstream
# example suppresses them "for testing"; OTABENCH_SUPPRESS=1 restores that as a negative
# control), and an empty SUIT report is not handed to the report printer.
FROM ubuntu:22.04
ARG LIBCSUIT_COMMIT=00f56098736ca6bb18ed16ced71eb7de4444bb9d
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install --no-install-recommends clang make libcunit1-dev \
      libssl-dev ruby git ca-certificates && gem install cbor-diag && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/kentakayama/libcsuit /libcsuit \
 && cd /libcsuit && git checkout "$LIBCSUIT_COMMIT" && git submodule update --init --recursive
WORKDIR /libcsuit
RUN make build_test
COPY otabench-patch.sh /libcsuit/otabench-patch.sh
RUN sh /libcsuit/otabench-patch.sh
ENTRYPOINT ["/libcsuit/examples/otabench/suit_manifest_process"]
