# SWUpdate 2024.12.1 from bookworm-backports (the version in the A/B image) for verification-only
# scenarios: .swu container mutations, no VM needed.
FROM debian:12
RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/bpo.list \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      cpio openssl gzip ca-certificates \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -t bookworm-backports swupdate \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f='swupdate ${Version}\n' swupdate \
 && echo 'otabench 1.0' > /etc/hwrevision
WORKDIR /work
