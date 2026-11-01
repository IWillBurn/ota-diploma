# Two RAUC versions side by side for verification-only scenarios (no VM needed):
#   /usr/bin/rauc            RAUC 1.8 from Debian 12 (the version in the A/B image)
#   /opt/rauc-1.15.2/bin/rauc  RAUC 1.15.2 from the release tarball (as in build_rauc_upgrade.py)
FROM debian:12
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      rauc squashfs-tools openssl ca-certificates curl xz-utils \
      build-essential meson ninja-build pkg-config libglib2.0-dev libssl-dev libjson-glib-dev \
      libdbus-1-dev libcurl4-openssl-dev libnl-genl-3-dev libfdisk-dev \
    && rm -rf /var/lib/apt/lists/*
ARG RAUC_VERSION=1.15.2
ARG RAUC_SHA256=127a24cde208c65b837ae978c695a00730f1094ee8b6c7d48cf58ef846eae340
RUN curl -fsSL -o /tmp/rauc.tar.xz \
      https://github.com/rauc/rauc/releases/download/v${RAUC_VERSION}/rauc-${RAUC_VERSION}.tar.xz \
    && echo "${RAUC_SHA256}  /tmp/rauc.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/rauc.tar.xz -C /tmp && cd /tmp/rauc-${RAUC_VERSION} \
    && meson setup build --prefix=/opt/rauc-${RAUC_VERSION} -Dtests=false -Dhtmldocs=false \
         -Dmanpages=false -Dservice=false -Dstreaming=false -Dnetwork=false -Dgpt=disabled \
    && ninja -C build install && rm -rf /tmp/rauc* \
    && dpkg-query -W -f='debian rauc ${Version}\n' rauc && /opt/rauc-${RAUC_VERSION}/bin/rauc --version
WORKDIR /work
