# The machine the opt-in Manager end-to-end run uses: Ubuntu 24.04 (x86_64, the only Linux
# companion that is released) with the released companion installed exactly as apt installs it,
# plus what is needed to build this repository's test binary and controller inside it.
# See tools/manager_e2e/README.md. Nothing here is shipped.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git jq pkg-config python3 rsync xz-utils \
      libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev libdbus-1-dev \
      dbus-x11 gnome-keyring procps \
    && rm -rf /var/lib/apt/lists/*
# Node 22 builds the Desktop interface and supplies npm; the companion's own Node runs Manager.
RUN curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      https://nodejs.org/dist/v22.21.1/node-v22.21.1-linux-x64.tar.xz -o /tmp/node.tar.xz \
    && mkdir -p /opt/node22 && tar -xJf /tmp/node.tar.xz -C /opt/node22 --strip-components=1 \
    && rm /tmp/node.tar.xz && /opt/node22/bin/node --version
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:/opt/node22/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable && rustc --version
# The released companion, installed by apt from the two packages a release publishes.
RUN --mount=type=bind,source=.,target=/companion \
    test "$(ls /companion/*_bootstrap.deb | wc -l)" = 1 && test "$(ls /companion/*_runtime.deb | wc -l)" = 1 \
    && apt-get update -qq \
    && apt-get install -y --no-install-recommends /companion/*_bootstrap.deb /companion/*_runtime.deb \
    && rm -rf /var/lib/apt/lists/* \
    && ls /opt/frameleaf/Runtimes
