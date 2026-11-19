# Opt-in proof image for carrying a library across companion packages (see README.md here).
# Two Postgres builds with pgvector stand in for "previous package" and "new package", beside the
# product's own server so the library schema comes from its migrations. Nothing here is shipped.
ARG SERVER_IMAGE=ghcr.io/frameleaf/frameleaf-server:latest
FROM ${SERVER_IMAGE}

ARG PREVIOUS_POSTGRES=18.7
ARG PREVIOUS_POSTGRES_SHA256=441dfae4280cae3e0425e5f876f80559fb0731c140f1aae22b3e5a54d0411bfd
# The two values below are the pins in runtime/host-database.json.
ARG NEXT_POSTGRES=19beta4
ARG NEXT_POSTGRES_SHA256=83157ee9c599d03b2f7a3d73ef3a56ec24e0e79cc2b3501a64d1364f56398c86
ARG PGVECTOR=0.8.7
ARG PGVECTOR_SHA256=cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85
# Compile jobs; kept low by default so the build does not crowd a shared machine.
ARG JOBS=4

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential bison flex pkg-config curl ca-certificates \
      bzip2 perl libicu-dev libssl-dev uuid-dev liblz4-dev libzstd-dev libxml2-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Same configure switches as tools/build_host_database.py.
RUN set -eux; \
    mkdir /pgbuild; cd /pgbuild; \
    curl -fsSL -o vector.tar.gz "https://codeload.github.com/pgvector/pgvector/tar.gz/refs/tags/v${PGVECTOR}"; \
    echo "${PGVECTOR_SHA256}  vector.tar.gz" | sha256sum -c -; \
    for spec in "${PREVIOUS_POSTGRES} ${PREVIOUS_POSTGRES_SHA256} /opt/postgres-previous" \
                "${NEXT_POSTGRES} ${NEXT_POSTGRES_SHA256} /opt/postgres-next"; do \
      set -- $spec; \
      curl -fsSL -o "postgresql-$1.tar.bz2" "https://ftp.postgresql.org/pub/source/v$1/postgresql-$1.tar.bz2"; \
      echo "$2  postgresql-$1.tar.bz2" | sha256sum -c -; \
      tar -xjf "postgresql-$1.tar.bz2"; \
      ( cd "postgresql-$1" \
        && ./configure --prefix="$3" --without-readline --with-icu --with-openssl --with-uuid=e2fs \
             --with-lz4 --with-zstd --with-libxml >/dev/null \
        && make -j"${JOBS}" world-bin >/dev/null \
        && make install-world-bin >/dev/null ); \
      rm -rf vector && mkdir vector && tar -xzf vector.tar.gz -C vector --strip-components=1; \
      ( cd vector && make -j"${JOBS}" PG_CONFIG="$3/bin/pg_config" OPTFLAGS= >/dev/null \
        && make PG_CONFIG="$3/bin/pg_config" install >/dev/null ); \
      rm -rf "postgresql-$1" "postgresql-$1.tar.bz2"; \
    done; \
    cd /; rm -rf /pgbuild; \
    /opt/postgres-previous/bin/postgres --version; /opt/postgres-next/bin/postgres --version

# Postgres refuses to run as root.
USER node
WORKDIR /home/node
ENTRYPOINT []
CMD ["node", "--version"]
