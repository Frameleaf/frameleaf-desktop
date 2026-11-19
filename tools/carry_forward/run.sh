#!/bin/sh
# Builds the proof image and runs the carry-forward test in it. See README.md.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repository=$(cd "$here/../.." && pwd)
image=${FRAMELEAF_CARRY_IMAGE:-frameleaf-carry-forward-proof:local}
docker build -t "$image" ${FRAMELEAF_CARRY_SERVER_IMAGE:+--build-arg "SERVER_IMAGE=$FRAMELEAF_CARRY_SERVER_IMAGE"} \
  ${FRAMELEAF_CARRY_JOBS:+--build-arg "JOBS=$FRAMELEAF_CARRY_JOBS"} "$here"
# /small is a 2 GiB volume for the too-little-room case; everything else lives in the container.
# --init: something has to reap the processes the killed-export case leaves behind.
exec docker run --rm --init --tmpfs /small:size=2g,uid=1000,gid=1000,mode=0700 \
  -v "$repository/runtime:/work/runtime:ro" -v "$here:/work/tools/carry_forward:ro" \
  -e FRAMELEAF_CARRY_E2E=1 -e FRAMELEAF_CARRY_SMALL=/small \
  "$image" node --test --test-concurrency=1 --test-force-exit /work/tools/carry_forward/e2e.mjs
