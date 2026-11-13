#!/usr/bin/env bash
# End-to-end run of Desktop's local-Manager code against a real Manager, photo server and
# database, in Docker. Opt-in; see README.md beside this file.
#
#   tools/manager_e2e/run.sh COMPANION_DIRECTORY CAPABLE_REVISION [PLAIN_REVISION]
#
# COMPANION_DIRECTORY holds the released Linux companion's *_bootstrap.deb and *_runtime.deb.
# CAPABLE_REVISION is a Frameleaf/frameleaf-app commit whose Manager declares the native
# capabilities; PLAIN_REVISION one whose Manager declares none (a released Manager).
set -euo pipefail
[[ $# -ge 2 ]] || { sed -n '2,10p' "$0" >&2; exit 2; }
companion=$(cd "$1" && pwd) capable=$2 plain=${3:-}
repository=$(cd "$(dirname "$0")/../.." && pwd)
name=${FRAMELEAF_MANAGER_E2E_NAME:-frameleaf-manager-e2e}
inside() { docker exec -e FRAMELEAF_MANAGER_E2E_SHORT -e FRAMELEAF_MANAGER_E2E_SERVER "$name" bash /src/tools/manager_e2e/inside.sh "$@"; }

docker build --platform linux/amd64 -t "$name" -f "$repository/tools/manager_e2e/Dockerfile" "$companion"
docker volume create "$name-cache" > /dev/null
docker rm -f "$name" > /dev/null 2>&1 || true
# Library profiles hold a database, which the controller admits only on a real local filesystem;
# a container's own root is an overlay. A fresh volume each run: every library starts new.
docker volume rm "$name-profiles" > /dev/null 2>&1 || true
docker volume create "$name-profiles" > /dev/null
docker run -d --name "$name" --platform linux/amd64 -v "$repository:/src:ro" -v "$name-cache:/cache" \
  -v "$name-profiles:/opt/frameleaf/Profiles" "$name" sleep infinity > /dev/null

inside build
inside assemble capable "$capable" 1000
[[ -z $plain ]] || inside assemble plain "$plain" 999

failed=0
try() { inside run "$@" || { failed=1; echo "FAILED: $*"; }; }
try released a_manager_that_declares_nothing_is_started_exactly_as_before
[[ -z $plain ]] || try plain a_manager_that_declares_nothing_is_started_exactly_as_before
try capable photos_open_only_while_manager_reports_its_controller_serving_them
try capable each_busy_port_moves_and_every_consumer_follows_the_saved_port
try capable the_tls_identity_is_renewed_and_no_refused_handover_leaves_the_library_stopped
try capable a_library_moved_from_the_released_companion_uses_what_the_new_manager_declares released
try capable a_port_moved_for_a_start_manager_refuses_does_not_stay_moved
try capable an_unfinished_operation_does_not_stop_an_identity_from_being_renewed
try capable 'a_crash_leaves_manager_running_on_its_moved_port the_next_run_finds_the_manager_a_crash_left_on_its_moved_port'
echo "Remove what this made with: docker rm -f $name; docker volume rm $name-cache $name-profiles; docker image rm $name"
exit "$failed"
