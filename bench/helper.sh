#!/bin/sh
set -eu
# Put the helper image BEFORE the build verb: Coolify 4.7.5 injects
# --build-arg pairs immediately after that verb, even in a shell wrapper.
# Preserve those arguments verbatim for the actual Compose build (never eval).
case "$1" in
  build|start|failstart) mode="$1"; image="$2"; set -- ;;
  *)
    image="$1"
    test "$2" = --project-directory && test "$3" = . && test "$4" = build
    mode=build
    shift 4
    ;;
esac
case "$mode" in
  build) output=.vibenest-build.json ;;
  start|failstart) mkdir -p .vibenest-final; output=.vibenest-final/effective.json ;;
  *) exit 64 ;;
esac
# The provider has already inserted its labels, image names and network identities.
if [ "$mode" = build ]; then
  docker compose --env-file /artifacts/build-time.env --project-directory . -f docker-compose.yaml config --no-env-resolution --format json | docker run --rm -i "$image" build > "$output.tmp"
else
  docker compose --project-directory . -f docker-compose.yaml config --format json | docker run --rm -i "$image" "$mode" > "$output.tmp"
fi
test -s "$output.tmp"
mv "$output.tmp" "$output"
if [ "$mode" = build ]; then
  docker compose --project-directory . -f "$output" build "$@"
  docker compose --project-directory . -f "$output" pull --ignore-buildable
elif [ "$mode" = failstart ]; then
  # This synthetic web process exits before opening the RW volume. This is NOT
  # a validation refusal: Compose actually attempts replacement and startup.
  docker compose --project-directory . -f "$output" config --quiet
  echo VIBENEST_CONTRACT_PREPARED_NO_CANDIDATE_WRITES
  docker compose --project-directory . -f "$output" up -d --wait --wait-timeout 20
else
  docker compose --project-directory . -f "$output" up -d
fi
