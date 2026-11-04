#!/bin/sh
set -eu
mode="$1"
image="$2"
case "$mode" in
  build) output=.vibenest-build.json ;;
  start) mkdir -p .vibenest-final; output=.vibenest-final/effective.json ;;
  *) exit 64 ;;
esac
# The provider has already inserted its labels, image names and network identities.
docker compose --project-directory . -f docker-compose.yaml config --format json | docker run --rm -i "$image" > "$output.tmp"
test -s "$output.tmp"
mv "$output.tmp" "$output"
if [ "$mode" = build ]; then
  docker compose --project-directory . -f "$output" build
  docker compose --project-directory . -f "$output" pull --ignore-buildable
else
  docker compose --project-directory . -f "$output" up -d
fi
