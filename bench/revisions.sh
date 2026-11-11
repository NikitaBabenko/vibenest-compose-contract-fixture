#!/bin/sh
set -eu
mode="$1"
image="$2"
dir=.vibenest-revision
render() { docker run --rm -i --entrypoint python3 "$image" /revision_render.py "$1"; }
up() { docker compose --project-directory . -f "$1" up -d --no-build --pull never --wait --wait-timeout 20; }
verify() {
  (cd "$dir" && sha256sum -c "$1.sha256")
  # Fail before runtime effects if a pinned image is missing; never pull/rebuild it.
  for ref in $(render images < "$dir/$1.json"); do
    test "$(docker image inspect --format '{{.Id}}' "$ref")" = "$ref"
  done
  docker compose --project-directory . -f "$dir/$1.json" config --quiet
}
case "$mode" in
  seed|prepare)
    # A repeated prepare must not overwrite a retained immutable receipt.
    test ! -e "$dir/retained.json"
    test ! -e "$dir/prepared.json"
    mkdir -p "$dir"
    docker compose --project-directory . -f docker-compose.yaml config --format json | render "$mode" > "$dir/candidate.tmp"
    test -s "$dir/candidate.tmp"
    for ref in $(render images < "$dir/candidate.tmp"); do
      docker image inspect --format '{{.Id}}' "$ref"
    done > "$dir/images.tmp"
    { cat "$dir/candidate.tmp"; printf '\n'; cat "$dir/images.tmp"; } | render pin > "$dir/prepared.json"
    (cd "$dir" && sha256sum prepared.json > prepared.sha256)
    verify prepared
    echo VIBENEST_REVISION_PREPARED_NO_RUNTIME
    if [ "$mode" = seed ]; then
      up "$dir/prepared.json"
      render retain < "$dir/prepared.json" > "$dir/retained.json"
      (cd "$dir" && sha256sum retained.json > retained.sha256)
    fi
    ;;
  activate|fault)
    verify prepared
    if [ "$mode" = fault ]; then
      render fault < "$dir/prepared.json" > "$dir/fault.json"
      echo VIBENEST_REVISION_PREPARED_FAULT_BEFORE_WEB_WRITES
      up "$dir/fault.json"
    else
      up "$dir/prepared.json"
    fi
    ;;
  resume)
    verify retained
    echo VIBENEST_REVISION_RESUME_EXACT_ARTIFACT
    up "$dir/retained.json"
    ;;
  *) exit 64 ;;
esac
