#!/bin/sh
# Scrumboy dispatches private-native with an independently supplied reviewed SHA.
# Guarded disposable entrypoint; must never run on a customer host.
set -eu
test "${GITHUB_ACTIONS:-}" = true
test "${VN_PRIVATE_DISPOSABLE:-}" = 1
test "${VN_PRIVATE_REVIEWED_SHA:-}" = "${GITHUB_SHA:?}"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test "${GITHUB_REPOSITORY:-}" = NikitaBabenko/vibenest-compose-contract-fixture
test "$(uname -s)" = Linux
test -z "${DOCKER_HOST:-}${DOCKER_CONTEXT:-}${DOCKER_TLS_VERIFY:-}"
test "$(awk '/MemAvailable/{print $2}' /proc/meminfo)" -gt 4000000
test "$(df -Pk . | awk 'NR==2{print $4}')" -gt 15000000
if docker inspect coolify >/dev/null 2>&1; then
  echo 'Fresh disposable host required' >&2
  exit 65
fi
test ! -e /tmp/vn-private-toolchain
umask 077
mkdir /tmp/vn-private-toolchain
# Fetch the archive from the HTTPS download endpoint, avoiding the go.dev redirect.
curl -fsS --max-time 120 --proto '=https' https://dl.google.com/go/go1.27.4.linux-amd64.tar.gz -o /tmp/vn-private-toolchain/go.tar.gz
printf '%s  /tmp/vn-private-toolchain/go.tar.gz\n' 7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 | sha256sum -c -
tar -xzf /tmp/vn-private-toolchain/go.tar.gz -C /tmp/vn-private-toolchain
export GOTOOLCHAIN=local GOENV=off GOPROXY=off GOSUMDB=off GOMAXPROCS=2 CGO_ENABLED=0
export GOCACHE=/tmp/vn-private-toolchain/cache GOPATH=/tmp/vn-private-toolchain/path
(cd bench/private && /tmp/vn-private-toolchain/go/bin/go test -p 1 ./... && /tmp/vn-private-toolchain/go/bin/go build -p 1 -trimpath -buildvcs=false -ldflags='-s -w' -o /tmp/vn-private-toolchain/native ./cmd/native)
python3 -m unittest discover -s bench -p 'test_*.py'
python3 bench/bootstrap.py
docker build -f bench/private-render.Dockerfile -t vn-private-render:local .
utility_image=$(docker image inspect --format '{{.Id}}' vn-private-render:local)
# No legacy collect.py invocation: it is not a private-canary-safe collector.
python3 bench/private_native.py /tmp/vn-private-toolchain/native "$utility_image"
