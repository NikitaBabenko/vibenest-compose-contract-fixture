#!/bin/sh
set -eu
stage=loader-entry
trap 'if [ "$?" -ne 0 ]; then printf "FIXTURE_REFUSAL %s\n" "$stage" >&2; fi' 0
set +a
unset VN_ARTIFACT_CAPABILITY
umask 077
# Public, hash-verified code only. No bearer ever appears in argv or a URL.
test "$#" = 7
origin=$1; ca_url=$2; ca_digest=$3; helper_digest=$4; helper_size=$5
test "$6" = --project-directory && test "$7" = .
case "$PWD" in /artifacts/*) deployment=${PWD#/artifacts/} ;; *) exit 64 ;; esac
case "$deployment" in ''|*[!a-zA-Z0-9_-]*) exit 64 ;; esac
case "$ca_digest$helper_digest" in *[!a-f0-9]*) exit 64 ;; esac
test "${#ca_digest}" = 64 && test "${#helper_digest}" = 64
case "$helper_size" in ''|*[!0-9]*) exit 64 ;; esac
test "$helper_size" -gt 0 && test "$helper_size" -le 16777216
test ! -e /tmp/vn-private
mkdir -m 700 /tmp/vn-private
stage=loader-ca-fetch
curl -q -fsS --noproxy '*' --max-time 20 --max-filesize 8192 --proto '=http' "$ca_url" -o /tmp/vn-private/ca.pem
stage=loader-ca-pin
printf '%s  /tmp/vn-private/ca.pem\n' "$ca_digest" | sha256sum -c - >/dev/null
# Read exactly one reserved scalar; never source provider/user ENV as shell code.
stage=loader-capability-read
capability=$(awk -F= '$1=="VN_ARTIFACT_CAPABILITY" {n++; v=substr($0,index($0,"=")+1)} END {if(n!=1) exit 1; print v}' /artifacts/build-time.env)
case "$capability" in \"*\") capability=${capability#\"}; capability=${capability%\"} ;; \'*\') capability=${capability#\'}; capability=${capability%\'} ;; esac
test "${#capability}" = 64
case "$capability" in *[!a-f0-9]*) exit 64 ;; esac
printf '%s' "$capability" > /tmp/vn-private/delivery
printf 'header = "Authorization: Bearer %s"\nheader = "X-Fixture-Deployment: %s"\n' "$capability" "$deployment" > /tmp/vn-private/curl.cfg
unset capability
stage=loader-helper-delivery
attempt=0
while :; do
  attempt=$((attempt+1))
  if curl -q -fsS --noproxy '*' --max-time 30 --max-filesize "$helper_size" --proto '=https' --tlsv1.3 --cacert /tmp/vn-private/ca.pem --config /tmp/vn-private/curl.cfg "$origin/v1/bootstrap/helper" -o /tmp/vn-private/helper; then break; fi
  test "$attempt" -lt 3 || exit 65
  sleep 1
done
rm /tmp/vn-private/curl.cfg
stage=loader-helper-pin
test "$(wc -c < /tmp/vn-private/helper | tr -d ' ')" = "$helper_size"
printf '%s  /tmp/vn-private/helper\n' "$helper_digest" | sha256sum -c - >/dev/null
chmod 700 /tmp/vn-private/helper
stage=loader-helper-exec
exec /tmp/vn-private/helper helper --phase=load --origin="$origin"
