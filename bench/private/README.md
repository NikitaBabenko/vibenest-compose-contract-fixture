# Native private transport fixture — candidate for isolated review

The runnable candidate entrypoint is `../run-private-native.sh`. **It has not run
against Docker/Coolify.** Local protocol/render/evidence tests do not prove native
transport, workload identity, production authority or cloud compatibility.

The existing `single` and previously passing `native-revisions` workflow options
are unchanged. This candidate is not wired to Actions until review. No push,
workflow dispatch, laptop image build or production call was performed. Scrumboy
alone dispatches a reviewed exact commit after resource/budget preflight.

## Entrypoint and isolation

Requires a fresh Linux Actions host, the exact fixture repository,
`GITHUB_SHA == VN_PRIVATE_REVIEWED_SHA == git HEAD`, `VN_PRIVATE_DISPOSABLE=1`, local
Docker with no remote-context environment override, at least4GB free RAM and15GB
free disk, and no existing Coolify container. It bootstraps the pinned4.7.5 provider,
builds the static helper/broker and immutable renderer utility, then invokes the
native harness. Images are built only on this explicitly disposable runner.

Go1.27.4 is pinned to its official archive SHA256, standard library only, with
GOTOOLCHAIN=local, GOENV=off, GOPROXY=off, GOMAXPROCS=2 and `-p 1`. Windows local
tests use a verified portable toolchain, without global installation/PATH changes.

The native helper/broker are Go. Rendering is **the fixture's private_render.py +
private_storage.py**, executed inside its separately built immutable Python utility
container. It is not the platform Python renderer2.0.0. Python is not assumed to
exist in the Coolify helper. `implementation-identity.json` records exact Go/helper
source hashes, runtime Linux helper SHA256/size, loader SHA256, renderer source
hashes and utility image ID, with platform-renderer participation explicitly false.
The Linux binary hash is unknown until that runner build; no binary-parity claim
is inferred from Windows unit compilation. A future production package/port needs
its own exact-binary contract and acceptance.

## Implemented sequence — all native assertions await actual execution

1. Real PHP validator and command rewriting checks, including999/1000/1001 lengths.
   Commands have no capability, standalone build verb or `docker compose` text.
   The repository URL contains `compose`; an explicit `--project-directory .`
   marker must prevent rewriting, as checked by the actual provider functions.
2. Broker management uses private stdin/stdout pipes, not HTTP admin or public
   logs. Only the public certificate uses HTTP; its SHA256 is embedded in the
   trusted command. Bearer requests use TLS1.3 and an isolated pinned CA pool.
   No redirects, proxy trust or unverified private executable is allowed.
3. Hash-verified public bootstrap reads exactly one64-hex build-only capability
   from build-time.env without sourcing it. Mode0600 curl config keeps it out of
   argv/URLs. Byte/time/read bounds apply. Runner binds the native deployment UUID
   after dispatch ACK before any redemption. Separate one-shot submission follows.
4. Native clone is the sole application source. Coolify removes `.git` before the
   custom command, so no rev-parse/refetch fallback is used. Digest-only manifest
   checks exact files/Git modes and rejects omissions, extras, symlinks and escapes.
   Generated Compose and modified Dockerfile are separate narrow allowances.
   Only the exact two provider ARG insertions immediately after FROM are removed
   for the original-body hash; original ARGs/commands retain their exact positions.
   Native application and actual queue commit identities are read back/recorded.
5. The narrow fixture profile is parser5/nonraw/no-preserve/no-build-server/
   use_build_secrets=false. Explicit ENV flags receive metadata-only readback.
   Default/source-commit build variables and global App domain are disabled only
   for this disposable fixture, leaving two explicit build keys. No Legacy defaults
   or real application ENV are changed.
6. Runner fsyncs typed draft NewCreate intents/nonces before dispatch. Native helper
   reads full volume-name inventory and creates only assigned local named volumes.
   RetainedInspect never creates. No marker precedes Docker create/copy-up. Lost
   create ACK remains unknown, with no automatic retry or new-name allocation.
7. Delivery is revoked/scrubbed before user build. Child environment is fixed. The
   synthetic Dockerfile checks an allowed dollar-containing build value and probes
   inaccessible helper files/transport ENV. Child output is bounded/scanned in
   memory, reduced to fixed stage/hash/count logs. Renderer has no mounts/network,
   no log driver, exact image ID, resource bounds and no pull fallback.
8. Preparation resolves native runtime ENV, freezes exact images/config and submits
   once. Backend holds AES256-GCM ciphertext with full scope AAD. This in-memory
   disposable backend survives helper disposal; it is not a durable platform store.
9. Activation/recovery use fresh native jobs/grants, backend rehydrate and exact
   local images, without user rebuild/pull fallback. Changed provider ENV must not
   alter frozen dollar/newline values; Compose re-resolution must match.
10. Helper creates without start and waits. Runner independently checks stopped
    containers' actual image/mount/RW/limits/non-root user, no host ports and HTTP
    unreachability before releasing this test step. This is not platform admission
    or host PoP. Record helper removal, actual Compose version/flags and complete
    before/after volume-name inventory; competing physical volumes fail the test.
11. Real SQLite WAL and Redis SET/GET/AOF sentinels must survive activation and exact
    recovery. Only first SQLite creation seeds Redis. Fault42 precedes DB open.
    Revoked provider-only restart must refuse without replacing the old writer.
    Missing retained-target injection must refuse without creating a replacement,
    while preserving the original physical data.
12. Scan raw hidden/persisted provider logs, helper context/build env, image history
    and complete uncompressed layer archives, runtime Env and exported evidence.
    Capability is forbidden in application context/images/runtime. Random user
    runtime ENV is expected in runtime/private config but forbidden in image/log/
    public evidence. Export only fixed categories, counts and digests.

## Proof limits

- The restricted forward adapter does not implement the separately owned platform
  v2 mapping sidecar/ledger. Extra declarations refuse; no suffix/omission guessing.
- Helper/settings slots contain no app source/archive/mirror. Manifests are hashes
  and metadata only. Upload proves capability possession; runner observation is
  separate disposable evidence, not authenticated production host provenance.
- Exact typed JSON casing, duplicates, invalid UTF-8, lone/mismatched surrogates,
  trailing values and excessive nesting are checked. User config maps remain
  case-sensitive. This is not universal cross-language numeric canonicalization.
- Native cancel/lost-create-ACK reconciliation and every hostile provider failure,
  encoding or external-writer race are not exhaustively certified. Unknown outcomes
  never trigger automatic launch/recovery. Happy-path success cannot close all
  remaining acceptance/security matrix items.
- Local Node tests use real SQLite and a labelled RESP double; local Node26 differs
  from target Node24. Actual Linux non-root ownership/copy-up, Redis AOF, helper
  networking/tools, validator behavior and end-to-end flow await the isolated run.
- Production enablement, owner/security/admission, authenticated host observation,
  route CAS, concurrent external-writer fencing and cloud/private App parity remain
  false/unknown. No customer project, credential or ENV is used.
