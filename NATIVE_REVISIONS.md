# Native two-resource feasibility scenario

This is a separate experiment. The single-resource run42996466987 at1a86a8a and
its negative conclusions remain unchanged. No provider patch is installed.

Dispatch `.github/workflows/contract.yml` on the exact approved source ref with
`scenario=native-revisions`. Only the release coordinator dispatches after a fresh
budget check. Estimated duration5–8 minutes from the preceding4m05s single-resource
run: one disposable ubuntu-latest VM, two synthetic provider applications, six
native deployments and serialized stops, no product hardware, tokens or quotas.
The existing workflow timeout is25 minutes; no retries or concurrent second run.

## Concrete native API questions

1. Can create with instant_deploy=false create a candidate with no runtime?
2. Can normal native build plus a prepare-only custom start persist a sanitized,
   image-ID-pinned artifact without candidate containers or changes to the old app?
3. Can explicit external named volumes on the same host survive both resource
   lifecycles with exact volume/mount identity?
4. After native stop and engine evidence of no live shared-volume users, can the
   candidate start its prepared images using custom build=true and custom start
   with no-build/pull-never? HTTP is checked on separate diagnostic fixture domains;
   this does NOT test the platform route CAS.
5. Can the old resource recover exact retained image digests/config through native
   restart with a no-op custom build and verified retained config resume? Native
   restart ALONE is insufficient: provider4.7.5 disables restart_only for Compose.
6. After candidate web exits42 before application-file writes, can a separate
   explicit recovery stop/reconcile all candidate writers and resume old images?
   The fixture has no schema migration; same-source web and same-image Redis have
   known synthetic data compatibility. Redis may write its normal AOF metadata.

All runtime creation/stopping is through native provider application endpoints and
their custom build/start commands. The host-side bench uses Docker only for reads
(inspect, volume existence, events); it never invokes Docker run/up/start/stop/rm
to repair an application. The provider-invoked helper remains a disposable contract
prototype, not an authenticated production helper or an alternative deploy adapter.

## Evidence and failure behavior

The helper retains resolved runtime config and pins local image IDs, drops build
instructions and uses pull_policy=never. Retained mounts are external so missing
volumes fail instead of creating empty replacements. Checksums detect drift; these
are NOT cryptographic authorization or a production receipt service.

Before every deliberate successor start the bench verifies native source identity,
artifact digest and no live users of either volume on this isolated host. Failure
or unknown API outcome raises immediately; no exception handler triggers rollback.
The expected fault has a separate, explicit recovery phase after confirmed exit42,
native stop and no-writer observation. Data is never restored/rewound automatically.

A continuous sanitized Docker event stream verifies stop-before-start ordering of
web and Redis across both provider resources, plus first and last observed container
identities. This proves only this serialized benign trace. It does not implement
writer fencing against another Cloud user, queued start, crash/retry or hostile actor.
No platform owner/security/admission gate is emulated. `productionEnablementAllowed`
is always false; route CAS, private GitHub App, authenticated artifacts and Cloud
binary parity remain separate acceptance items even if every primitive passes.

If a primitive fails, report its exact checkpoint and evidence as unproven/blocked.
Do not remove assertions or stateful production guards to manufacture success.

## First attempt and bounded correction

Run42999097437 (d798cfe9) stopped during the first baseline build, before any
two-resource checkpoint. Coolify injectDockerComposeBuildArgs inserted build-arg
pairs between the wrapper's build verb and helper image positional argument.
The Docker invocation therefore mistook --build-arg for its image. This is a
fixture command-contract defect, not evidence that native revisions cannot work.

The corrected native build invocation puts image and project-directory before
the build verb and forwards all injected trailing arguments verbatim to Compose
build, without eval or argument logging. A local shell test invokes the actual
helper with a Docker stub using the observed prefix/hash argument shape, and
checks values containing spaces and shell metacharacters remain single arguments.
VN_CONTRACT_VOLUME_PREFIX is explicitly runtime-only; injection correctness does
not depend on an empty build-time environment or absent synthetic hash.

At provider source378ce373, ApplicationsController:5074 dispatches StopApplication
with its default removeContainers=true. The action issues stop followed by rm -f.
The corrected probe requires actual runtime=[] after every native stop, records
that checkpoint, and rejects even stopped containers referencing shared volumes.
Native docker_cleanup=false prevents asynchronous cleanup during this bounded
retained-artifact experiment. Candidate create/prepare likewise require no
containers, including exited ones. These are observations of serialized actions;
durable platform fencing and admission for future queued commands remain required.

Run43001552784 (04873799) reached ENV creation and failed422 before deployment:
the fixture incorrectly used is_build_time. The exact provider create_env validator
accepts is_buildtime and rejects every unknown field (ApplicationsController at
the pinned378ce3735c source,4655–4694). Corrected to is_buildtime=false; runtime
defaults true in the same method. A local AST-based check validates the actual ENV
request against that vendor allowed-field set before another costly runner boot.
HTTP errors now retain only status and validation field names, never raw values.

Run43002577130 (b349c5a) passed ENV setup and the old seed deploy, including web/Redis
HTTP, mounts and pinned artifact creation. It then failed an over-strict raw URL
comparison at fresh_identity; candidate creation was not reached. Pinned source
1936–1939 explicitly converts a public GitHub URL to owner/repository + source id0.
The next correction checks those exact equivalent representations and source
binding, never suffix/host normalization; branch/commit/UUID remain strict.
Individual identity outcomes are saved before asserting, including a pre-build
check immediately after create. No next run is automatically dispatched.
