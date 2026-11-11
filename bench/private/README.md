# Private transport fixture: offline foundation

This is a separate, locally reviewed foundation for the proposed `private-transport`
scenario. It is **not yet a dispatchable native Coolify scenario**. The existing
`single` and passing `native-revisions` workflow options are unchanged. No Actions,
push, production calls, customer project operations, or Docker image builds were
performed while preparing this package.

## Implemented and locally exercised

- Go standard-library capability store and TLS client/handler: random 256-bit
  capabilities; hashes in the grant index; exact immutable scope; one-time binding
  of a previously unknown native deployment UUID; finite delivery reads; expiry and
  explicit revocation; separate one-shot artifact submission with read-only
  lost-response receipt lookup; no redirect or system-proxy fallback.
- Backend-held AES-256-GCM effective config, bound to the full scope as AAD. The
  retained object survives grant revocation. Plaintext config and backend keys do
  not appear in receipt responses. This backend is **in-memory for one disposable
  runner process**, not a durable production store.
- Strict JSON checks reject duplicates, trailing values, unknown typed fields,
  oversize bodies and excessive depth. Config/image/mount authenticity remains a
  separate native observation responsibility; successful upload is not host PoP.
- `../private_storage.py`: a narrow exact-forward adapter for pinned Coolify4.7.5
  parser5, production ordinary volume keys `app-data` and `redis-data`. It refuses
  unknown versions, previews, aliases, extras and unsupported declaration/mount
  options. Service source keys remain unchanged; only the verified top-level
  declaration is rebound to the independently supplied retained physical name.
- Pure typed NewCreate / RetainedInspect / ReconcileUnknown decisions. Missing
  retained storage never becomes create. These functions **do not journal or
  dispatch anything**, authenticate receipts, or lock the observation interval.
- Pure pre-start inspect validator for exactly two created, never-started
  containers with expected image IDs, mounts, limits, non-root web and no host
  exposure. It returns `productionStartAuthorized=false`.
- `../private_leaks.py`: raw in-memory canary matching including encoded,
  split-line and partial representations; output contains only fixed categories,
  byte counts and hashes. This is a scanner primitive, **not a completed collector**.
- Separate `../../private-app/` + `../../private-compose.yaml`: real SQLite WAL
  state and Redis SET/GET sentinel; Redis seeds only on first SQLite creation.
  Existing state with missing Redis refuses instead of reseeding. Fault42 runs
  before opening SQLite. The image uses `USER node` and an empty owned data
  directory, leaving Docker create to perform ordinary volume copy-up.

## Local evidence and limits

The Python regression suite includes all62 previous tests and12 new tests.
Go tests cover scope changes, wrong/missing/expired/revoked/spent grants, role
separation, concurrent one-shot submission, encryption/AAD tampering, TLS trust,
redirect/size/hash refusal and ambiguous JSON. The Node tests use real local
SQLite and an explicitly labelled RESP test double: they prove restart behavior,
no Redis reseed and fail-before-write ordering, **not Redis AOF persistence**.

Local Node is26.7.0; the target Docker image is Node24. Target version parity,
Linux non-root execution and Docker copy-up are still required in the isolated
run. Go uses pinned official1.27.4, GOTOOLCHAIN=local, GOPROXY=off, GOENV=off,
GOMAXPROCS=2 and `go test -p 1`. No system toolchain installation is needed.

## Native integration still required before adding a workflow option

1. Hash-verified public bootstrap and private helper executable; actual provider
   command validator/rewriter tests, including its1000-character boundary. The
   repository URL contains `compose`, so an explicit supported
   `--project-directory` strategy must be verified, not assumed neutral.
2. Runner-local TLS broker lifecycle, ephemeral CA distribution/pinning, strict
   private temp files outside the native source context, bounded server header /
   read / write timeouts and sanitized failures. The HTTP handler alone is not a
   deployable server. No source/archive/mirror delivery slot is permitted.
3. Native clone exact-SHA verification and discovery before final settings freeze;
   runner-observed provider parser/storage/normalized digests. The mapping adapter
   verifies a restricted shape, **not the provenance of caller-authored input**.
4. Durable create intent/nonce, fresh complete host inventory, exactly-once
   NewCreate dispatch in native helper and separate read-only unknown-ACK
   reconciliation. Do not write markers into fresh volumes before Docker create.
5. Buildtime-only literal capability ENV and separate submission delivery;
   revoke/scrub before hostile user RUN across provider ENV, build-time.env,
   generated Dockerfiles/Compose ARG/secrets, launchers and subprocess environment.
   Keeping a submission capability outside context needs actual isolation proof.
6. No-preserve helper disposal, fresh-job backend rehydration, exact images with no
   rebuild/pull, changed provider ENV and real dollar/newline re-resolution checks.
   `literal_safe` is only a candidate escaping transform until the target Compose
   binary round-trip matches the frozen model.
7. Native create-without-start followed by fresh actual mount/limit/image inspection,
   HTTP-unreachable check and only then start. Independent runner observations,
   quiescence, retained missing-volume refusal and failure recovery remain required.
8. Full/hidden logs, commands, generated context/args, image history/layers and
   runtime ENV must feed the scanner **before** any redaction/export. Do not use
   legacy `collect.py` for private canaries until it is integrated safely.
9. Real non-root SQLite + Redis AOF sentinel across activation/recovery, preserved
   physical volumes and exact image/config identity. Public synthetic data only.

Production admission, authenticated host evidence, route CAS, concurrent external
writer fencing, cloud binary parity and private App acceptance remain unproved.
Scrumboy alone dispatches a reviewed exact revision after resource/budget preflight.
