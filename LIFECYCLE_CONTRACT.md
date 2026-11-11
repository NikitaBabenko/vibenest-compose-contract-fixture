# Compose lifecycle regression, Coolify 4.7.5

This is a disposable, public, synthetic web/Redis fixture. It does not load
production credentials, private repositories, application data or platform hardware.
The manual-only workflow must be scheduled by the release coordinator after a fresh
budget check. Do not use bootstrap.py against a persistent machine.

Provider compose files are read at public source commit
`378ce3735c4522ebb6b68e93b909b0511f278763` (v4.7.5). The runtime image ID and registry
digests are recorded; the API version must match. This does not establish binary
parity with the managed Cloud control plane, whose digest is unavailable.

The normal deploy/restart/redeploy checks still verify HTTP, Redis, storage identity,
data markers and resource limits. The two negative cases then run independently:

1. `false` as the custom start command: no candidate process is launched. Every old
   service/container/image, HTTP state and restart-config fingerprint must survive.
2. Native reset of the disposable baseline, then custom `failstart`: render and
   validate the prepared configuration, invoke Compose up with `--wait`, and start
   a synthetic web entrypoint which exits 42 before opening any data file. This
   distinguishes a real start failure after preparation from an early validation
   refusal. Its restart policy is disabled to avoid a crash loop. The baseline reset
   is a test setup operation, not a product recovery implementation.

Both case artifacts are saved before the final red assertion. Evidence includes
exact old/new container and image IDs, config hashes (never contents), provider
deployment IDs, HTTP responses and sanitized Docker lifecycle events. No automatic
recovery is attempted after an unknown API outcome. Missing data is not success.

The test requires preservation of the old IDs because native retained-revision
recovery is not implemented by this fixture. A future authorized recreation path
would require a different exact-image/config/volume acceptance check and fresh
platform security/owner/source/artifact authority, not weakening this comparison.
Snapshot equality and event collection alone do not certify absence of all concurrent
writers; `singleWriterAcceptance` remains `not_certified`.

`productionEnablementAllowed` remains false even if these checks pass. Private source,
authenticated artifact integration, durable receipts, cancellation, lost ACKs,
single-writer exclusion and reconciled gated recovery require separate acceptance.
If a candidate wrote unknown or incompatible state, preserve evidence and fail closed.
Never roll back data automatically or claim arbitrary database migrations are reversible.

Local checks (no containers):

```sh
python3 -m unittest discover -s bench -p 'test_*.py' -v
```

Current public provider source still calls force removal before custom start. A
successful build-time precheck cannot make a later custom-start refusal safe.
A self-hosted provider patch cannot be rolled out into managed Coolify Cloud by
releasing the client application. This fixture is a regression/reproduction package,
not a production fix.
