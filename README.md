# Disposable Coolify Compose contract fixture

Manual-only GitHub Actions bench for Coolify 4.7.5. It uses a fresh runner and
ephemeral credentials, with no access to VibeNest production. The fixture is a
small Node web server plus Redis; all persistent data is synthetic.

This tests a candidate custom-command mechanism, not a released VibeNest feature.
The prototype is not a production helper: artifact authentication, policy and
durable project/attempt storage bindings belong to the platform implementation.
No success result here alone authorizes enabling GitHub App Compose on production.

See LIFECYCLE_CONTRACT.md for the single-resource negative tests and
NATIVE_REVISIONS.md for the separately scheduled two-resource feasibility scenario.
