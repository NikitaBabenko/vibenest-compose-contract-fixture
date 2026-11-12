FROM node:24-alpine
WORKDIR /app
ARG FIXTURE_BUILD_ALLOWED
# Hostile-build probes: a RUN layer must not see helper files or transport ENV.
RUN { test "$FIXTURE_BUILD_ALLOWED" = 'allowed-build-dollar$fixture' || { echo 'FIXTURE_BUILD_PROBE argument' >&2; exit 1; }; } \
 && { test ! -e /artifacts/build-time.env || { echo 'FIXTURE_BUILD_PROBE artifact-path' >&2; exit 1; }; } \
 && { test ! -e /tmp/vn-private/session.json || { echo 'FIXTURE_BUILD_PROBE session-path' >&2; exit 1; }; } \
 && node -e "if(Object.keys(process.env).some(k=>k.startsWith('VN_ARTIFACT_'))){console.error('FIXTURE_BUILD_PROBE transport-env');process.exit(75)}"
COPY --chown=node:node private-app/server.mjs /app/server.mjs
# Leave the named volume itself untouched. Docker create performs image-directory
# copy-up, including ownership, before the inspected non-root container can start.
RUN mkdir /app/data && chown node:node /app/data && chmod 0700 /app/data
USER node
EXPOSE 3000
CMD ["node", "/app/server.mjs"]
