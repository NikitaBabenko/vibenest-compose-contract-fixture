FROM node:24-alpine
WORKDIR /app
ARG FIXTURE_BUILD_ALLOWED
# Hostile-build probes: a RUN layer must not see helper files or transport ENV.
RUN test "$FIXTURE_BUILD_ALLOWED" = 'allowed-build-dollar$fixture' && test ! -e /artifacts/build-time.env && test ! -e /tmp/vn-private/session.json && node -e "if(Object.keys(process.env).some(k=>k.startsWith('VN_ARTIFACT_')))process.exit(75)"
COPY --chown=node:node private-app/server.mjs /app/server.mjs
# Leave the named volume itself untouched. Docker create performs image-directory
# copy-up, including ownership, before the inspected non-root container can start.
RUN mkdir /app/data && chown node:node /app/data && chmod 0700 /app/data
USER node
EXPOSE 3000
CMD ["node", "/app/server.mjs"]
