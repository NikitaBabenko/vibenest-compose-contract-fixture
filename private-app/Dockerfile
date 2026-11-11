FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node private-app/server.mjs /app/server.mjs
# Leave the named volume itself untouched. Docker create performs image-directory
# copy-up, including ownership, before the inspected non-root container can start.
RUN mkdir /app/data && chown node:node /app/data && chmod 0700 /app/data
USER node
EXPOSE 3000
CMD ["node", "/app/server.mjs"]
