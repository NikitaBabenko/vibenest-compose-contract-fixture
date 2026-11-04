FROM node:24-alpine
WORKDIR /app
COPY server.mjs .
EXPOSE 3000
CMD ["node","server.mjs"]
