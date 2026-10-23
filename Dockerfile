# ZeroByte Relay, self-hosted. No dependencies beyond Node itself.
#
#   docker build -t zerobyte-relay .
#   docker run -p 8080:8080 -v relay-data:/data \
#     -e RELAY_APPS=<app id>[,<app id>...] zerobyte-relay
#
# Put TLS in front of it; deploy/Caddyfile is one way.

FROM node:24-alpine

WORKDIR /app
COPY package.json LICENSE NOTICE ./
COPY bin ./bin
COPY src ./src

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    RELAY_DATA=/data/relay.sqlite

RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8080

CMD ["node", "bin/zerobyte-relay.js"]
