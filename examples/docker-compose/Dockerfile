FROM ghcr.io/capyshield/capyshield:latest AS capyshield

FROM node:22-alpine
COPY --from=capyshield /usr/local/bin/capyshield /usr/local/bin/capyshield
WORKDIR /app
COPY . .
RUN capyshield guard --config capyshield.yaml -- npm ci --omit=dev
# Every process started from this image runs behind the egress guard.
ENTRYPOINT ["capyshield", "guard", "--config", "/app/capyshield.yaml", "--"]
CMD ["node", "server.js"]
