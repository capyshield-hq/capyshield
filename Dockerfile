FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p capyshield

FROM alpine:3
LABEL org.opencontainers.image.title="capyshield" \
      org.opencontainers.image.description="Deterministic zero-trust egress guard and local VEX/reachability engine" \
      org.opencontainers.image.authors="Agus Makmun <summon.agus@gmail.com>" \
      org.opencontainers.image.source="https://github.com/capyshield/capyshield" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apk add --no-cache ca-certificates
COPY --from=build /src/target/release/capyshield /usr/local/bin/capyshield
ENTRYPOINT ["capyshield"]
