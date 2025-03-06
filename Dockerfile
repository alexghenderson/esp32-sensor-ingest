FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src

RUN apt-get update && apt-get install -y libsqlite3-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/sensor-ingest /usr/local/bin/

EXPOSE 8080

RUN apt-get update && apt-get install -y libsqlite3-0 ca-certificates fuse3 sqlite3 && rm -rf /var/lib/apt/lists/*
COPY --from=flyio/litefs:0.5 /usr/local/bin/litefs /usr/local/bin/litefs
COPY litefs.yml /etc/litefs.yml

ENTRYPOINT litefs mount
