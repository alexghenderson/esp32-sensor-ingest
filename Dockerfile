FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/sensor-ingest .

EXPOSE 8080

CMD ["./sensor-ingest"]
