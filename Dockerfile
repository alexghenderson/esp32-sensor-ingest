FROM rust:1.76-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/sensor-ingest .
COPY .env .

EXPOSE 8080

CMD ["./sensor-ingest"]
