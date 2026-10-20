FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin gateway
COPY --from=builder /app/target/release/automantle-gateway /usr/local/bin/automantle-gateway

USER gateway
ENTRYPOINT ["/usr/local/bin/automantle-gateway"]
