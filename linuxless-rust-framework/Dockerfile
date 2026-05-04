# syntax=docker/dockerfile:1

# Builder: official image includes **rustup**; `rust-toolchain.toml` pins channel + components.
FROM rust:bookworm AS builder

WORKDIR /app
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
# Install channel/components from rust-toolchain.toml (rustup is the default toolchain driver here).
RUN rustup show

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        musl-tools \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

COPY src ./src

RUN mkdir -m 1777 /tmp

ENV CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc

RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime: empty filesystem except binary + world-writable /tmp for libraries that buffer there.
FROM scratch

COPY --from=builder /tmp /tmp
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/linuxless-rust-framework /linuxless-rust-framework

# Optional: ECDSA P-256 signed artifact envelope (native / wasm / image digest) verified at startup.
# Build with: cargo run --features artifact-tool --bin artifact-tool -- keygen ...
# COPY artifact-envelope.json /artifact-envelope.json
# COPY artifact-public.pem /artifact-public.pem
# ENV ARTIFACT_VERIFY_ENVELOPE=/artifact-envelope.json
# ENV ARTIFACT_VERIFY_PUBLIC_KEY_PATH=/artifact-public.pem
# ENV ARTIFACT_VERIFY_STRICT_FILES=1

USER 10001:10001

ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["/linuxless-rust-framework"]
