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
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rustic /rustic

# Optional: ECDSA P-256 **Rustic** image-trust envelope + runtime digest binding.
# `cargo build --release --features rustic-tool --bin rustic-tool` then sign / verify.
# COPY rustic-envelope.json /rustic-envelope.json
# COPY rustic-public.pem /rustic-public.pem
# ENV IMAGE_TRUST_ENVELOPE=/rustic-envelope.json
# ENV IMAGE_TRUST_PUBLIC_KEY_PATH=/rustic-public.pem
# ENV IMAGE_TRUST_RUNTIME_DIGEST=sha256:...   # from registry / build attestation
# ENV IMAGE_TRUST_STRICT_FILES=1
# ENV IMAGE_TRUST_API_TOKEN=...               # gates /v1/protected/* when set

USER 10001:10001

ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["/rustic"]
