# syntax=docker/dockerfile:1
# Build from **repository root** (the Rustic monorepo): `docker build -t rustic .`
# The Rust crate lives in `rustic/`; this file stays at the root beside `.git`.

FROM rust:bookworm AS builder

WORKDIR /app
COPY rustic/rust-toolchain.toml rustic/Cargo.toml rustic/Cargo.lock ./
RUN rustup show

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        musl-tools \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

COPY rustic/src ./src

RUN mkdir -m 1777 /tmp

ENV CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /tmp /tmp
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rustic /rustic

# Optional: ECDSA P-256 image-trust envelope + runtime digest (see rustic/README.md).
# COPY rustic-envelope.json /rustic-envelope.json
# COPY rustic-public.pem /rustic-public.pem
# ENV IMAGE_TRUST_ENVELOPE=/rustic-envelope.json
# ENV IMAGE_TRUST_PUBLIC_KEY_PATH=/rustic-public.pem
# ENV IMAGE_TRUST_RUNTIME_DIGEST=sha256:...
# ENV IMAGE_TRUST_STRICT_FILES=1
# ENV IMAGE_TRUST_API_TOKEN=...

USER 10001:10001

ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["/rustic"]
