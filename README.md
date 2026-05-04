# Rustic

**Rustic** is a **Rust edition 2024** service template for **`FROM scratch`** containers: static **musl** binary, **rustls** + **aws-lc-rs**, **mimalloc**, structured logging, and a **concurrent** Axum stack. **Image-trust** uses **ECDSA P-256** signed JSON for **`/.well-known/rustic-image-trust.json`**; **[`kwt` on crates.io](https://crates.io/crates/kwt)** powers **KWT** tokens for **`/v1/protected/*`** only.

The goal is a **small, self-contained process** in the container: no distro rootfs, no shell — just your binary and what you explicitly copy in.

## Repository layout

| Path | Role |
|------|------|
| **`Dockerfile`** | Multi-stage **musl** → **`FROM scratch`**, copies `rustic/` sources |
| **`directions.txt`** | Notes on static / scratch-friendly Rust stacks |
| **`rustic/`** | Cargo package: `src/`, `Cargo.toml`, `rust-toolchain.toml`, `examples/`; **`kwt`** from [crates.io](https://crates.io/crates/kwt) ([repo](https://github.com/TheMapleseed/KWT)) |

Run **`cargo`** / **`rustup`** from **`rustic/`** unless noted.

## Security model (image trust + KWT)

- **ECDSA envelope (`IMAGE_TRUST_ENVELOPE`):** **P-256** + **SHA-256** (DER signatures, Base64 in JSON), **`p256`** crate. Formats: `rustic-image-trust-envelope-v1` (current); legacy `artifact-envelope-v1` still accepted on verify. **`GET /.well-known/rustic-image-trust.json`** serves the same signed JSON.
- **Image trust payload:** optional **runtime OCI digest**, **WASM**, **web/DOM bundle** digests; see `rustic/src/artifacts/envelope.rs`.
- **Startup:** with `IMAGE_TRUST_ENVELOPE`, verifies **ECDSA**, optional **`IMAGE_TRUST_RUNTIME_DIGEST`** / **`CONTAINER_IMAGE_DIGEST`**, optional **`IMAGE_TRUST_STRICT_FILES=1`**.
- **KWT ([crate](https://crates.io/crates/kwt)):** used only for **`/v1/protected/*`** — **`Authorization: KWT …`** or **`X-KWT`**. Set **`IMAGE_TRUST_KWT_MASTER_KEY`** (64 hex); **`IMAGE_TRUST_KWT_AUDIENCE`** (default `rustic`). Issue tokens with `kwt::token::KwtToken::issue` from your own tooling or tests.

## Crate layout

| Path | Role |
|------|------|
| `rustic/src/lib.rs` | `artifacts`, `http`, `state`, `telemetry`, helpers |
| `rustic/src/http/mod.rs` | Health, well-known attestation, `/v1/protected` + KWT gate |
| `rustic/src/main.rs` | Binary: warm-up + `axum::serve` |
| `rustic/src/artifacts/` | Image-trust verify/sign |
| `rustic/src/bin/rustic_tool.rs` | ECDSA `sign` / `verify`, `sha256`, `keygen` |
| `rustic/rust-toolchain.toml` | **stable**, `rustfmt`, `clippy` |

## Run locally

```bash
cd rustic
RUST_LOG=info cargo run
```

- `GET http://127.0.0.1:8080/health`
- Attestation (if configured): `GET http://127.0.0.1:8080/.well-known/rustic-image-trust.json`

## Static Linux (musl) binary

```bash
cd rustic
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Binary: `rustic/target/x86_64-unknown-linux-musl/release/rustic`.

## Image signing CLI

From **`rustic/`**:

```bash
cargo build --release --features rustic-tool --bin rustic-tool
./target/release/rustic-tool keygen --private-out dev.key.pem --public-out dev.pub.pem
./target/release/rustic-tool sha256 --file target/x86_64-unknown-linux-musl/release/rustic
```

**ECDSA** — edit `examples/payload.sample.json`, then:

```bash
./target/release/rustic-tool sign --payload examples/payload.sample.json --secret-key dev.key.pem --output rustic-envelope.json
./target/release/rustic-tool verify --envelope rustic-envelope.json --public-key dev.pub.pem
```

## Docker

From **repository root**:

```bash
docker build -t rustic .
docker run --rm -p 8080:8080 rustic
```

## CI

**`.github/workflows/ci.yml`** — **fmt**, **clippy** (`--all-features`), **tests**, **Swatinem/rust-cache** on `./rustic` (`working-directory: rustic`).
