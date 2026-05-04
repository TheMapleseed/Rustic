# Rustic

**Rustic** is a **Rust edition 2024** service template for **`FROM scratch`** containers: static **musl** binary, **rustls** + **aws-lc-rs**, **mimalloc**, structured logging, and a **concurrent** Axum stack with **image-trust** manifests — **ECDSA P-256** signed JSON and/or **[KWT](https://github.com/TheMapleseed/KWT)** encrypted attestations — so callers can verify what image and bundles they are talking to.

The goal is a **small, self-contained process** in the container: no distro rootfs, no shell — just your binary and what you explicitly copy in.

## Repository layout

| Path | Role |
|------|------|
| **`Dockerfile`** | Multi-stage **musl** → **`FROM scratch`**, copies `rustic/` sources |
| **`directions.txt`** | Notes on static / scratch-friendly Rust stacks |
| **`rustic/`** | Cargo package: `src/`, `Cargo.toml`, `rust-toolchain.toml`, `examples/`, vendored **`rustic/crates/kwt`** |

Run **`cargo`** / **`rustup`** from **`rustic/`** unless noted.

## Security model (image trust + KWT)

- **ECDSA path (public verifiers):** **P-256** + **SHA-256** (DER signatures, Base64 in JSON), **`p256`** crate. Envelope formats: `rustic-image-trust-envelope-v1` (current); legacy `artifact-envelope-v1` still accepted on verify.
- **KWT attestation path (symmetric):** `IMAGE_TRUST_ENVELOPE` may be a **`v1.…`** token or JSON `{"format":"rustic-image-trust-kwt-v1","kwt":"v1.…"}` with **`IMAGE_TRUST_KWT_MASTER_KEY`** (64 hex chars). Embeds minified **`ArtifactPayload`** JSON in the KWT payload. **`GET /.well-known/rustic-image-trust.json`** returns the JSON wrapper for KWT mode (see **`rustic-tool kwt-sign`**).
- **KWT vs ECDSA on the wire:** Dense binary claims + **XChaCha20-Poly1305** + **HKDF** ([KWT](https://github.com/TheMapleseed/KWT)). Use **ECDSA** when verifiers only have a **public** key.
- **Image trust payload:** optional **runtime OCI digest**, **WASM**, **web/DOM bundle** digests; see `rustic/src/artifacts/envelope.rs`.
- **Startup:** with `IMAGE_TRUST_ENVELOPE`, verifies **ECDSA** or **KWT**, optional **`IMAGE_TRUST_RUNTIME_DIGEST`** / **`CONTAINER_IMAGE_DIGEST`**, optional **`IMAGE_TRUST_STRICT_FILES=1`**.
- **Access control:** **`/v1/protected/*`** requires **KWT** (`Authorization: KWT …` or **`X-KWT`**). **`IMAGE_TRUST_KWT_MASTER_KEY`**; **`IMAGE_TRUST_KWT_AUDIENCE`** (default `rustic`).

## Crate layout

| Path | Role |
|------|------|
| `rustic/src/lib.rs` | `artifacts`, `http`, `state`, `telemetry`, helpers |
| `rustic/src/http/mod.rs` | Health, well-known attestation, `/v1/protected` + KWT gate |
| `rustic/src/main.rs` | Binary: warm-up + `axum::serve` |
| `rustic/src/artifacts/` | Image-trust verify/sign |
| `rustic/src/bin/rustic_tool.rs` | `sign`, `verify`, `kwt-sign`, `sha256`, `keygen` |
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

**KWT:**

```bash
./target/release/rustic-tool kwt-sign \
  --payload examples/payload.sample.json \
  --master-key-hex "<64 hex chars>" \
  --audience rustic \
  --output rustic-kwt-envelope.json
```

## Docker

From **repository root**:

```bash
docker build -t rustic .
docker run --rm -p 8080:8080 rustic
```

## CI

**`.github/workflows/ci.yml`** — **fmt**, **clippy** (`--all-features`), **tests**, **Swatinem/rust-cache** on `./rustic` (`working-directory: rustic`).
