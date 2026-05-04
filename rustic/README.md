# Rustic

**Rustic** is a **Rust edition 2024** service template for **`FROM scratch`** (or minimal) containers: **rustls** + **aws-lc-rs**, **mimalloc**, structured logging, and a **concurrent** Axum stack with **ECDSA P-256 (NIST ECC)** **image-trust** envelopes so callers can cryptographically verify what image and bundles they are talking to.

## Security model (ECC / ECDSA)

- **Algorithm:** ECDSA over **P-256** with **SHA-256** (DER signatures, Base64 in JSON). Implemented with the **`p256`** crate (no OpenSSL).
- **Envelope formats:** `rustic-image-trust-envelope-v1` (current). Legacy `artifact-envelope-v1` is still **accepted on verify** so older signed files keep working.
- **Image trust payload** (`image_trust` in the signed JSON): optional binding of **runtime OCI digest**, **WASM image digest**, and **web/DOM bundle digest**; see `src/artifacts/envelope.rs`.
- **Startup:** if `IMAGE_TRUST_ENVELOPE` is set, the binary verifies the signature, optionally compares **`IMAGE_TRUST_RUNTIME_DIGEST`** / **`CONTAINER_IMAGE_DIGEST`** to `image_trust.runtime_image_digest_sha256`, and optionally checks on-disk files when **`IMAGE_TRUST_STRICT_FILES=1`**.
- **Callers:** `GET /.well-known/rustic-image-trust.json` returns the **same signed JSON** your WASM, browser, or API gateway can verify with your org public key **before** trusting this stack.
- **Access control (KWT):** prefer **[KWT](https://github.com/TheMapleseed/KWT)** — compact, always-encrypted tokens (v1: XChaCha20-Poly1305 + HKDF). Set **`IMAGE_TRUST_KWT_MASTER_KEY`** to 64 hex chars (32-byte master key) and send **`Authorization: KWT <v1…token>`** or **`X-KWT: <token>`** on `/v1/protected/*`. Audience defaults to **`rustic`**; override with **`IMAGE_TRUST_KWT_AUDIENCE`**. Issue tokens with the `kwt` crate (`KwtToken::issue`) using the same key.
- **Legacy static gate:** if the KWT master key is **not** set, optional **`IMAGE_TRUST_API_TOKEN`** still enables `Bearer` / `X-Image-Trust-Token` (shared secret only).

## Layout (scalable / concurrent)

| Path | Role |
|------|------|
| `src/lib.rs` | Library root: `artifacts`, `http`, `state`, `telemetry`, plus async helpers |
| `src/http/mod.rs` | Axum router: public health + well-known attestation; nested `/v1/protected` with ECDSA-gated token layer |
| `src/state.rs` | `AppState` (`Arc` payload) cloned per handler — Hyper handles requests concurrently |
| `src/main.rs` | Thin binary: `tokio::join!` for parallel warm-up (DNS / HTTPS smoke / time sample), then `axum::serve` |
| `src/artifacts/` | ECDSA verify/sign, `ImageTrustClaims`, runtime digest checks |
| `src/bin/rustic_tool.rs` | CLI: `cargo build --features rustic-tool --bin rustic-tool` → `sign`, `verify`, `sha256`, `keygen` |
| Root `Dockerfile` | At **repo root** (next to `.git`): multi-stage **musl** → `scratch`, entrypoint **`/rustic`** |
| `rust-toolchain.toml` | **rustup** default: **stable**, `rustfmt`, `clippy` |

## Run locally

```bash
cd rustic
RUST_LOG=info cargo run
```

- Health: `GET http://127.0.0.1:8080/health`
- Attestation (when configured): `GET http://127.0.0.1:8080/.well-known/rustic-image-trust.json`

## Static Linux binary

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Binary: `target/x86_64-unknown-linux-musl/release/rustic`.

## Image signing CLI

```bash
cargo build --release --features rustic-tool --bin rustic-tool
./target/release/rustic-tool keygen --private-out dev.key.pem --public-out dev.pub.pem
./target/release/rustic-tool sha256 --file target/x86_64-unknown-linux-musl/release/rustic
# Fill `examples/payload.sample.json`, then:
./target/release/rustic-tool sign --payload examples/payload.sample.json --secret-key dev.key.pem --output rustic-envelope.json
./target/release/rustic-tool verify --envelope rustic-envelope.json --public-key dev.pub.pem
```

## Container

From the **repository root** (parent of `rustic/`), not from inside `rustic/`:

```bash
cd ..   # if you are currently in rustic/
docker build -t rustic .
docker run --rm -p 8080:8080 rustic
```

If you only have the `rustic/` subtree without the root `Dockerfile`, clone the full [Rustic](https://github.com/TheMapleseed/Rustic) repo or copy the root `Dockerfile` and adjust `COPY` paths.

## CI

GitHub Actions under `.github/workflows/` runs **fmt**, **clippy** (`--all-features`), and **tests** with **Swatinem/rust-cache** on `./rustic`.
