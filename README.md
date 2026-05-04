# Rustic

**Rustic** is a **Rust edition 2024** service template for **`FROM scratch`** (or minimal) containers: **rustls** + **aws-lc-rs**, **mimalloc**, structured logging, and a **concurrent** Axum stack with **image-trust** manifests: **ECDSA P-256** signed JSON and/or **[KWT](https://github.com/TheMapleseed/KWT)** encrypted attestations so callers can verify what image and bundles they are talking to.

## Repository layout

| Path | Role |
|------|------|
| **`Dockerfile`** | Multi-stage **musl** → **`FROM scratch`**, copies `rustic/` sources |
| **`directions.txt`** | Notes on static / scratch-friendly Rust stacks |
| **`rustic/`** | Cargo package: `src/`, `Cargo.toml`, `rust-toolchain.toml`, `examples/`, vendored **`rustic/crates/kwt`** |

All **`cargo`** and **`rustup`** commands below run from **`rustic/`** unless noted.

## Security model (image trust + KWT)

- **ECDSA path (public verifiers):** **P-256** + **SHA-256** (DER signatures, Base64 in JSON), **`p256`** crate. Envelope formats: `rustic-image-trust-envelope-v1` (current); legacy `artifact-envelope-v1` still accepted on verify.
- **KWT attestation path (symmetric):** `IMAGE_TRUST_ENVELOPE` may be a **`v1.…`** token or JSON `{"format":"rustic-image-trust-kwt-v1","kwt":"v1.…"}` issued with the same **`IMAGE_TRUST_KWT_MASTER_KEY`** (64 hex chars). The token embeds minified **`ArtifactPayload`** JSON (opcode `0x70` in the vendored `kwt` crate). Startup validates the token and applies the same runtime-digest / optional file checks as ECDSA. **`GET /.well-known/rustic-image-trust.json`** returns that JSON wrapper so callers decrypt with the master key (see **`rustic-tool kwt-sign`**).
- **Why KWT here (size + cryptography):** For a given manifest, the **on-the-wire token is much smaller** than typical JWT-style or verbose JSON-plus-signature payloads: claims use a **dense canonical binary** encoding, then **XChaCha20-Poly1305** with a **per-token HKDF-derived key** (see the [KWT](https://github.com/TheMapleseed/KWT) spec). That gives **authenticated encryption**—**integrity and confidentiality** for anyone who holds the master key—without negotiable crypto in the token itself. **ECDSA** remains the choice when verifiers should use only a **public** key (no shared secret). Neither mode is a strict “stronger math” superset of the other; they optimize for **different trust models**.
- **Image trust payload** (`image_trust` in the manifest): optional **runtime OCI digest**, **WASM**, **web/DOM bundle** digests; see `rustic/src/artifacts/envelope.rs`.
- **Startup:** if `IMAGE_TRUST_ENVELOPE` is set, the binary verifies **ECDSA** or **KWT**, optionally compares **`IMAGE_TRUST_RUNTIME_DIGEST`** / **`CONTAINER_IMAGE_DIGEST`** to `image_trust.runtime_image_digest_sha256`, and optionally checks on-disk files when **`IMAGE_TRUST_STRICT_FILES=1`**.
- **Access control (KWT only):** **`/v1/protected/*`** accepts only **KWT** — **`Authorization: KWT <v1…token>`** or **`X-KWT`**. Without **`IMAGE_TRUST_KWT_MASTER_KEY`**, protected routes return **401**. Audience defaults to **`rustic`**; override with **`IMAGE_TRUST_KWT_AUDIENCE`**. Issue tokens with the vendored `kwt` crate (`KwtToken::issue`).

## Crate layout (scalable / concurrent)

| Path | Role |
|------|------|
| `rustic/src/lib.rs` | Library root: `artifacts`, `http`, `state`, `telemetry`, plus async helpers |
| `rustic/src/http/mod.rs` | Axum router: public health + well-known attestation; nested `/v1/protected` with KWT gate |
| `rustic/src/state.rs` | `AppState` (`Arc` payload) cloned per handler |
| `rustic/src/main.rs` | Thin binary: `tokio::join!` for parallel warm-up (DNS / HTTPS smoke / time sample), then `axum::serve` |
| `rustic/src/artifacts/` | ECDSA + KWT attestation verify/sign, `ImageTrustClaims`, runtime digest checks |
| `rustic/src/bin/rustic_tool.rs` | CLI: `sign`, `verify`, **`kwt-sign`**, `sha256`, `keygen` |
| `rustic/rust-toolchain.toml` | **rustup** default: **stable**, `rustfmt`, `clippy` |

## Run locally

```bash
cd rustic
RUST_LOG=info cargo run
```

- Health: `GET http://127.0.0.1:8080/health`
- Attestation (when configured): `GET http://127.0.0.1:8080/.well-known/rustic-image-trust.json`

## Static Linux binary

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

**ECDSA envelope** — edit `examples/payload.sample.json`, then:

```bash
./target/release/rustic-tool sign --payload examples/payload.sample.json --secret-key dev.key.pem --output rustic-envelope.json
./target/release/rustic-tool verify --envelope rustic-envelope.json --public-key dev.pub.pem
```

**KWT attestation** (same payload; master key must match `IMAGE_TRUST_KWT_MASTER_KEY` at runtime):

```bash
./target/release/rustic-tool kwt-sign \
  --payload examples/payload.sample.json \
  --master-key-hex "<64 hex chars>" \
  --audience rustic \
  --output rustic-kwt-envelope.json
# or raw token only: add --raw-token-only
```

## Container

From the **repository root** (where this `README.md` and `Dockerfile` live):

```bash
docker build -t rustic .
docker run --rm -p 8080:8080 rustic
```

If you only have the `rustic/` subtree without the root `Dockerfile`, clone the full [Rustic](https://github.com/TheMapleseed/Rustic) repo.

## CI

GitHub Actions: **`.github/workflows/ci.yml`** — **fmt**, **clippy** (`--all-features`), **tests**, with **Swatinem/rust-cache** on `./rustic` (jobs use `working-directory: rustic`).
