# Linuxless Rust framework

Template for a **statically linked** Rust service aimed at **`FROM scratch`** containers: no distro base image, no shell, no OpenSSL—only your binary plus whatever you explicitly copy in (for example `/tmp`).

**Toolchain:** use [**rustup**](https://rustup.rs/) locally. This crate ships **`rust-toolchain.toml`** so rustup selects the **stable** channel with **rustfmt** and **clippy** when you work in this directory. The Docker builder uses the same file via **`rustup show`**.

## Layout

| Path | Role |
|------|------|
| `rust-toolchain.toml` | **rustup** default: **stable**, `rustfmt` + `clippy`, `minimal` profile |
| `src/main.rs` | `mimalloc` global allocator, rustls crypto provider install, Tokio + Axum serve |
| `src/app.rs` | `tracing` setup (`RUST_LOG`), HTTP router, `/health` |
| `src/shutdown.rs` | SIGTERM/SIGINT (Unix) or Ctrl+C elsewhere—feeds Axum graceful shutdown |
| `src/time_info.rs` | `chrono` + `chrono-tz` sample (no `/usr/share/zoneinfo` in scratch) |
| `src/dns.rs` | `hickory-resolver` sample using system `resolv.conf` when present |
| `src/outbound.rs` | `reqwest` + **rustls** + **webpki-roots** HTTPS smoke to `example.com` |
| `Dockerfile` | Multi-stage: Bookworm builder (`x86_64-unknown-linux-musl`) → `scratch` |
| `src/artifacts/` | **ECDSA P-256 (NIST ECC)** signed manifests: native ELF, **WASM**, OCI image digests, arbitrary files |
| `src/bin/artifact_tool.rs` | Optional CLI (`--features artifact-tool`): `sign`, `verify`, `sha256`, `keygen` |
| `examples/payload.sample.json` | Unsigned payload template before signing |

## ECC artifact verification (P-256)

This stack treats **“ECC verification”** as **ECDSA over the P-256 curve with SHA-256**: a small, pure-Rust path that fits **scratch**, **static musl**, **WASM clients**, and **full OS images** alike.

- **Signed envelope** (`format: "artifact-envelope-v1"`): JSON payload listing artifacts (`type`: `wasm` \| `native` \| `container_image` \| `oci_layer` \| `file`) each with a **64-char lowercase SHA-256 hex** of the raw bytes, optional `path` for on-disk checks inside an image.
- **Signature**: DER ECDSA, **standard Base64**, algorithm id `ecdsa-p256-sha256`.
- **Public key**: SPKI PEM (`-----BEGIN PUBLIC KEY-----`). Private key for signing: PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).

**Runtime (Linux / container):** if `ARTIFACT_VERIFY_ENVELOPE` points to an envelope file, the server verifies before binding the port. Set **`ARTIFACT_VERIFY_PUBLIC_KEY_PEM`** (inline PEM) or **`ARTIFACT_VERIFY_PUBLIC_KEY_PATH`**. Set **`ARTIFACT_VERIFY_STRICT_FILES=1`** to require every artifact with a `path` to match its digest on disk (hardening for OS/rootfs layouts).

**Client-side WASM:** use the same JSON envelope and verify with **Web Crypto** (`crypto.subtle.importKey` + `verify` with `{ name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" }` over the **UTF-8 bytes** of the canonical payload—the server uses the same canonicalization rule (`serde_json` of the payload with artifacts sorted by `name`). The helper `artifacts::warn_if_client_envelope_invalid` is for optional browser-supplied manifests.

**CLI (local / CI):**

```bash
cargo build --release --features artifact-tool --bin artifact-tool

./target/release/artifact-tool keygen --private-out dev.key.pem --public-out dev.pub.pem
./target/release/artifact-tool sha256 --file ./target/x86_64-unknown-linux-musl/release/linuxless-rust-framework
# edit examples/payload.sample.json with that digest, then:
./target/release/artifact-tool sign --payload examples/payload.sample.json --secret-key dev.key.pem --output artifact-envelope.json
./target/release/artifact-tool verify --envelope artifact-envelope.json --public-key dev.pub.pem
```

Copy `artifact-envelope.json` and `dev.pub.pem` into the image (see commented `Dockerfile` lines) to verify **inside the OS image** at startup.

## Local run

```bash
cd linuxless-rust-framework
RUST_LOG=info cargo run
```

Then: `curl -s http://127.0.0.1:8080/health` → `ok`.

Port defaults to **8080**; override with `PORT`.

## Static Linux binary

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Artifact: `target/x86_64-unknown-linux-musl/release/linuxless-rust-framework`.

## Container image

```bash
docker build -t linuxless-rust-framework .
docker run --rm -p 8080:8080 linuxless-rust-framework
```

The image runs as UID **10001**, includes **`/tmp`** with sticky-bit permissions for crates that expect it, and exposes **8080**. Build the image on **amd64** (or use `docker buildx` with a suitable cross toolchain); `musl-tools` in the Dockerfile targets **x86_64** musl.

**Health checks:** Docker `HEALTHCHECK` cannot rely on `curl` or `sh` inside `scratch`. Prefer Kubernetes HTTP probes, or ship a tiny second binary for probes.

## CI caching

GitHub Actions workflow under `.github/workflows/` uses **Swatinem/rust-cache** for `cargo clippy` / `cargo test`. For Docker layer caching in CI, use **build-push-action** with `cache-from` / `cache-to` `type=gha` (see your `directions.txt` notes).

## Caveats

- **PID 1:** graceful shutdown requires signal handling (implemented here).
- **No NSS:** for strict DNS control, configure `hickory-resolver` explicitly instead of system conf.
- **`panic = "abort"`** in release: smaller binary, no unwinding on panic.
- **aws-lc-rs:** needs a C toolchain at **build** time; the **runtime** image stays `scratch`.
