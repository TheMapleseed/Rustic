# Rustic

**Rustic** is a **Rust edition 2024** template: a **static musl** service you can ship in **`FROM scratch`**, plus optional **ECDSA image-trust** manifests and **KWT**-gated HTTP routes.

| Layer | What it is |
|-------|------------|
| **Runtime** | **Axum** + **Tokio**, **rustls** + **aws-lc-rs**, **mimalloc**, **tracing** — one process, no distro rootfs in the final image. |
| **Image trust (ECDSA)** | Signed JSON envelope (`rustic-image-trust-envelope-v1`) for **`GET /.well-known/rustic-image-trust.json`** and startup checks. Implemented in `rustic::artifacts` (**`p256`**, no OpenSSL). |
| **API gate (KWT)** | **[`kwt` on crates.io](https://crates.io/crates/kwt)** (same format as [KWT](https://github.com/TheMapleseed/KWT)) — **`/v1/protected/*`** accepts only **`Authorization: KWT …`** or **`X-KWT`**. |

The **repository** is a small monorepo: root **`Dockerfile`** + **`rustic/`** Cargo package (library + **`rustic`** binary + optional **`rustic-tool`** CLI).

## Repository layout

| Path | Role |
|------|------|
| **`Dockerfile`** | Multi-stage **musl** → **`FROM scratch`**; copies only `rustic/` sources (no vendored sub-crates). |
| **`directions.txt`** | Longer notes on scratch / static builds (reference, not the live API doc). |
| **`rustic/`** | Single package: **`lib`** (`artifacts`, `http`, …), **`rustic`** binary, optional **`rustic-tool`**. Depends on **`kwt`** from **crates.io**. |

Commands: **`cd rustic`** then **`cargo`** / **`rustup`**. Docker: run from **repository root**.

## Environment variables

| Variable | Role |
|----------|------|
| **`IMAGE_TRUST_ENVELOPE`** | Path to signed **ECDSA** envelope JSON (optional). Aliases: `ARTIFACT_VERIFY_ENVELOPE`. |
| **`IMAGE_TRUST_PUBLIC_KEY_PEM`** / **`…_PATH`** | SPKI public key PEM to verify the envelope. Aliases: `ARTIFACT_VERIFY_*`. |
| **`IMAGE_TRUST_RUNTIME_DIGEST`** / **`CONTAINER_IMAGE_DIGEST`** | If the envelope claims a runtime digest, must match at startup. |
| **`IMAGE_TRUST_STRICT_FILES`** | `1` / `true` / `yes` — verify on-disk files against manifest. |
| **`IMAGE_TRUST_KWT_MASTER_KEY`** | 64 hex chars (32-byte key). If unset, **`/v1/protected/*`** returns **401**. |
| **`IMAGE_TRUST_KWT_AUDIENCE`** | Expected KWT audience (default **`rustic`**). |
| **`PORT`** | Listen port (default **8080**). |
| **`RUST_LOG`** | **tracing** filter (e.g. `info`). |

## Security model (short)

- **ECDSA:** Public verifiers use your org **public key**; envelope formats **`rustic-image-trust-envelope-v1`** and legacy **`artifact-envelope-v1`**. Payload can bind **OCI / WASM / DOM** digests — see `rustic/src/artifacts/envelope.rs`.
- **KWT:** Symmetric; verifiers need the **master key**. Used **only** for **`/v1/protected/*`**, not for the on-disk envelope file. Issue tokens with **`kwt::token::KwtToken::issue`** (see **`http`** tests). Production deployments often add **replay control** (JTI / store) beyond this template.

**License note:** The **`kwt`** crate is **GPL-3.0-or-later** on crates.io. Rustic itself is **MIT OR Apache-2.0**; if you publish a binary that links `kwt`, resolve how that affects **your** distribution (legal review for proprietary products).

## Crate layout (`rustic/`)

| Module / binary | Role |
|-----------------|------|
| **`artifacts`** | ECDSA sign/verify, envelope types, runtime digest + optional file checks. |
| **`http`** | Router: `/health`, `/.well-known/rustic-image-trust.json`, `/v1/protected/*` + KWT middleware. |
| **`kwt_access`** | Parse **`IMAGE_TRUST_KWT_*`** into **`KwtAccessConfig`**. |
| **`main.rs`** (binary) | rustls default crypto provider, warm-up (`dns`, `outbound`, `time_info`), **`axum::serve`**. |
| **`rustic-tool`** (feature **`rustic-tool`**) | CLI: ECDSA **`sign`** / **`verify`**, **`sha256`**, **`keygen`**. |

## Run locally

```bash
cd rustic
RUST_LOG=info cargo run
```

- `GET http://127.0.0.1:8080/health`
- With `IMAGE_TRUST_*` set: `GET http://127.0.0.1:8080/.well-known/rustic-image-trust.json`

## Static Linux (musl) binary

```bash
cd rustic
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Output: `rustic/target/x86_64-unknown-linux-musl/release/rustic`.

## Image signing CLI

```bash
cd rustic
cargo build --release --features rustic-tool --bin rustic-tool
./target/release/rustic-tool keygen --private-out dev.key.pem --public-out dev.pub.pem
./target/release/rustic-tool sha256 --file target/x86_64-unknown-linux-musl/release/rustic
```

Edit `examples/payload.sample.json`, then:

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

**`.github/workflows/ci.yml`** — **fmt**, **clippy** (`--all-features` **`-D warnings`**), **tests**; **Swatinem/rust-cache** on `./rustic` (`working-directory: rustic`).

---

## Can this become “a crate” and stay as useful?

**It is already a crate:** `rustic` has a **`lib`** target. Another project can depend on it (path/git today; `publish = false` blocks crates.io until you flip that). You can call **`rustic::http::router`**, **`rustic::artifacts::verify_on_startup_from_env`**, etc., and supply your own `main` if you want.

**Publishing one big `rustic` on crates.io** is *possible* but *awkward* as a **reusable library**: you drag **Axum, Tokio, rustls, reqwest, hickory, …** and opinionated HTTP routes. Version churn (axum 0.8 → 0.9, etc.) becomes your semver problem for every downstream app. Good for an **internal template** or a **named product crate** (`your-org-rustic`), less ideal as a generic “tiny dependency.”

**Splitting into smaller crates** is **reasonable** and preserves most utility:

| Extractable crate | Rough scope | Utility preserved |
|-------------------|-------------|---------------------|
| **`rustic-image-trust`** (name example) | `artifacts` + `p256` + serde/sha2/hex | **High** — sign/verify envelopes, digest checks, **no** HTTP, **no** `kwt`. Fits CI tools, agents, CLIs. |
| **`rustic-http` or keep in app** | Axum router + KWT middleware | **Medium** — useful if you want the same routes; still couples to Axum/tower versions. |
| **Binary + Dockerfile** | Thin `main`, warm-up, `serve` | **High** for “clone and deploy”; doesn’t need to be a published library. |

**Practical recommendation:** If the goal is **library-style reuse**, extract **`artifacts`** (and optionally move **`rustic-tool`** into `rustic-image-trust-cli` or keep as a second bin in a workspace member). Keep the **HTTP stack** in an application crate (this repo or `rustic-server`) that depends on the small crate. You keep **similar utility**: same trust semantics, smaller dependency surface for non-HTTP consumers, and the scratch Docker story stays on the **binary** side.

**What you lose when splitting:** a single **`cargo add rustic`** one-liner until you publish and document multiple crates; you gain clearer boundaries and lighter dependents.
