//! **Rustic** — minimal-container service template: **ECDSA P-256** or **[KWT](https://github.com/TheMapleseed/KWT)** image-trust manifests, Axum HTTP, shared state.
//!
//! Crypto is **pure Rust** (`p256` / `rustls` + `aws-lc-rs`); no OpenSSL dependency.

pub mod artifacts;
pub mod dns;
pub mod http;
pub mod kwt_access;
pub mod outbound;
pub mod shutdown;
pub mod state;
pub mod telemetry;
pub mod time_info;
