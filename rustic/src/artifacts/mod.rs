//! **ECDSA P-256 (NIST ECC)** signed envelopes for **OCI / container image trust**, optional **WASM** and **web (DOM) bundle**
//! digests, and **caller-verifiable** attestations (`GET /.well-known/rustic-image-trust.json`).
//!
//! Deployers inject **`IMAGE_TRUST_RUNTIME_DIGEST`** at rollout; if the signed payload includes
//! `image_trust.runtime_image_digest_sha256`, startup fails on mismatch (wrong image / supply-chain break).
//! Gateways or browser WASM verify the **same ECDSA** signature over the canonical JSON using your org public key.

mod envelope;
mod p256_sig;

pub use envelope::{
    ArtifactEntry, ArtifactKind, ArtifactPayload, ArtifactVerifyError, ENVELOPE_FORMAT,
    ENVELOPE_FORMAT_LEGACY, Envelope, ImageTrustClaims, SignatureRecord, envelope_format_supported,
    normalize_sha256_hex,
};
pub use p256_sig::{sign_payload_pem_pkcs8, verify_envelope_pem};

use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Verifies envelope signature, optional file bindings, and **runtime OCI digest** vs signed `image_trust`.
/// Returns the envelope JSON to serve at `/.well-known/linuxless-image-trust.json` when configured.
pub fn verify_on_startup_from_env() -> Result<Option<Arc<str>>, ArtifactVerifyError> {
    let path = match envelope_path_from_env() {
        Some(p) => p,
        _ => return Ok(None),
    };

    let pem = read_pem_from_env()?;
    let strict_files =
        env_flag("IMAGE_TRUST_STRICT_FILES") || env_flag("ARTIFACT_VERIFY_STRICT_FILES");

    let json = std::fs::read_to_string(&path).map_err(|e| ArtifactVerifyError::Io {
        path: path.clone(),
        source: e,
    })?;

    verify_envelope_pem(&json, &pem)?;
    info!(path, "image trust envelope signature OK (ECDSA P-256)");

    verify_runtime_digest_if_claimed(&json)?;

    if strict_files {
        verify_file_bindings(&json, &pem)?;
    }

    Ok(Some(Arc::from(json)))
}

fn envelope_path_from_env() -> Option<String> {
    std::env::var("IMAGE_TRUST_ENVELOPE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("ARTIFACT_VERIFY_ENVELOPE")
                .ok()
                .filter(|s| !s.is_empty())
        })
}

fn read_pem_from_env() -> Result<String, ArtifactVerifyError> {
    if let Ok(pem) = std::env::var("IMAGE_TRUST_PUBLIC_KEY_PEM") {
        if !pem.is_empty() {
            return Ok(pem);
        }
    }
    if let Ok(p) = std::env::var("IMAGE_TRUST_PUBLIC_KEY_PATH") {
        if !p.is_empty() {
            return std::fs::read_to_string(&p)
                .map_err(|e| ArtifactVerifyError::Io { path: p, source: e });
        }
    }
    if let Ok(pem) = std::env::var("ARTIFACT_VERIFY_PUBLIC_KEY_PEM") {
        if !pem.is_empty() {
            return Ok(pem);
        }
    }
    if let Ok(p) = std::env::var("ARTIFACT_VERIFY_PUBLIC_KEY_PATH") {
        if !p.is_empty() {
            return std::fs::read_to_string(&p)
                .map_err(|e| ArtifactVerifyError::Io { path: p, source: e });
        }
    }
    Err(ArtifactVerifyError::MissingPublicKey)
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// If the signed payload includes `image_trust.runtime_image_digest_sha256`, the runtime must supply a matching digest.
fn verify_runtime_digest_if_claimed(json: &str) -> Result<(), ArtifactVerifyError> {
    let env: Envelope = serde_json::from_str(json)?;
    let Some(ref it) = env.payload.image_trust else {
        return Ok(());
    };
    let Some(ref expected_raw) = it.runtime_image_digest_sha256 else {
        return Ok(());
    };
    let expected = normalize_sha256_hex(expected_raw).ok_or_else(|| {
        ArtifactVerifyError::Crypto(
            "invalid image_trust.runtime_image_digest_sha256 (want 64 hex or sha256:...)".into(),
        )
    })?;

    let actual_raw = std::env::var("IMAGE_TRUST_RUNTIME_DIGEST")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("CONTAINER_IMAGE_DIGEST")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .ok_or(ArtifactVerifyError::MissingRuntimeDigestEnv)?;

    let actual = normalize_sha256_hex(&actual_raw).ok_or_else(|| {
        ArtifactVerifyError::Crypto(
            "IMAGE_TRUST_RUNTIME_DIGEST / CONTAINER_IMAGE_DIGEST is not a valid sha256 digest"
                .into(),
        )
    })?;

    if expected != actual {
        return Err(ArtifactVerifyError::RuntimeImageDigestMismatch { expected, actual });
    }

    info!(%expected, "runtime OCI digest matches signed image_trust claim");
    Ok(())
}

/// After signature checks, ensure each artifact with a `path` matches its `sha256` (optional hardening in OS images).
pub fn verify_file_bindings(json: &str, public_key_pem: &str) -> Result<(), ArtifactVerifyError> {
    verify_envelope_pem(json, public_key_pem)?;
    let env: Envelope = serde_json::from_str(json)?;
    let mut payload = env.payload;
    payload.sort_artifacts();

    for a in &payload.artifacts {
        if let Some(ref rel) = a.path {
            let p = Path::new(rel);
            let bytes = std::fs::read(p).map_err(|e| ArtifactVerifyError::Io {
                path: rel.clone(),
                source: e,
            })?;
            let digest = hex::encode(Sha256::digest(&bytes));
            if digest != a.sha256 {
                return Err(ArtifactVerifyError::DigestMismatch {
                    name: a.name.clone(),
                    path: rel.clone(),
                    expected: a.sha256.clone(),
                    actual: digest,
                });
            }
            info!(name = %a.name, path = %rel, "artifact file binding OK");
        }
    }
    Ok(())
}

/// Verify a WASM (or any) byte slice matches an entry in a signed envelope by name.
pub fn verify_bytes_against_envelope(
    json: &str,
    public_key_pem: &str,
    artifact_name: &str,
    bytes: &[u8],
) -> Result<(), ArtifactVerifyError> {
    verify_envelope_pem(json, public_key_pem)?;
    let env: Envelope = serde_json::from_str(json)?;
    let mut payload = env.payload;
    payload.sort_artifacts();
    let digest = hex::encode(Sha256::digest(bytes));
    let found = payload
        .artifacts
        .iter()
        .find(|a| a.name == artifact_name)
        .ok_or_else(|| ArtifactVerifyError::UnknownArtifact {
            name: artifact_name.to_string(),
        })?;
    if found.sha256 != digest {
        return Err(ArtifactVerifyError::DigestMismatch {
            name: artifact_name.to_string(),
            path: "<inline bytes>".into(),
            expected: found.sha256.clone(),
            actual: digest,
        });
    }
    Ok(())
}

/// Non-fatal: logs if client-provided manifest fails verification (e.g. optional client WASM attestation).
pub fn warn_if_client_envelope_invalid(
    json: Option<&str>,
    public_key_pem: Option<&str>,
    artifact_name: &str,
    bytes: &[u8],
) {
    let (Some(json), Some(pem)) = (json, public_key_pem) else {
        return;
    };
    if let Err(e) = verify_bytes_against_envelope(json, pem, artifact_name, bytes) {
        warn!(%e, "client artifact envelope verification failed");
    }
}
