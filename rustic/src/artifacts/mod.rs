//! **Image trust** for OCI / WASM / web bundles: **ECDSA P-256** signed JSON envelopes and
//! **`GET /.well-known/rustic-image-trust.json`** for callers.
//!
//! Deployers inject **`IMAGE_TRUST_RUNTIME_DIGEST`** at rollout; if the manifest includes
//! `image_trust.runtime_image_digest_sha256`, startup fails on mismatch (wrong image / supply-chain break).
//! **[KWT](https://crates.io/crates/kwt)** is used for **`/v1/protected/*`** (see `http` + `kwt_access`), not for the envelope file on disk.

mod envelope;
mod p256_sig;

pub use envelope::{
    ArtifactEntry, ArtifactKind, ArtifactPayload, ArtifactVerifyError, ENVELOPE_FORMAT,
    ENVELOPE_FORMAT_LEGACY, Envelope, ImageTrustClaims, SignatureRecord,
    envelope_format_supported, normalize_sha256_hex,
};
pub use p256_sig::{sign_payload_pem_pkcs8, verify_envelope_pem};

use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Verifies ECDSA image-trust envelope, optional file bindings, and **runtime OCI digest** vs `image_trust`.
/// Returns the envelope JSON for `GET /.well-known/rustic-image-trust.json` when configured.
pub fn verify_on_startup_from_env() -> Result<Option<Arc<str>>, ArtifactVerifyError> {
    let path = match envelope_path_from_env() {
        Some(p) => p,
        _ => return Ok(None),
    };

    let strict_files =
        env_flag("IMAGE_TRUST_STRICT_FILES") || env_flag("ARTIFACT_VERIFY_STRICT_FILES");

    let file_body = std::fs::read_to_string(&path).map_err(|e| ArtifactVerifyError::Io {
        path: path.clone(),
        source: e,
    })?;

    let pem = read_pem_from_env()?;
    verify_envelope_pem(&file_body, &pem)?;
    info!(path, "image trust envelope signature OK (ECDSA P-256)");

    verify_runtime_digest_if_claimed(&file_body)?;

    if strict_files {
        verify_file_bindings(&file_body, &pem)?;
    }

    Ok(Some(Arc::from(file_body)))
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
    verify_runtime_digest_if_claimed_payload(env.payload.image_trust.as_ref())
}

fn verify_runtime_digest_if_claimed_payload(
    image_trust: Option<&ImageTrustClaims>,
) -> Result<(), ArtifactVerifyError> {
    let Some(it) = image_trust else {
        return Ok(());
    };
    let Some(expected_raw) = it.runtime_image_digest_sha256.as_ref() else {
        return Ok(());
    };
    let expected = normalize_sha256_hex(expected_raw.as_str()).ok_or_else(|| {
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
    verify_file_bindings_payload(&payload)
}

/// Same file-binding checks as [`verify_file_bindings`] without repeating ECDSA verify.
pub fn verify_file_bindings_payload(payload: &ArtifactPayload) -> Result<(), ArtifactVerifyError> {
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

