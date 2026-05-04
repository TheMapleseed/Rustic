use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current Rustic signed envelope discriminator (ECDSA P-256 over canonical JSON payload).
pub const ENVELOPE_FORMAT: &str = "rustic-image-trust-envelope-v1";

/// Discriminator for [`KwtAttestationWellKnown`] served at `/.well-known/rustic-image-trust.json` when the deployer uses a KWT attestation file.
pub const KWT_ATTESTATION_WELL_KNOWN_FORMAT: &str = "rustic-image-trust-kwt-v1";

/// JSON wrapper for **`GET /.well-known/rustic-image-trust.json`** when attestation is a [KWT](https://github.com/TheMapleseed/KWT) token. Callers decrypt with the same master key used at issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KwtAttestationWellKnown {
    pub format: String,
    pub kwt: String,
}
/// Earlier experimental format — still accepted when verifying.
pub const ENVELOPE_FORMAT_LEGACY: &str = "artifact-envelope-v1";
pub const SIG_ALG_P256: &str = "ecdsa-p256-sha256";

#[must_use]
pub fn envelope_format_supported(format: &str) -> bool {
    format == ENVELOPE_FORMAT || format == ENVELOPE_FORMAT_LEGACY
}

#[derive(Debug, Error)]
pub enum ArtifactVerifyError {
    #[error("IO error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "missing public key: set IMAGE_TRUST_PUBLIC_KEY_PEM / IMAGE_TRUST_PUBLIC_KEY_PATH (or ARTIFACT_VERIFY_* aliases)"
    )]
    MissingPublicKey,
    #[error("unsupported envelope format: {0}")]
    UnsupportedFormat(String),
    #[error("no supported ECDSA P-256 signature verified")]
    NoValidSignature,
    #[error("cryptographic error: {0}")]
    Crypto(String),
    #[error("unknown artifact name: {name}")]
    UnknownArtifact { name: String },
    #[error("digest mismatch for {name} at {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        name: String,
        path: String,
        expected: String,
        actual: String,
    },
    #[error(
        "runtime OCI image digest mismatch: manifest expects {expected}, environment has {actual}"
    )]
    RuntimeImageDigestMismatch { expected: String, actual: String },
    #[error(
        "manifest requires runtime_image_digest_sha256 but IMAGE_TRUST_RUNTIME_DIGEST (or CONTAINER_IMAGE_DIGEST) is not set"
    )]
    MissingRuntimeDigestEnv,
    #[error(
        "IMAGE_TRUST_KWT_MASTER_KEY must be set when IMAGE_TRUST_ENVELOPE is a KWT attestation"
    )]
    MissingKwtMasterKeyForAttestation,
    #[error("KWT attestation validated but token has no embedded artifact manifest (claim opcode 0x70)")]
    MissingArtifactManifestInKwt,
    #[error("KWT: {0}")]
    Kwt(String),
    #[error("KWT key environment: {0}")]
    KwtEnv(#[from] crate::kwt_access::KwtEnvError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub format: String,
    pub payload: ArtifactPayload,
    pub signatures: Vec<SignatureRecord>,
}

/// Binds the signed manifest to **this** running OCI image and optional WASM / web (DOM) bundles.
/// Callers (browser WASM, API gateway, CI) fetch `/.well-known/rustic-image-trust.json` and verify (ECDSA or decrypt KWT).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageTrustClaims {
    /// Expected digest of the **runtime** OCI image (rootfs/config identity), 64-char lowercase hex (no `sha256:` prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_image_digest_sha256: Option<String>,
    /// Logical reference, e.g. `ghcr.io/org/service` (for humans / policy engines; not a substitute for digest checks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_oci_reference: Option<String>,
    /// WASM module or wasm-OCI artifact bound to this deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_image_digest_sha256: Option<String>,
    /// Hashed web/DOM client bundle (e.g. JS + loader) that must pair with this backend for access-control decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_dom_bundle_digest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPayload {
    pub manifest_version: u32,
    pub artifacts: Vec<ArtifactEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_trust: Option<ImageTrustClaims>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Linux / musl static ELF or similar.
    Native,
    /// Raw `.wasm` module bytes.
    Wasm,
    /// OCI image digest (`sha256:...` without prefix stored as 64 hex in `sha256` field, or full digest in `name`).
    ContainerImage,
    /// Single layer tarball digest or blob.
    OciLayer,
    /// Generic file (config tarball, SBOM, etc.).
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ArtifactKind,
    /// Lowercase hex SHA-256 of raw artifact bytes (64 chars, no `sha256:` prefix).
    pub sha256: String,
    /// If set, `ARTIFACT_VERIFY_STRICT_FILES=1` checks this path on disk inside the image/chroot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRecord {
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_id: Option<String>,
    /// DER-encoded ECDSA signature, standard Base64 (RFC 4648).
    pub signature_der_base64: String,
}

impl ArtifactPayload {
    pub fn sort_artifacts(&mut self) {
        self.artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut p = self.clone();
        p.sort_artifacts();
        serde_json::to_vec(&p)
    }
}

/// Normalize `sha256:abcd...` or `ABCD` → 64-char lowercase hex.
pub fn normalize_sha256_hex(input: &str) -> Option<String> {
    let s = input.trim();
    let hex_part = s.strip_prefix("sha256:").unwrap_or(s);
    if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex_part.to_ascii_lowercase())
}
