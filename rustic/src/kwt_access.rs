//! [KWT](https://github.com/TheMapleseed/KWT) (KDL Web Token) for `/v1/protected/*` and optional
//! **image-trust attestation** files (`IMAGE_TRUST_ENVELOPE` may be a KWT token).
//! Clients send **`Authorization: KWT <token>`** or **`X-KWT`** — v1 tokens are **encrypted**
//! (XChaCha20-Poly1305 + HKDF).

use kwt::crypto::MasterKey;
use thiserror::Error;

/// Parsed KWT validator configuration (32-byte master key + expected audience).
#[derive(Clone)]
pub struct KwtAccessConfig {
    pub master_key: MasterKey,
    pub audience: String,
}

#[derive(Debug, Error)]
pub enum KwtEnvError {
    #[error("IMAGE_TRUST_KWT_MASTER_KEY must decode to exactly 32 bytes (64 hex chars)")]
    BadKey,
}

/// Load the KWT master key from **`IMAGE_TRUST_KWT_MASTER_KEY`** (64 hex chars), if set.
pub fn kwt_master_key_from_env() -> Result<Option<MasterKey>, KwtEnvError> {
    let key_hex = match std::env::var("IMAGE_TRUST_KWT_MASTER_KEY") {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };
    let raw = hex::decode(key_hex.trim()).map_err(|_| KwtEnvError::BadKey)?;
    let master_key = MasterKey::from_bytes(&raw).map_err(|_| KwtEnvError::BadKey)?;
    Ok(Some(master_key))
}

/// Expected audience for issued KWTs (attestation + API gate). Default **`rustic`**.
pub fn kwt_audience_from_env() -> String {
    std::env::var("IMAGE_TRUST_KWT_AUDIENCE").unwrap_or_else(|_| "rustic".into())
}

/// Load KWT gate config from the environment. If unset, the HTTP layer still rejects `/v1/protected/*` with **401**.
pub fn kwt_access_from_env() -> Result<Option<KwtAccessConfig>, KwtEnvError> {
    let Some(master_key) = kwt_master_key_from_env()? else {
        return Ok(None);
    };
    Ok(Some(KwtAccessConfig {
        master_key,
        audience: kwt_audience_from_env(),
    }))
}
