//! Optional [KWT](https://github.com/TheMapleseed/KWT) (KDL Web Token) gate for `/v1/protected/*`.
//! When `IMAGE_TRUST_KWT_MASTER_KEY` is set, clients send **`Authorization: KWT <token>`** (or `X-KWT`)
//! instead of a static shared secret — tokens are **encrypted** (XChaCha20-Poly1305 + HKDF), not JWT-shaped.

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

/// Load KWT gate config from the environment. If the master key is unset, KWT auth is disabled.
pub fn kwt_access_from_env() -> Result<Option<KwtAccessConfig>, KwtEnvError> {
    let key_hex = match std::env::var("IMAGE_TRUST_KWT_MASTER_KEY") {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };
    let raw = hex::decode(key_hex.trim()).map_err(|_| KwtEnvError::BadKey)?;
    let master_key = MasterKey::from_bytes(&raw).map_err(|_| KwtEnvError::BadKey)?;
    let audience = std::env::var("IMAGE_TRUST_KWT_AUDIENCE").unwrap_or_else(|_| "rustic".into());
    Ok(Some(KwtAccessConfig {
        master_key,
        audience,
    }))
}
