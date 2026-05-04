use std::sync::Arc;

use crate::kwt_access::KwtAccessConfig;

/// Cheaply cloneable server state (`Arc` inside) for concurrent Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Full signed JSON envelope for `GET /.well-known/rustic-image-trust.json` (callers verify ECDSA offline).
    pub image_trust_attestation: Option<Arc<str>>,
    /// When set, `/v1/protected/*` requires a valid [KWT](https://github.com/TheMapleseed/KWT) (not a static bearer).
    pub kwt_access: Option<Arc<KwtAccessConfig>>,
}

impl AppState {
    #[must_use]
    pub fn new(
        image_trust_attestation: Option<Arc<str>>,
        kwt_access: Option<KwtAccessConfig>,
    ) -> Self {
        Self {
            image_trust_attestation,
            kwt_access: kwt_access.map(Arc::new),
        }
    }
}
