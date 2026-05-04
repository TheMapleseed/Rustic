use std::sync::Arc;

/// Cheaply cloneable server state (`Arc` inside) for concurrent Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Full signed JSON envelope for `GET /.well-known/rustic-image-trust.json` (callers verify ECDSA offline).
    pub image_trust_attestation: Option<Arc<str>>,
}

impl AppState {
    #[must_use]
    pub fn new(image_trust_attestation: Option<Arc<str>>) -> Self {
        Self {
            image_trust_attestation,
        }
    }
}
