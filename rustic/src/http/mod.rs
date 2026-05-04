//! Axum router composition: public attestation + protected routes.
//! Protected routes accept either **[KWT](https://github.com/TheMapleseed/KWT)** (`Authorization: KWT …`)
//! when `IMAGE_TRUST_KWT_MASTER_KEY` is configured, or a legacy static **`IMAGE_TRUST_API_TOKEN`**.

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::kwt_access::KwtAccessConfig;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let kwt = state.kwt_access.clone();
    let protected =
        Router::new()
            .route("/status", get(protected_status))
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                let kwt = kwt.clone();
                async move { image_trust_access_gate(req, next, kwt).await }
            }));

    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/rustic-image-trust.json",
            get(well_known_attestation),
        )
        .nest("/v1/protected", protected)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

async fn health() -> &'static str {
    "ok"
}

async fn well_known_attestation(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    match &state.image_trust_attestation {
        Some(json) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json.to_string(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "Rustic image-trust envelope not configured (set IMAGE_TRUST_ENVELOPE after signing)",
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct ProtectedStatus {
    access: &'static str,
}

async fn protected_status() -> Json<ProtectedStatus> {
    Json(ProtectedStatus {
        access: "kwt-or-static-token-ok",
    })
}

/// Prefer **KWT** when `AppState.kwt_access` is set; otherwise optional static `IMAGE_TRUST_API_TOKEN`.
async fn image_trust_access_gate(
    req: Request,
    next: Next,
    kwt_cfg: Option<Arc<KwtAccessConfig>>,
) -> Result<axum::response::Response, StatusCode> {
    if let Some(cfg) = kwt_cfg.as_ref() {
        let Some(token) = extract_kwt_credential(&req) else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let _ = kwt::token::KwtToken::validate(token, &cfg.master_key, cfg.audience.as_str())
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        return Ok(next.run(req).await);
    }

    let Some(expected) = std::env::var("IMAGE_TRUST_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
    else {
        return Ok(next.run(req).await);
    };

    let ok = req
        .headers()
        .get("x-image-trust-token")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s == expected.as_str())
        || req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .is_some_and(|s| s == expected.as_str());

    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

/// `Authorization: KWT <v1.nonce.ciphertext>` or `X-KWT: <same>`.
fn extract_kwt_credential(req: &Request) -> Option<&str> {
    if let Some(v) = req.headers().get("x-kwt").and_then(|h| h.to_str().ok()) {
        let t = v.trim();
        return (!t.is_empty()).then_some(t);
    }
    let auth = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = auth
        .strip_prefix("KWT ")
        .or_else(|| auth.strip_prefix("kwt "))?;
    let t = rest.trim();
    (!t.is_empty()).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use kwt::codec::{self, Role, Scope};
    use kwt::crypto::MasterKey;
    use kwt::token::KwtToken;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_ok() {
        let app = router(AppState::new(None, None));
        let res = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_accepts_kwt() {
        let key = MasterKey::generate();
        let mut claims = codec::new_claims("svc-test", "rustic", 3600);
        claims.roles.push(Role::Service);
        claims.scopes.push(Scope::Admin);
        let token = KwtToken::issue(&claims, &key).unwrap();

        let cfg = KwtAccessConfig {
            master_key: key.clone(),
            audience: "rustic".into(),
        };
        let app = router(AppState::new(None, Some(cfg)));

        let req = Request::get("/v1/protected/status")
            .header(header::AUTHORIZATION, format!("KWT {token}"))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
