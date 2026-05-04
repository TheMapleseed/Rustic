//! Axum router composition: public attestation + optionally gated API routes (concurrent by default via Hyper).

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/status", get(protected_status))
        .layer(middleware::from_fn(image_trust_access_gate));

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
        access: "image-trust-token-ok",
    })
}

/// When `IMAGE_TRUST_API_TOKEN` is set, `/v1/protected/*` requires `Authorization: Bearer …` or `X-Image-Trust-Token`.
async fn image_trust_access_gate(
    req: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
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
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .is_some_and(|s| s == expected.as_str());

    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_ok() {
        let app = router(AppState::new(None));
        let res = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
