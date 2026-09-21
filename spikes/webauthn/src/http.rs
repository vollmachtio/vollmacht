//! Browser boundary: no cookies, CORS, persistence, credential logging, or GitHub access.

use crate::{
    HOST, ORIGIN,
    ceremony::{Ceremonies, Error},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

struct App {
    bearer: String,
    ceremonies: Mutex<Ceremonies>,
}

pub fn router(token: String) -> Result<Router, webauthn_rs::prelude::WebauthnError> {
    let app = Arc::new(App {
        bearer: format!("Bearer {token}"),
        ceremonies: Mutex::new(Ceremonies::new()?),
    });
    Ok(Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [("content-type", "text/html; charset=utf-8")],
                    include_str!("../web/index.html"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route("/api", post(command))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), boundary))
        .with_state(app))
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn permitted(request: &Request, app: &App) -> bool {
    let headers = request.headers();
    if single(headers, "host") != Some(HOST) || request.uri().query().is_some() {
        return false;
    }
    if let Some(authority) = request.uri().authority()
        && authority.as_str() != HOST
    {
        return false;
    }
    if headers.contains_key("sec-fetch-site")
        && !matches!(
            single(headers, "sec-fetch-site"),
            Some("same-origin" | "none")
        )
    {
        return false;
    }
    if request.uri().path() == "/api" {
        return request.method() == axum::http::Method::POST
            && single(headers, "origin") == Some(ORIGIN)
            && single(headers, "content-type") == Some("application/json")
            && single(headers, "authorization")
                .is_some_and(|value| bool::from(value.as_bytes().ct_eq(app.bearer.as_bytes())));
    }
    true
}

async fn boundary(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let mut response = if permitted(&request, &app) {
        // Bounds body reception after headers. This is not a general-purpose DoS defense.
        tokio::time::timeout(std::time::Duration::from_secs(5), next.run(request))
            .await
            .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
    } else {
        StatusCode::FORBIDDEN.into_response()
    };
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, value.parse().expect("constant header"));
    }
    response
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Register {},
    Authenticate {},
    FinishRegistration {
        id: String,
        credential: RegisterPublicKeyCredential,
    },
    FinishAuthentication {
        id: String,
        credential: PublicKeyCredential,
    },
    Cancel {
        id: String,
    },
}

async fn command(State(app): State<Arc<App>>, body: Bytes) -> Response {
    // Do not reflect parser errors or credential bytes in responses or logs.
    let Ok(command) = serde_json::from_slice::<Command>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_request"})),
        )
            .into_response();
    };
    let Ok(mut ceremonies) = app.ceremonies.lock() else {
        return failure(Error::Internal);
    };
    // Read time inside the serialization boundary, not before waiting for the mutex.
    let now = Instant::now();
    let result = match command {
        Command::Register {} => ceremonies
            .start_registration(now)
            .map(|(id, options)| json!({"id":id,"options":options})),
        Command::Authenticate {} => ceremonies
            .start_authentication(now)
            .map(|(id, options)| json!({"id":id,"options":options})),
        Command::FinishRegistration { id, credential } => ceremonies
            .finish_registration(&id, &credential, now)
            .map(|()| json!({"status":"registered"})),
        Command::FinishAuthentication { id, credential } => ceremonies
            .finish_authentication(&id, &credential, now)
            .map(|()| json!({"status":"verified","user_verified":true})),
        Command::Cancel { id } => ceremonies
            .cancel(&id, now)
            .map(|()| json!({"status":"cancelled"})),
    };
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => failure(error),
    }
}

fn failure(error: Error) -> Response {
    let (status, code) = match error {
        Error::Busy => (StatusCode::CONFLICT, "ceremony_pending"),
        Error::AlreadyRegistered => (StatusCode::CONFLICT, "already_registered"),
        Error::NotRegistered => (StatusCode::CONFLICT, "not_registered"),
        Error::NoMatchingCeremony => (StatusCode::CONFLICT, "missing_or_expired_ceremony"),
        Error::VerificationFailed => (StatusCode::UNAUTHORIZED, "verification_failed"),
        Error::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    (status, Json(json!({"error":code}))).into_response()
}
