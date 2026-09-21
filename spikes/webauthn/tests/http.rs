use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use vollmacht_webauthn_probe::{HOST, ORIGIN, http::router};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn app() -> Router {
    router(TOKEN.into()).unwrap()
}
fn request(body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api")
        .header("host", HOST)
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(body.into())
        .unwrap()
}
async fn call(app: &Router, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(request(body.to_string()))
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn boundary_rejects_missing_wrong_and_duplicate_security_headers() {
    for name in ["host", "origin", "content-type", "authorization"] {
        for kind in ["missing", "wrong", "duplicate"] {
            let mut req = request(r#"{"operation":"register"}"#);
            match kind {
                "missing" => {
                    req.headers_mut().remove(name);
                }
                "wrong" => {
                    req.headers_mut()
                        .insert(name, "https://evil.example".parse().unwrap());
                }
                _ => {
                    let value = req.headers()[name].clone();
                    req.headers_mut().append(name, value);
                }
            }
            assert_eq!(
                app().oneshot(req).await.unwrap().status(),
                StatusCode::FORBIDDEN,
                "{name} {kind}"
            );
        }
    }
}

#[tokio::test]
async fn cross_site_same_site_null_origin_query_and_preflight_are_denied() {
    for site in ["cross-site", "same-site", "invalid"] {
        let mut req = request(r#"{"operation":"register"}"#);
        req.headers_mut()
            .insert("sec-fetch-site", site.parse().unwrap());
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    for uri in ["/api?token=secret", "http://evil.example/api"] {
        let mut req = request(r#"{"operation":"register"}"#);
        *req.uri_mut() = uri.parse().unwrap();
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut req = request("");
    *req.method_mut() = axum::http::Method::OPTIONS;
    assert_eq!(
        app().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut req = request("");
    req.headers_mut().insert("origin", "null".parse().unwrap());
    assert_eq!(
        app().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn malformed_unknown_and_duplicate_commands_are_rejected_without_reflection() {
    for body in [
        "not-json SECRET",
        r#"{"operation":"unknown"}"#,
        r#"{"operation":"register","extra":"SECRET"}"#,
        r#"{"operation":"register","operation":"register"}"#,
    ] {
        let response = app().oneshot(request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("SECRET"));
    }
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    assert_eq!(
        app()
            .oneshot(request("x".repeat(65_537)))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn static_assets_and_rejections_have_security_headers_and_no_token() {
    for uri in ["/", "/app.js", "/style.css", "/missing"] {
        let req = Request::builder()
            .uri(uri)
            .header("host", HOST)
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
        let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_registration_and_concurrent_authentication_replay() {
    let app = app();
    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let origin = Url::parse(ORIGIN).unwrap();
    let (status, start) = call(&app, json!({"operation":"register"})).await;
    assert_eq!(status, StatusCode::OK);
    let mut options: CreationChallengeResponse =
        serde_json::from_value(start["options"].clone()).unwrap();
    // SoftPasskey cannot satisfy the client-side platform hint. Server UV remains required.
    assert_eq!(
        start["options"]["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .authenticator_attachment = None;
    let credential = auth.do_registration(origin.clone(), options).unwrap();
    let (status, _) = call(
        &app,
        json!({"operation":"finish_registration","id":start["id"],"credential":credential}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, start) = call(&app, json!({"operation":"authenticate"})).await;
    let options: RequestChallengeResponse =
        serde_json::from_value(start["options"].clone()).unwrap();
    let credential = auth.do_authentication(origin, options).unwrap();
    let body =
        json!({"operation":"finish_authentication","id":start["id"],"credential":credential});
    let a = {
        let app = app.clone();
        let body = body.clone();
        tokio::spawn(async move { call(&app, body).await })
    };
    let b = {
        let app = app.clone();
        tokio::spawn(async move { call(&app, body).await })
    };
    let mut statuses = [a.await.unwrap().0.as_u16(), b.await.unwrap().0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
}
