use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    middleware::from_fn,
    routing::{delete, get, patch, post, put},
    Router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

use axum_tower_sessions_csrf::{get_or_create_token, CsrfMiddleware, TOKEN_HEADER};

fn build_app() -> Router {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    Router::new()
        .route("/", get(|| async { "hello" }))
        .route(
            "/token",
            get(|session: Session| async move { get_or_create_token(&session).await.unwrap() }),
        )
        .route("/post", post(|| async { "post ok" }))
        .route("/put", put(|| async { "put ok" }))
        .route("/delete", delete(|| async { "delete ok" }))
        .route("/patch", patch(|| async { "patch ok" }))
        .layer(from_fn(CsrfMiddleware::middleware))
        .layer(session_layer)
}

fn extract_session_cookie(response: &axum::http::Response<Body>) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|val| {
            let s = val.to_str().ok()?;
            Some(s.split(';').next()?.to_string())
        })
}

async fn get_token_and_cookie(app: &Router) -> (String, String) {
    let req = Request::builder()
        .uri("/token")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let cookie = extract_session_cookie(&response).expect("should have session cookie");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let token = String::from_utf8(body.to_vec()).unwrap();

    (token, cookie)
}

// --- Safe methods pass through without token ---

#[tokio::test]
async fn test_get_passes_without_token() {
    let app = build_app();
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello");
}

#[tokio::test]
async fn test_head_passes_without_token() {
    let app = build_app();
    let req = Request::builder()
        .method(Method::HEAD)
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    // HEAD on a GET route should not return 403
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_options_passes_without_token() {
    let app = build_app();
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

// --- State-changing methods rejected without token ---

#[tokio::test]
async fn test_post_without_token_returns_403() {
    let app = build_app();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/post")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_put_without_token_returns_403() {
    let app = build_app();
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/put")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_delete_without_token_returns_403() {
    let app = build_app();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/delete")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_patch_without_token_returns_403() {
    let app = build_app();
    let req = Request::builder()
        .method(Method::PATCH)
        .uri("/patch")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// --- State-changing methods pass with valid token ---

#[tokio::test]
async fn test_post_with_valid_token_passes() {
    let app = build_app();
    let (token, cookie) = get_token_and_cookie(&app).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/post")
        .header("cookie", &cookie)
        .header(TOKEN_HEADER, &token)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"post ok");
}

#[tokio::test]
async fn test_put_with_valid_token_passes() {
    let app = build_app();
    let (token, cookie) = get_token_and_cookie(&app).await;

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/put")
        .header("cookie", &cookie)
        .header(TOKEN_HEADER, &token)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"put ok");
}

#[tokio::test]
async fn test_delete_with_valid_token_passes() {
    let app = build_app();
    let (token, cookie) = get_token_and_cookie(&app).await;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/delete")
        .header("cookie", &cookie)
        .header(TOKEN_HEADER, &token)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"delete ok");
}

#[tokio::test]
async fn test_patch_with_valid_token_passes() {
    let app = build_app();
    let (token, cookie) = get_token_and_cookie(&app).await;

    let req = Request::builder()
        .method(Method::PATCH)
        .uri("/patch")
        .header("cookie", &cookie)
        .header(TOKEN_HEADER, &token)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"patch ok");
}

// --- State-changing methods rejected with wrong token ---

#[tokio::test]
async fn test_post_with_wrong_token_returns_403() {
    let app = build_app();
    let (_token, cookie) = get_token_and_cookie(&app).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/post")
        .header("cookie", &cookie)
        .header(TOKEN_HEADER, "totally_wrong_token")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// --- Token session behavior ---

#[tokio::test]
async fn test_token_created_on_first_request() {
    let app = build_app();
    let (token, _cookie) = get_token_and_cookie(&app).await;

    assert_eq!(token.len(), 64, "Token should be 64 hex characters");
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "Token should only contain hex characters"
    );
}

#[tokio::test]
async fn test_token_is_idempotent() {
    let app = build_app();
    let (token1, cookie) = get_token_and_cookie(&app).await;

    // Second request with same session cookie should return same token
    let req = Request::builder()
        .uri("/token")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let token2 = String::from_utf8(body.to_vec()).unwrap();

    assert_eq!(token1, token2, "Same session should return same token");
}
