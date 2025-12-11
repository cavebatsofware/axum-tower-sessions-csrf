/*
 * Copyright (C) 2025 Grant DeFayette
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR MIT
 *
 * This file is part of axum-tower-sessions-csrf.
 *
 * Licensed under either of:
 *   - GNU Lesser General Public License v3.0 or later (LICENSE-LGPL3)
 *   - MIT license (LICENSE-MIT)
 * at your option.
 */

//! CSRF token validation middleware

use crate::{get_or_create_token, TOKEN_HEADER};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tower_sessions::Session;

/// CSRF protection middleware
///
/// Provides methods for validating CSRF tokens on state-changing requests.
pub struct CsrfMiddleware;

impl CsrfMiddleware {
    /// Axum middleware function for CSRF protection
    ///
    /// This middleware validates CSRF tokens on state-changing HTTP requests.
    /// It follows the OWASP Synchronizer Token Pattern.
    ///
    /// # Behavior
    ///
    /// - **Validates**: POST, PUT, DELETE, PATCH requests must include valid token
    /// - **Allows**: GET, HEAD, OPTIONS requests without validation
    /// - **Returns 403**: If token is missing or invalid
    /// - **Returns 500**: If session operations fail
    ///
    /// # Security Properties
    ///
    /// - Uses constant-time comparison to prevent timing attacks
    /// - Stores tokens server-side in sessions (not in cookies)
    /// - Tokens are cryptographically secure random values
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use axum::Router;
    /// use axum::middleware::from_fn;
    /// use axum_tower_sessions_csrf::CsrfMiddleware;
    ///
    /// let app = Router::new()
    ///     .route("/api/data", post(update_data))
    ///     .layer(from_fn(CsrfMiddleware::middleware));
    /// ```
    pub async fn middleware(session: Session, request: Request<Body>, next: Next) -> Response {
        let method = request.method();
        let path = request.uri().path();

        // Ensure CSRF token exists in session and get it
        let token = match get_or_create_token(&session).await {
            Ok(t) => t,
            Err(e) => {
                #[cfg(feature = "tracing")]
                tracing::error!("CSRF: Failed to get/create token: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Session error").into_response();
            }
        };

        // Only validate state-changing requests
        if matches!(
            method,
            &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
        ) {
            // Validate token from request header
            if !Self::validate_token(request.headers(), &token) {
                #[cfg(feature = "tracing")]
                tracing::warn!("CSRF: Invalid token for {} {}", method, path);
                return (
                    StatusCode::FORBIDDEN,
                    "Invalid or missing CSRF token. Please refresh and try again.",
                )
                    .into_response();
            }

            #[cfg(feature = "tracing")]
            tracing::debug!("CSRF: Token validated for {} {}", method, path);
        }

        // Run the request
        next.run(request).await
    }

    /// Validate CSRF token using constant-time comparison
    ///
    /// Compares the token from the request header against the expected session token.
    /// Uses constant-time comparison to prevent timing attacks.
    fn validate_token(headers: &HeaderMap, session_token: &str) -> bool {
        if let Some(header_value) = headers.get(TOKEN_HEADER) {
            if let Ok(header_token) = header_value.to_str() {
                return Self::constant_time_eq(header_token.as_bytes(), session_token.as_bytes());
            }
        }
        false
    }

    /// Constant-time equality comparison
    ///
    /// Compares two byte slices in constant time to prevent timing attacks.
    /// This is critical for security - variable-time comparison could leak
    /// information about the correct token through timing analysis.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(CsrfMiddleware::constant_time_eq(b"test", b"test"));
        assert!(CsrfMiddleware::constant_time_eq(b"", b""));
        assert!(CsrfMiddleware::constant_time_eq(
            b"long_token_value_12345",
            b"long_token_value_12345"
        ));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!CsrfMiddleware::constant_time_eq(b"test", b"fail"));
        assert!(!CsrfMiddleware::constant_time_eq(b"test", b"Test"));
        assert!(!CsrfMiddleware::constant_time_eq(b"a", b"b"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!CsrfMiddleware::constant_time_eq(b"test", b"test1"));
        assert!(!CsrfMiddleware::constant_time_eq(b"test1", b"test"));
        assert!(!CsrfMiddleware::constant_time_eq(b"", b"x"));
    }
}
