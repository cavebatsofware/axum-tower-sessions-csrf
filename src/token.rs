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

//! CSRF token generation and session management

use crate::TOKEN_KEY;
use rand::Rng;
use tower_sessions::Session;

/// Generate a cryptographically secure CSRF token
///
/// Returns a 64-character hexadecimal string (32 bytes of random data).
/// Uses the system's cryptographically secure random number generator.
///
/// # Examples
///
/// ```
/// use axum_tower_sessions_csrf::generate_token;
///
/// let token = generate_token();
/// assert_eq!(token.len(), 64);
/// ```
pub fn generate_token() -> String {
    let token_bytes: [u8; 32] = rand::rng().random();
    hex::encode(token_bytes)
}

/// Get existing CSRF token from session, or create a new one
///
/// This function checks the session for an existing CSRF token.
/// If none exists, it generates a new token and stores it in the session.
///
/// # Arguments
///
/// * `session` - The tower-sessions Session instance
///
/// # Returns
///
/// * `Ok(String)` - The CSRF token
/// * `Err(String)` - Error message if session operations fail
///
/// # Examples
///
/// ```ignore
/// use axum::extract::Extension;
/// use tower_sessions::Session;
/// use axum_tower_sessions_csrf::get_or_create_token;
///
/// async fn handler(session: Session) -> Result<String, String> {
///     let token = get_or_create_token(&session).await?;
///     Ok(format!("Your CSRF token: {}", token))
/// }
/// ```
///
/// # Errors
///
/// Returns an error if session read or write operations fail.
pub async fn get_or_create_token(session: &Session) -> Result<String, String> {
    // Try to retrieve existing token
    if let Some(token) = session
        .get::<String>(TOKEN_KEY)
        .await
        .map_err(|e| format!("Failed to read from session: {e}"))?
    {
        return Ok(token);
    }

    // Generate and store new token
    let token = generate_token();
    session
        .insert(TOKEN_KEY, token.clone())
        .await
        .map_err(|e| format!("Failed to write to session: {e}"))?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let token = generate_token();
        assert_eq!(token.len(), 64, "Token should be 64 hex characters");
    }

    #[test]
    fn test_generate_token_is_hex() {
        let token = generate_token();
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "Token should only contain hex characters"
        );
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2, "Tokens should be unique");
    }

    #[test]
    fn test_multiple_tokens_are_unique() {
        let tokens: Vec<String> = (0..100).map(|_| generate_token()).collect();
        let unique_count = tokens.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, 100, "All generated tokens should be unique");
    }
}
