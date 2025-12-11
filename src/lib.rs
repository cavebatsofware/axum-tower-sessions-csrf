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

//! # axum-tower-sessions-csrf
//!
//! CSRF protection for Axum using tower-sessions, implementing the
//! [Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
//! as recommended by OWASP.
//!
//! ## Features
//!
//! - 🔒 Cryptographically secure token generation
//! - 📦 Session-based token storage (no cookies needed)
//! - ⚡ Constant-time token validation (prevents timing attacks)
//! - 🎯 Automatic validation on POST/PUT/DELETE/PATCH requests
//! - 🔧 Simple integration with existing Axum applications
//! - 🪶 Lightweight with minimal dependencies
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use axum::middleware::from_fn;
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//! use axum_tower_sessions_csrf::CsrfMiddleware;
//!
//! #[tokio::main]
//! async fn main() {
//!     let session_store = MemoryStore::default();
//!     let session_layer = SessionManagerLayer::new(session_store);
//!
//!     let app = Router::new()
//!         .route("/", get(|| async { "Hello!" }))
//!         .layer(from_fn(CsrfMiddleware::middleware))
//!         .layer(session_layer);
//!
//!     // Run your app...
//! }
//! ```
//!
//! ## Usage
//!
//! 1. Add the middleware to your router (must be after `SessionManagerLayer`)
//! 2. Clients fetch CSRF token via [`get_or_create_token`]
//! 3. Include token in `x-csrf-token` header for state-changing requests
//!
//! See the [examples](https://github.com/yourusername/axum-tower-sessions-csrf/tree/main/examples)
//! for complete working code.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod token;
mod validation;

pub use token::{generate_token, get_or_create_token};
pub use validation::CsrfMiddleware;

/// CSRF token session key (used internally by the middleware)
pub const TOKEN_KEY: &str = "csrf_token";

/// CSRF token HTTP header name
pub const TOKEN_HEADER: &str = "x-csrf-token";
