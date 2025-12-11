[![Cargo Check](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/check.yml/badge.svg)](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/check.yml)
[![Cargo Format](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/format.yml/badge.svg)](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/format.yml)
[![Lint](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/lint.yml/badge.svg)](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/lint.yml)
[![Cargo Audit](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/audit.yml/badge.svg)](https://github.com/cavebatsofware/axum-tower-sessions-csrf/actions/workflows/audit.yml)
[![crates.io](https://img.shields.io/crates/v/basic-axum-rate-limit.svg)](https://crates.io/crates/basic-axum-rate-limit)

# axum-tower-sessions-csrf

[![Crates.io](https://img.shields.io/crates/v/axum-tower-sessions-csrf.svg)](https://crates.io/crates/axum-tower-sessions-csrf)
[![Documentation](https://docs.rs/axum-tower-sessions-csrf/badge.svg)](https://docs.rs/axum-tower-sessions-csrf)
[![License](https://img.shields.io/crates/l/axum-tower-sessions-csrf.svg)](https://github.com/yourusername/axum-tower-sessions-csrf#license)

CSRF protection for Axum using tower-sessions, implementing the **Synchronizer Token Pattern** as recommended by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

## Features

- **Cryptographically secure** token generation
- **Session-based** token storage (no cookies needed)
- **Constant-time** token validation (prevents timing attacks)
- **Automatic** validation on POST/PUT/DELETE/PATCH requests
- **Simple** integration with existing Axum applications
- **Lightweight** with minimal dependencies

## Installation

```toml
[dependencies]
axum-tower-sessions-csrf = "0.1"
tower-sessions = "0.14"
```

## Quick Start

```rust
use axum::{routing::{get, post}, Router};
use axum::middleware::from_fn;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use axum_tower_sessions_csrf::CsrfMiddleware;

#[tokio::main]
async fn main() {
    // Setup session layer
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    // Build your app with CSRF protection
    let app = Router::new()
        .route("/", get(index))
        .route("/submit", post(submit))
        .layer(from_fn(CsrfMiddleware::middleware))  // Add CSRF middleware
        .layer(session_layer);                        // Session layer must be last

    // Run your server...
}
```

## Usage

### Backend: Get CSRF Token

```rust
use tower_sessions::Session;
use axum::Json;
use axum_tower_sessions_csrf::get_or_create_token;

async fn get_token(session: Session) -> Result<Json<String>, String> {
    let token = get_or_create_token(&session).await?;
    Ok(Json(token))
}
```

### Frontend: Include Token in Requests

```javascript
// Fetch CSRF token
const response = await fetch('/api/csrf-token');
const { token } = await response.json();

// Include in state-changing requests
await fetch('/api/submit', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': token,  // Required header
    },
    body: JSON.stringify(data),
});
```

## How It Works

1. **Token Generation**: Generates a 64-character hex token (32 random bytes)
2. **Session Storage**: Stores token server-side in tower-sessions
3. **Header Validation**: Validates `x-csrf-token` header on POST/PUT/DELETE/PATCH
4. **Constant-Time Comparison**: Prevents timing attacks during validation

## Security Considerations

- Tokens are stored server-side (not in cookies)
- Constant-time comparison prevents timing attacks
- Cryptographically secure random token generation
- Follows OWASP best practices https://devguide.owasp.org/

## License

Licensed under either of:

- GNU Lesser General Public License v3.0 or later ([LICENSE-LGPL3](LICENSE-LGPL3.md) or https://www.gnu.org/licenses/lgpl-3.0.html)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
