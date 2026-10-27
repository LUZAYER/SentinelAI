# Security & Hardening

SentinelAI is designed with defense-in-depth principles to protect both the platform and its users.

## Authentication
- Passwords are automatically hashed using Bcrypt before storage.
- JWT (JSON Web Tokens) are used for stateless authentication.
- Endpoints are protected via dependency injection (`Depends(get_current_user)`).

## Protections
- **CORS**: Cross-Origin Resource Sharing is strictly enforced.
- **Rate Limiting**: Configured in middleware to prevent DoS attacks against authentication endpoints.
- **SSRF Prevention**: The Phishing detector strictly validates all URLs before initiating HTTP requests to prevent Server-Side Request Forgery.
- **Upload Validation**: File uploads are strictly validated against a MIME type whitelist and a hard size limit (default 100MB).

## Execution Isolation
SentinelAI never executes uploaded binaries or documents directly. All static analysis (e.g., PE header parsing, string extraction) is performed safely via Python abstractions (e.g., `pefile`) to prevent malware execution on the host machine.
