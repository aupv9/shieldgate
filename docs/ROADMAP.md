# ShieldGate — Roadmap hoàn thiện Core Features (AuthZ Server)

> Trạng thái khảo sát: 2026-08-01, branch `claude/auth-server-production-ready-n982ew`.
> Mục tiêu: đưa ShieldGate từ mức "hoạt động được" lên mức **production-ready, tuân thủ chuẩn OAuth 2.0 / OIDC**.

## 1. Hiện trạng

### Đã có (hoạt động)
- Authorization Code + PKCE (S256), Refresh Token grant, Client Credentials grant
- Token introspection (RFC 7662), revocation (RFC 7009) — ở mức cơ bản
- OIDC Discovery, JWKS (stub), UserInfo, ID Token (HS256)
- Multi-tenancy (tenant CRUD, X-Tenant-ID), User/Client CRUD, RBAC đầy đủ, Audit logging
- Rate limiting per-IP qua Redis, account lockout sau N lần login sai, login page HTML

### Gap đã xác định (theo file:line)

| # | Gap | Vị trí | Mức độ |
|---|-----|--------|--------|
| G1 | Client secret lưu **plaintext**, so sánh `!=` (không constant-time) | `internal/services/client_service_impl.go:204`, `models.go:204` | 🔴 Critical |
| G2 | Access/refresh token lưu **plaintext** trong DB | `auth_service_impl.go:135-161` | 🔴 Critical |
| G3 | Introspect & Revoke **không yêu cầu client authentication** (vi phạm RFC 7662 §2.1, RFC 7009 §2.1) | `oauth_handler.go:436-484` | 🔴 Critical |
| G4 | JWT chỉ hỗ trợ **HS256** — client bên thứ 3 không thể verify ID token; JWKS là stub không có key material | `auth_service_impl.go:312,388`, `oauth_handler.go:422-433` | 🔴 Critical |
| G5 | `nonce` nhận ở /authorize nhưng **không lưu vào auth code, không đưa vào ID token** (vi phạm OIDC Core §3.1.3.7) | `oauth_handler.go:87`, `models.go:216-228` | 🔴 Critical |
| G6 | **Scope không được validate** với `client.Scopes`; grant type không check với `client.GrantTypes` | `oauth_handler.go`, `auth_service_impl.go` | 🔴 Critical |
| G7 | Refresh grant **mất scope** (`GenerateTokens(..., "", false)`), không reuse-detection, không revoke token family | `auth_service_impl.go:204` | 🔴 Critical |
| G8 | Revoke JWT xong **token vẫn valid** — `ValidateAccessToken` chỉ check chữ ký, không check DB/denylist | `auth_service_impl.go:264-285`, `middleware.go` | 🔴 Critical |
| G9 | Login form **không có CSRF protection** | `oauth_handler.go:132`, `templates/login.html` | 🟠 High |
| G10 | Auth code exchange không atomic (race → dùng code 2 lần); code reuse không revoke token đã cấp (RFC 6749 §4.1.2) | `auth_service_impl.go:70-119` | 🟠 High |
| G11 | client_credentials **cấp cả refresh token** (sai RFC 6749 §4.4.3), user_id = uuid.Nil lưu vào DB | `oauth_handler.go:365` | 🟠 High |
| G12 | Chỉ hỗ trợ `client_secret_post`, chưa có `client_secret_basic` (Authorization header) | `oauth_handler.go:267-283` | 🟠 High |
| G13 | **Không có session/SSO** — mỗi lần authorize phải login lại; không có `prompt=`, `max_age`, logout | toàn bộ flow | 🟠 High |
| G14 | **Không có consent screen** — auto-approve mọi scope sau login | `oauth_handler.go:195` | 🟠 High |
| G15 | Discovery thiếu `grant_types_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`, `revocation_endpoint`, `introspection_endpoint` | `auth_service_impl.go:342-355` | 🟡 Medium |
| G16 | ID token thiếu `auth_time`, `at_hash`; expiry hardcode 1h | `auth_service_impl.go:300-314` | 🟡 Medium |
| G17 | UserInfo: `email_verified` hardcode `true`, không trả claims theo scope (profile/email) | `auth_service_impl.go:334-339` | 🟡 Medium |
| G18 | Tenant resolution qua header `X-Tenant-ID` — không khả thi cho browser redirect flow | `middleware.go`, tất cả handlers | 🟡 Medium |
| G19 | Helper `contains()` cho scope matching có logic lỗi | `auth_service_impl.go:401-406` | 🟡 Medium |
| G20 | JWT_SECRET tĩnh, không có key rotation | `config` | 🟡 Medium |
| G21 | Idempotency key TODO chưa làm | `tenant_handler.go:71` | 🟢 Low |
| G22 | Email verification / password reset stub trong UserService | `user_service_impl.go:305-317` | 🟢 Low |

---

## 2. Roadmap theo Phase

### Phase 1 — Security Hardening lõi ✅ HOÀN THÀNH (2026-08-02)
> Mục tiêu: vá các lỗ hổng khiến server không thể deploy production. Không đổi API surface.

| Task | Gaps | Trạng thái |
|------|------|-----------|
| 1.1 Hash client secret | G1 | ✅ bcrypt hash trong DB, plaintext chỉ trả 1 lần ở response Create (`PlainClientSecret`); secret 256-bit từ crypto/rand |
| 1.2 Hash token trong DB | G2 | ✅ SHA-256(token) cho cả access & refresh token; lookup theo hash |
| 1.3 Client auth cho introspect/revoke | G3 | ✅ Introspect yêu cầu confidential client; revoke yêu cầu client auth + chỉ revoke token thuộc client đó |
| 1.4 `client_secret_basic` | G12 | ✅ `clientCredentialsFromRequest` hỗ trợ Basic (có URL-decode per RFC 6749 §2.3.1) + form post ở mọi endpoint |
| 1.5 Validate scope & grant type | G6, G19 | ✅ `services/scope.go` (ParseScope/ScopeIsSubset/ValidateScopeForClient); check `client.GrantTypes` ở authorize + mọi grant; `contains()` lỗi đã xoá |
| 1.6 Refresh token rotation đúng | G7 | ✅ Giữ scope gốc, cho phép narrow, cấp ID token nếu `openid`; `family_id` + `revoked_at` → replay = revoke cả family |
| 1.7 Auth code atomic + reuse revoke | G10 | ✅ `Consume` = UPDATE...RETURNING atomic đánh dấu `used_at`; reuse → revoke token family (family = authCode.ID) |
| 1.8 Enforce revocation | G8 | ✅ `ValidateAccessToken` check record còn sống trong token store; `RequireAuth` nhận validator để chặn JWT đã revoke ở management API |
| 1.9 CSRF cho login form | G9 | ✅ Signed double-submit cookie (HMAC-SHA256, HttpOnly, SameSite=Lax) — hidden field + cookie phải khớp |
| 1.10 Sửa client_credentials | G11 | ✅ `GenerateClientCredentialsTokens`: không refresh token, `sub = client.ID`; chặn public client dùng grant này |

Bổ sung ngoài kế hoạch: PKCE compare dùng constant-time; `email_verified` trong UserInfo lấy từ user record thay vì hardcode; fix panic khi render login page với client nil.

### Phase 2 — OIDC Compliance ✅ HOÀN THÀNH (2026-08-02)

| Task | Gaps | Trạng thái |
|------|------|-----------|
| 2.1 Ký bất đối xứng RS256 | G4 | ✅ RSA-2048 tự bootstrap vào bảng `signing_keys`, header `kid`; HS256 giữ làm verify-fallback cho token cũ |
| 2.2 JWKS thật + key rotation | G4, G20 | ✅ `/.well-known/jwks.json` publish public key của mọi key đang phục vụ; `RotateSigningKey` — key cũ vẫn verify (zero-downtime) |
| 2.3 Nonce end-to-end | G5 | ✅ authorize → login form → cột `nonce` trong auth code → claim trong ID token |
| 2.4 ID token đầy đủ claims | G16 | ✅ `auth_time` (thời điểm login thật), `at_hash` (bind access token), expiry theo `ID_TOKEN_DURATION` |
| 2.5 UserInfo theo scope | G17 | ✅ Claims trả theo scope profile/email (given_name, family_name, preferred_username, locale, zoneinfo…) |
| 2.6 Discovery đầy đủ | G15 | ✅ revocation/introspection/end_session/registration endpoints, token_endpoint_auth_methods, code_challenge_methods |

### Phase 3 — Session, Consent & SSO ✅ HOÀN THÀNH (2026-08-02)

| Task | Gaps | Trạng thái |
|------|------|-----------|
| 3.1 Server-side session | G13 | ✅ Bảng `user_sessions` (token hash SHA-256), cookie HttpOnly+SameSite=Lax; /authorize có session → bỏ qua login |
| 3.2 `prompt` & `max_age` | G13 | ✅ `prompt=login/consent/none` với `login_required`/`consent_required`; `max_age` ép re-login khi authentication cũ |
| 3.3 Consent screen | G14 | ✅ Trang consent liệt kê scope; grant lưu per (user, client) trong `user_consents`, cộng dồn — đã grant thì skip |
| 3.4 Logout | G13 | ✅ `/oauth/logout` (end_session_endpoint): revoke session, clear cookie, `post_logout_redirect_uri` chỉ theo URI đã đăng ký |
| 3.5 Tenant theo domain | G18 | ✅ `TenantContext` nhận resolver Host→tenant (wired `GetByDomain`); browser flow không cần X-Tenant-ID |

### Bổ sung — Grant types mở rộng ✅ HOÀN THÀNH (2026-08-02)

| Task | Trạng thái |
|------|-----------|
| Device Authorization Grant (RFC 8628) | ✅ `POST /oauth/device_authorization` (client auth + scope/grant validation), trang xác thực `GET/POST /oauth/device` (CSRF, approve/deny), polling qua token endpoint với đủ error codes (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`); device_code hash SHA-256, user_code 8 ký tự không nhầm lẫn, single-use, bind client |
| Token Exchange (RFC 8693) | ✅ `grant_type=token-exchange` trên token endpoint; chỉ confidential client; subject_token phải là access token còn sống; scope = subset của cả subject token lẫn client registration; token mới giữ nguyên `sub`, ghi delegation qua claim `act` |
| Discovery mở rộng | ✅ `device_authorization_endpoint` + `grant_types_supported` trong OIDC discovery |

### Phase 4 — Nâng cao & Production Ops ✅ HOÀN THÀNH PHẦN LỚN (2026-08-02)

| Task | Trạng thái |
|------|-----------|
| 4.1 MFA (TOTP) | ✅ RFC 6238 tự implement (SHA-1, 6 số, ±1 step); enroll/activate/disable qua `/v1/users/:id/mfa/*`; login flow 2 bước với signed state token 5 phút + trang `mfa.html` |
| 4.2 Dynamic Client Registration | ✅ `POST /oauth/register` (RFC 7591) sau RequireAuth; `token_endpoint_auth_method=none` → public client; publish `registration_endpoint` |
| 4.3 Email flows | ✅ Endpoints public `/auth/verify-email`, `/auth/request-password-reset` (không lộ account tồn tại), `/auth/reset-password`; protected `/v1/users/:id/send-verification` |
| 4.4 Idempotency key | ✅ Middleware `Idempotency()` trên nhóm /v1: replay response đã lưu (Redis, TTL 24h) theo header `Idempotency-Key`; không cache 5xx |
| 4.5 Observability | ✅ `/metrics` Prometheus text format (requests theo method/route/status, duration, in-flight, uptime) — không thêm dependency; Redis giờ được attach vào request context (fix rate limiting trước đây không hoạt động) |
| 4.6 Conformance & load test | ⏳ Còn lại: chạy OIDC conformance suite + k6 load test (cần môi trường deploy) |

Ghi chú còn lại cho production: mã hoá at-rest cho `mfa_secret`/`signing_keys` (KMS), OpenTelemetry tracing, back-channel logout, và endpoint quản trị cho `RotateSigningKey`.

---

## 3. Thứ tự thực thi đề xuất

```mermaid
gantt
    dateFormat  YYYY-MM-DD
    title ShieldGate Core Roadmap
    section Phase 1 — Security
    Hash secrets & tokens (1.1, 1.2)        :p1a, 2026-08-03, 3d
    Client auth introspect/revoke (1.3, 1.4):p1b, after p1a, 2d
    Scope/grant validation (1.5)            :p1c, after p1a, 2d
    Refresh rotation + code atomic (1.6, 1.7):p1d, after p1c, 3d
    Revocation enforcement + CSRF (1.8-1.10):p1e, after p1d, 2d
    section Phase 2 — OIDC
    RS256 + JWKS + rotation (2.1, 2.2)      :p2a, after p1e, 4d
    Nonce + ID token claims (2.3, 2.4)      :p2b, after p2a, 2d
    UserInfo + Discovery (2.5, 2.6)         :p2c, after p2b, 2d
    section Phase 3 — Session
    Session + prompt (3.1, 3.2)             :p3a, after p2c, 4d
    Consent + Logout (3.3, 3.4)             :p3b, after p3a, 4d
    Tenant by domain (3.5)                  :p3c, after p3b, 2d
    section Phase 4 — Advanced
    MFA / DCR / Email / Observability       :p4, after p3c, 14d
```

Nguyên tắc:
- Phase 1 làm **trước và trọn vẹn** — mọi thứ sau đều xây trên nền security đúng.
- Mỗi task = 1 PR riêng, kèm unit + integration test, giữ coverage ≥ 80%.
- Migration DB (hash secret/token, cột nonce, family_id) viết theo kiểu expand-migrate-contract để không downtime.
