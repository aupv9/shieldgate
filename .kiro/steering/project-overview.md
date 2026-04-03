# ShieldGate Project Overview

ShieldGate là một OAuth 2.0 và OpenID Connect Authorization Server được xây dựng bằng Go, tuân thủ đầy đủ các tiêu chuẩn bảo mật hiện đại.

## Thông tin dự án
- **Tên dự án**: ShieldGate - OAuth 2.0 Authorization Server
- **Ngôn ngữ**: Go 1.21+
- **Kiến trúc**: Microservice với thiết kế stateless
- **Database**: PostgreSQL với Redis cache
- **Framework**: Gin web framework

## Cấu trúc thư mục chính
```
shieldgate/
├── cmd/auth-server/          # Entry point của ứng dụng
├── internal/
│   ├── handlers/             # HTTP handlers (controllers)
│   ├── services/             # Business logic layer
│   ├── models/               # Data models và database schemas
│   ├── database/             # Database connection và Redis
│   └── middleware/           # HTTP middleware
├── config/                   # Configuration management
├── docs/                     # Tài liệu kỹ thuật
├── templates/                # HTML templates
└── tests/                    # Test utilities
```

## Các tính năng chính
- OAuth 2.0 compliance (RFC 6749)
- OpenID Connect (OIDC) support
- PKCE (Proof Key for Code Exchange) cho public clients
- JWT token generation và validation
- Client management (dynamic registration)
- User management với bcrypt password hashing
- Rate limiting và CORS support
- Comprehensive logging và monitoring

## Flows được hỗ trợ
- Authorization Code Flow (với PKCE)
- Client Credentials Flow
- Refresh Token Flow
- Token Introspection và Revocation

## Security features
- HTTPS/TLS mandatory
- bcrypt password hashing với configurable cost
- JWT với secure signing
- Input validation và sanitization
- Rate limiting chống brute-force
- Audit logging cho security events