# ShieldGate Architecture Design (English Summary)

> **Note**: This is an English summary of the comprehensive Vietnamese architecture design document. For complete technical details, refer to [Thiết kế kiến trúc tổng thể hệ thống Authorization Server.md](Thiết%20kế%20kiến%20trúc%20tổng%20thể%20hệ%20thống%20Authorization%20Server.md).

## 1. Architecture Overview

The ShieldGate Authorization Server is designed using a microservice architecture, focusing on modularity, scalability, and security. It serves as the central identity and authorization management hub for integrated systems, implementing industry standards like OAuth 2.0 and OpenID Connect.

### Core Design Principles

- **Statelessness**: Minimize server-side session storage to enhance scalability and fault tolerance
- **Scalability**: Designed for easy horizontal scaling to handle high concurrent request volumes
- **Security by Design**: Security integrated from the design phase, including encryption, secure key management, and security best practices compliance
- **API-first**: Provides clear, easy-to-use APIs with comprehensive documentation for seamless system integration
- **Observability**: Integrated logging, monitoring, and tracing for easy debugging and performance tracking

## 2. Main System Components

The Authorization Server consists of the following main components:

### API Gateway
- Single entry point for all client requests
- Handles routing, basic authentication, rate limiting, and security
- Load balancing and request distribution

### Authorization Service (Core)
The core service handling main authorization logic:
- **Client Management**: Registration and management of client information
- **User Management**: Registration, authentication, and profile management
- **Token Management**: Creation, validation, and revocation of Access Tokens, Refresh Tokens, and ID Tokens
- **OAuth 2.0 Flow Processing**: Authorization Code, Client Credentials, PKCE, etc.
- **OpenID Connect Processing**: Identity information provision

### Database
- Stores user, client, token, and authorization configuration data
- Supports PostgreSQL for reliability and performance
- Optimized schema for OAuth 2.0/OIDC requirements

### Cache/Key-Value Store
- Redis-based temporary storage for tokens, sessions, and frequently accessed data
- Improves performance and reduces database load
- Configurable TTL for different data types

### Logging & Monitoring System
- Collects and analyzes logs and metrics
- Monitors operational status and detects errors and security issues
- Integration with Prometheus, Grafana, and ELK stack

## 3. Basic Operation Flow (Authorization Code Flow with PKCE)

This is the recommended flow for public clients (mobile apps, SPAs) as it provides enhanced security compared to the Implicit Flow.

### Flow Steps

1. **Client Authorization Request**
   - Client redirects user to `/authorize` endpoint
   - Includes `client_id`, `redirect_uri`, `scope`, `response_type=code`, `code_challenge`, and `code_challenge_method`

2. **User Authentication and Consent**
   - Authorization Server authenticates user (if not logged in)
   - Requests user consent for requested scopes
   - Generates `authorization code` upon user approval

3. **Authorization Server Redirect**
   - Redirects user back to client's `redirect_uri`
   - Includes the `authorization code` in the response

4. **Client Token Request**
   - Client sends `authorization code`, `client_id`, `redirect_uri`, `code_verifier`, and `grant_type=authorization_code`
   - Request sent to `/token` endpoint via secure channel

5. **Authorization Server Token Issuance**
   - Validates `authorization code` and `code_verifier`
   - Issues `Access Token`, `Refresh Token`, and `ID Token` (for OIDC)

6. **Client Resource Access**
   - Client uses `Access Token` to call Resource Server APIs
   - Resource Server validates token via Introspection Endpoint or JWT verification

7. **Access Token Refresh**
   - When `Access Token` expires, client uses `Refresh Token`
   - Requests new `Access Token` from `/token` endpoint with `grant_type=refresh_token`

## 4. Database Schema

### Users Table
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID/INT | Unique user identifier |
| `username` | VARCHAR(255) | Login username (unique) |
| `email` | VARCHAR(255) | User email (unique) |
| `password_hash` | VARCHAR(255) | Hashed password |
| `created_at` | TIMESTAMP | Account creation time |
| `updated_at` | TIMESTAMP | Last update time |

### Clients Table
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID/INT | Unique client identifier |
| `client_id` | VARCHAR(255) | Client ID (unique, public) |
| `client_secret` | VARCHAR(255) | Client Secret (confidential clients only) |
| `name` | VARCHAR(255) | Client application name |
| `redirect_uris` | TEXT[] | Valid redirect URIs array |
| `grant_types` | TEXT[] | Allowed grant types array |
| `scopes` | TEXT[] | Allowed scopes array |
| `is_public` | BOOLEAN | True for public clients (SPA, mobile) |
| `created_at` | TIMESTAMP | Client registration time |
| `updated_at` | TIMESTAMP | Last update time |

### Authorization Codes Table
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID/INT | Unique code identifier |
| `code` | VARCHAR(255) | Authorization code |
| `client_id` | UUID/INT | Client identifier |
| `user_id` | UUID/INT | User identifier |
| `redirect_uri` | VARCHAR(255) | Used redirect URI |
| `scope` | TEXT | Granted scope |
| `code_challenge` | VARCHAR(255) | PKCE code challenge |
| `code_challenge_method` | VARCHAR(50) | Challenge method (S256, plain) |
| `expires_at` | TIMESTAMP | Code expiration time |
| `created_at` | TIMESTAMP | Code creation time |

### Access Tokens Table
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID/INT | Unique token identifier |
| `token` | VARCHAR(255) | Access Token value (JWT) |
| `client_id` | UUID/INT | Client identifier |
| `user_id` | UUID/INT | User identifier |
| `scope` | TEXT | Granted scope |
| `expires_at` | TIMESTAMP | Token expiration time |
| `created_at` | TIMESTAMP | Token creation time |

### Refresh Tokens Table
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID/INT | Unique token identifier |
| `token` | VARCHAR(255) | Refresh Token value |
| `client_id` | UUID/INT | Client identifier |
| `user_id` | UUID/INT | User identifier |
| `expires_at` | TIMESTAMP | Token expiration time |
| `created_at` | TIMESTAMP | Token creation time |

## 5. API Endpoints

### OAuth 2.0 / OpenID Connect Endpoints

#### `/oauth/authorize` (GET)
Authorization endpoint for user authentication and consent.
- **Parameters**: `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`
- **Response**: Redirect to `redirect_uri` with `code` and `state`

#### `/oauth/token` (POST)
Token endpoint for exchanging authorization codes or refresh tokens.
- **Parameters**: `grant_type`, `code`, `redirect_uri`, `client_id`, `client_secret`, `code_verifier`, `refresh_token`
- **Response**: JSON with `access_token`, `token_type`, `expires_in`, `refresh_token`, `id_token`

#### `/oauth/introspect` (POST)
Token introspection endpoint for resource servers.
- **Parameters**: `token`
- **Response**: JSON with `active`, `scope`, `client_id`, `user_id`, `exp`, `iat`

#### `/oauth/revoke` (POST)
Token revocation endpoint.
- **Parameters**: `token`, `token_type_hint`
- **Response**: HTTP 200 OK

#### `/.well-known/openid-configuration` (GET)
OpenID Provider discovery endpoint.
- **Response**: JSON with endpoints, supported algorithms, etc.

#### `/userinfo` (GET)
UserInfo endpoint for retrieving user profile information.
- **Request**: `Authorization: Bearer <access_token>`
- **Response**: JSON with user claims (`sub`, `name`, `email`)

### Client Management Endpoints

#### `/clients` (POST)
Register new client.
- **Request**: JSON with client details
- **Response**: Registered client information

#### `/clients/{client_id}` (GET/PUT/DELETE)
Client CRUD operations for administrators.

### User Management Endpoints

#### `/users` (POST)
Register new user.
- **Request**: JSON with `username`, `email`, `password`
- **Response**: Registered user information

#### `/users/{user_id}` (GET/PUT/DELETE)
User CRUD operations.

## 6. Technology Stack (Go)

### Core Technologies
- **Programming Language**: Go (Golang)
- **Web Framework**: Gin or Echo for lightweight API development
- **OAuth 2.0 Library**: `github.com/go-oauth2/oauth2` for OAuth 2.0 server implementation
- **JWT Library**: `github.com/golang-jwt/jwt` for JWT token handling
- **Password Hashing**: `golang.org/x/crypto/bcrypt` for secure password hashing

### Data Storage
- **Database**: PostgreSQL with `database/sql` and `github.com/lib/pq` driver
- **Cache**: Redis with `github.com/go-redis/redis/v8`
- **Migration**: Database migration tools for schema management

### Observability
- **Logging**: `logrus` or `zap` for structured logging
- **Monitoring**: Prometheus for metrics collection
- **Visualization**: Grafana for dashboards and alerting
- **Tracing**: Jaeger or Zipkin for distributed tracing

### Deployment
- **Containerization**: Docker for application packaging
- **Orchestration**: Docker Compose for local development
- **Cloud**: Kubernetes for production deployment

## 7. Security Considerations

### Communication Security
- **HTTPS/TLS**: Mandatory for all communications
- **Certificate Management**: Proper SSL/TLS certificate handling
- **Secure Headers**: Implementation of security headers

### Authentication & Authorization
- **Strong Password Hashing**: bcrypt with configurable cost
- **Client Secret Management**: Secure storage and handling for confidential clients
- **PKCE Implementation**: Always use PKCE for public clients
- **Token Security**: Short-lived access tokens with secure refresh mechanism

### Token Management
- **Token Expiration**: Configurable token lifetimes
- **Token Revocation**: Efficient token revocation mechanism
- **JWT Security**: Proper JWT signing and validation
- **Scope Validation**: Strict scope enforcement

### Input Validation & Protection
- **Input Sanitization**: Comprehensive input validation to prevent injection attacks
- **Rate Limiting**: Protection against brute-force and DoS attacks
- **CORS Configuration**: Proper cross-origin resource sharing setup
- **Request Size Limits**: Protection against large payload attacks

### Monitoring & Auditing
- **Security Event Logging**: Comprehensive audit trail
- **Anomaly Detection**: Monitoring for suspicious activities
- **Access Logging**: Detailed request/response logging
- **Alert System**: Real-time security alerts

### Compliance & Standards
- **OAuth 2.0 Compliance**: Full adherence to RFC 6749
- **OpenID Connect Compliance**: Implementation of OIDC specifications
- **Security Best Practices**: Following OWASP guidelines
- **Regular Security Updates**: Keeping dependencies updated

## 8. Performance & Scalability

### Horizontal Scaling
- **Stateless Design**: Enables easy horizontal scaling
- **Load Balancing**: Support for multiple server instances
- **Database Scaling**: Read replicas and connection pooling
- **Cache Strategy**: Redis clustering for high availability

### Performance Optimization
- **Connection Pooling**: Efficient database connection management
- **Caching Strategy**: Multi-level caching implementation
- **Query Optimization**: Efficient database queries
- **Resource Management**: Proper memory and CPU utilization

### Monitoring & Metrics
- **Performance Metrics**: Response time, throughput, error rates
- **Resource Monitoring**: CPU, memory, disk, network usage
- **Business Metrics**: Token issuance rates, user activity
- **SLA Monitoring**: Service level agreement compliance

## 9. Deployment Architecture

### Development Environment
- Local development with Docker Compose
- Hot reloading for rapid development
- Test database and Redis instances
- Debug logging and profiling tools

### Staging Environment
- Production-like environment for testing
- Automated deployment pipeline
- Integration testing and load testing
- Security scanning and vulnerability assessment

### Production Environment
- High availability setup with redundancy
- Load balancers and auto-scaling
- Monitoring and alerting systems
- Backup and disaster recovery procedures

---

**Note**: This architecture design provides a comprehensive foundation for building a secure, scalable OAuth 2.0/OpenID Connect Authorization Server. For detailed implementation specifics and Vietnamese technical documentation, refer to the complete architecture document.