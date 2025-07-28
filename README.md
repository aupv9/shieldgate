# ShieldGate - OAuth 2.0 Authorization Server

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](docker-compose.yml)

ShieldGate is a comprehensive OAuth 2.0 and OpenID Connect Authorization Server built with Go. It provides centralized authentication and authorization services for modern applications, supporting various client types from traditional web applications to mobile apps and Single Page Applications (SPAs).

## 🚀 Features

- **OAuth 2.0 Compliance**: Full support for OAuth 2.0 specification
- **OpenID Connect**: Complete OIDC implementation for identity management
- **PKCE Support**: Enhanced security for public clients
- **Multiple Grant Types**: Authorization Code, Client Credentials, Refresh Token
- **JWT Tokens**: Secure token generation and validation
- **Client Management**: Dynamic client registration and management
- **User Management**: Built-in user registration and authentication
- **Rate Limiting**: Protection against abuse and brute-force attacks
- **CORS Support**: Cross-origin resource sharing configuration
- **Docker Ready**: Containerized deployment with Docker Compose
- **Comprehensive Logging**: Detailed logging and monitoring capabilities
- **Redis Caching**: Optional Redis integration for improved performance

## 🏗️ Architecture

ShieldGate follows a microservice architecture with the following components:

- **API Gateway**: Single entry point for all client requests
- **Authorization Service**: Core OAuth 2.0/OIDC logic
- **PostgreSQL Database**: Persistent storage for users, clients, and tokens
- **Redis Cache**: Optional caching layer for improved performance
- **Logging & Monitoring**: Comprehensive observability

## 📋 Prerequisites

### For Docker Deployment (Recommended)
- Docker 20.10+
- Docker Compose 2.0+

### For Development
- Go 1.21+
- PostgreSQL 13+
- Redis 6+ (optional)

## 🚀 Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd shieldgate
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the services**
   ```bash
   docker-compose up -d
   ```

4. **Verify installation**
   ```bash
   curl http://localhost:8080/health
   ```

### Manual Installation

1. **Install dependencies**
   ```bash
   go mod download
   ```

2. **Configure the application**
   ```bash
   cp config.yaml.example config.yaml
   # Edit config.yaml with your settings
   ```

3. **Run the server**
   ```bash
   go run cmd/auth-server/main.go
   ```

## 📖 Configuration

ShieldGate supports both YAML configuration files and environment variables. The application searches for configuration in the following order:

1. `./config.yaml`
2. `./config/config.yaml`
3. `/etc/auth-server/config.yaml`

### Sample Configuration

```yaml
# Database configuration
database:
  url: "postgres://authuser:password@localhost:5432/authdb?sslmode=disable"

# Server configuration
server:
  url: "http://localhost:8080"
  port: "8080"
  gin_mode: "release"

# JWT configuration
jwt:
  secret: "your-super-secret-jwt-key-minimum-32-characters-long"

# Security configuration
security:
  bcrypt_cost: 12
  access_token_duration: 3600
  refresh_token_duration: 2592000
```

For detailed configuration options, see [CONFIG_MIGRATION.md](docs/CONFIG_MIGRATION.md).

## 🔧 Usage

### OAuth 2.0 Flow Example

1. **Register a client**
   ```bash
   curl -X POST http://localhost:8080/api/v1/clients \
     -H "Content-Type: application/json" \
     -d '{
       "name": "My App",
       "redirect_uris": ["http://localhost:3000/callback"],
       "grant_types": ["authorization_code", "refresh_token"],
       "scopes": ["read", "write", "openid"],
       "is_public": true
     }'
   ```

2. **Create a user**
   ```bash
   curl -X POST http://localhost:8080/api/v1/users \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "password": "password123"
     }'
   ```

3. **Start authorization flow**
   ```
   http://localhost:8080/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=read%20write%20openid&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
   ```

For a complete OAuth 2.0 flow demonstration, see [demo_oauth_flow.md](docs/demo_oauth_flow.md).

## 🔌 API Endpoints

### OAuth 2.0 / OpenID Connect
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/introspect` - Token introspection
- `POST /oauth/revoke` - Token revocation
- `GET /.well-known/openid-configuration` - OpenID Connect discovery
- `GET /userinfo` - User information endpoint

### Client Management
- `POST /api/v1/clients` - Register new client
- `GET /api/v1/clients/{id}` - Get client details
- `PUT /api/v1/clients/{id}` - Update client
- `DELETE /api/v1/clients/{id}` - Delete client

### User Management
- `POST /api/v1/users` - Register new user
- `GET /api/v1/users/{id}` - Get user details
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user

### Health & Monitoring
- `GET /health` - Health check endpoint

## 📚 Documentation

### English Documentation
- **[Configuration Migration Guide](docs/CONFIG_MIGRATION.md)** - Migrating from environment variables to YAML
- **[OAuth Flow Demo](docs/demo_oauth_flow.md)** - Step-by-step OAuth 2.0 implementation guide
- **[Deployment Guide (English Summary)](docs/DEPLOYMENT_GUIDE_EN.md)** - Comprehensive deployment and usage guide
- **[Architecture Design (English Summary)](docs/ARCHITECTURE_DESIGN_EN.md)** - System architecture and design principles

### Vietnamese Documentation (Complete)
- **[Deployment Guide (Vietnamese)](docs/Hướng%20dẫn%20Triển%20khai%20và%20Sử%20dụng%20Authorization%20Server.md)** - Complete deployment and usage guide
- **[Architecture Design (Vietnamese)](docs/Thiết%20kế%20kiến%20trúc%20tổng%20thể%20hệ%20thống%20Authorization%20Server.md)** - Detailed system architecture and design

### Diagrams
- **[OAuth Flow Sequence](docs/oauth_flow_sequence.mmd)** - Mermaid diagram of OAuth 2.0 flow
- **[Overall Architecture](docs/overall_architecture.mmd)** - System architecture diagram

## 🔒 Security Features

- **HTTPS/TLS**: Mandatory for all communications
- **PKCE**: Proof Key for Code Exchange for public clients
- **JWT Tokens**: Secure token generation with configurable expiration
- **Password Hashing**: bcrypt with configurable cost
- **Rate Limiting**: Protection against brute-force attacks
- **CORS**: Configurable cross-origin resource sharing
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Detailed security event logging

## 🧪 Testing

Run the test suite:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and conventions
- Write comprehensive tests for new features
- Update documentation for any API changes
- Ensure all tests pass before submitting PR
- Use meaningful commit messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and request features via [GitHub Issues](../../issues)
- **Documentation**: Check the comprehensive guides in the `docs/` directory
- **Health Check**: Use `GET /health` endpoint to verify server status

## 🏷️ Version

Current version: 1.0.0

## 🙏 Acknowledgments

- OAuth 2.0 specification by IETF
- OpenID Connect specification by OpenID Foundation
- Go community for excellent libraries and tools
- Contributors and maintainers

---

**Note**: This project includes comprehensive Vietnamese documentation for deployment and architecture. English translations and summaries are provided in this README for international developers.