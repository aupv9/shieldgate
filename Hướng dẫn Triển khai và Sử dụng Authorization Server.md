# Hướng dẫn Triển khai và Sử dụng Authorization Server

## Mục lục

1. [Giới thiệu](#giới-thiệu)
2. [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
3. [Cài đặt và Triển khai](#cài-đặt-và-triển-khai)
4. [Cấu hình](#cấu-hình)
5. [Quản lý Client](#quản-lý-client)
6. [Quản lý Người dùng](#quản-lý-người-dùng)
7. [Tích hợp OAuth 2.0](#tích-hợp-oauth-20)
8. [Tích hợp OpenID Connect](#tích-hợp-openid-connect)
9. [Bảo mật](#bảo-mật)
10. [Monitoring và Logging](#monitoring-và-logging)
11. [Troubleshooting](#troubleshooting)
12. [API Reference](#api-reference)

## Giới thiệu

Authorization Server này được thiết kế để cung cấp dịch vụ xác thực và ủy quyền tập trung cho các hệ thống trong nền tảng của bạn. Nó tuân thủ các tiêu chuẩn OAuth 2.0 và OpenID Connect, đảm bảo tính tương thích và bảo mật cao.

Hệ thống hỗ trợ nhiều loại client khác nhau, từ ứng dụng web truyền thống đến ứng dụng di động và Single Page Applications (SPA). Với kiến trúc microservice và khả năng containerization, nó có thể dễ dàng tích hợp vào các môi trường cloud-native hiện đại.

## Yêu cầu hệ thống

### Phần cứng tối thiểu

Để chạy Authorization Server trong môi trường production, bạn cần:

- **CPU**: Tối thiểu 2 cores, khuyến nghị 4 cores trở lên
- **RAM**: Tối thiểu 2GB, khuyến nghị 4GB trở lên
- **Storage**: Tối thiểu 20GB SSD cho hệ điều hành và ứng dụng
- **Network**: Kết nối internet ổn định với băng thông tối thiểu 100Mbps

### Phần mềm

- **Hệ điều hành**: Linux (Ubuntu 20.04+, CentOS 8+, hoặc tương đương)
- **Docker**: Phiên bản 20.10+ (khuyến nghị sử dụng Docker)
- **Docker Compose**: Phiên bản 2.0+
- **PostgreSQL**: Phiên bản 13+ (nếu không sử dụng Docker)
- **Redis**: Phiên bản 6+ (tùy chọn, để caching)

### Môi trường Development

Để phát triển và test:

- **Go**: Phiên bản 1.21+
- **Git**: Để clone source code
- **Postman hoặc curl**: Để test API endpoints

## Cài đặt và Triển khai

### Phương pháp 1: Sử dụng Docker Compose (Khuyến nghị)

Docker Compose là cách đơn giản nhất để triển khai Authorization Server cùng với tất cả dependencies cần thiết.

#### Bước 1: Chuẩn bị môi trường

Đầu tiên, tạo thư mục cho project và clone source code:

```bash
mkdir -p /opt/authorization-server
cd /opt/authorization-server
git clone <repository-url> .
```

#### Bước 2: Cấu hình Environment Variables

Copy file cấu hình mẫu và chỉnh sửa theo môi trường của bạn:

```bash
cp .env.example .env
nano .env
```

Chỉnh sửa các giá trị quan trọng trong file `.env`:

```bash
# Database configuration
DATABASE_URL=postgres://authuser:your_secure_password@postgres:5432/authdb?sslmode=disable

# JWT Secret - QUAN TRỌNG: Thay đổi thành một chuỗi ngẫu nhiên mạnh
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long

# Server configuration
SERVER_URL=https://your-domain.com
PORT=8080

# Redis configuration (optional)
REDIS_URL=redis://redis:6379
```

#### Bước 3: Khởi chạy Services

Sử dụng Docker Compose để khởi chạy tất cả services:

```bash
docker-compose up -d
```

Lệnh này sẽ:
- Tạo và khởi chạy PostgreSQL database
- Tạo và khởi chạy Redis cache
- Build và khởi chạy Authorization Server
- Tự động tạo network để các container giao tiếp với nhau

#### Bước 4: Kiểm tra trạng thái

Kiểm tra xem tất cả services đã chạy thành công:

```bash
docker-compose ps
docker-compose logs auth-server
```

Truy cập health check endpoint để đảm bảo server hoạt động:

```bash
curl http://localhost:8080/health
```

#### Bước 5: Khởi tạo Database Schema

Authorization Server sẽ tự động tạo các bảng cần thiết khi khởi động. Tuy nhiên, bạn có thể kiểm tra bằng cách kết nối vào database:

```bash
docker-compose exec postgres psql -U authuser -d authdb -c "\dt"
```

### Phương pháp 2: Triển khai Manual

Nếu bạn muốn kiểm soát chi tiết hơn hoặc tích hợp vào hệ thống hiện có, bạn có thể triển khai manual.

#### Bước 1: Cài đặt Dependencies

Cài đặt PostgreSQL:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# CentOS/RHEL
sudo yum install postgresql-server postgresql-contrib
sudo postgresql-setup initdb
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

Cài đặt Redis (tùy chọn):

```bash
# Ubuntu/Debian
sudo apt install redis-server

# CentOS/RHEL
sudo yum install redis
sudo systemctl enable redis
sudo systemctl start redis
```

#### Bước 2: Cấu hình Database

Tạo database và user:

```sql
sudo -u postgres psql
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
\q
```

#### Bước 3: Build và Chạy Application

```bash
# Clone source code
git clone <repository-url>
cd authorization-server

# Build application
go mod download
go build -o auth-server main.go

# Tạo file .env
cp .env.example .env
# Chỉnh sửa .env với thông tin database và cấu hình

# Chạy application
./auth-server
```

#### Bước 4: Tạo Service (Systemd)

Để chạy như một service system:

```bash
sudo nano /etc/systemd/system/auth-server.service
```

Nội dung file service:

```ini
[Unit]
Description=Authorization Server
After=network.target postgresql.service

[Service]
Type=simple
User=authuser
WorkingDirectory=/opt/authorization-server
ExecStart=/opt/authorization-server/auth-server
Restart=always
RestartSec=5
Environment=PATH=/usr/bin:/usr/local/bin
EnvironmentFile=/opt/authorization-server/.env

[Install]
WantedBy=multi-user.target
```

Kích hoạt và khởi chạy service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable auth-server
sudo systemctl start auth-server
sudo systemctl status auth-server
```

### Phương pháp 3: Triển khai trên Kubernetes

Để triển khai trên Kubernetes cluster, bạn cần tạo các manifest files.

#### ConfigMap cho Environment Variables

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-server-config
data:
  DATABASE_URL: "postgres://authuser:password@postgres:5432/authdb?sslmode=disable"
  SERVER_URL: "https://auth.your-domain.com"
  PORT: "8080"
  REDIS_URL: "redis://redis:6379"
```

#### Secret cho JWT Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-server-secret
type: Opaque
data:
  JWT_SECRET: <base64-encoded-jwt-secret>
```

#### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-server
  template:
    metadata:
      labels:
        app: auth-server
    spec:
      containers:
      - name: auth-server
        image: your-registry/auth-server:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: auth-server-config
        - secretRef:
            name: auth-server-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

#### Service và Ingress

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-server-service
spec:
  selector:
    app: auth-server
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-server-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - auth.your-domain.com
    secretName: auth-server-tls
  rules:
  - host: auth.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-server-service
            port:
              number: 80
```

## Cấu hình

### Environment Variables

Authorization Server sử dụng environment variables để cấu hình. Dưới đây là danh sách đầy đủ các biến có thể cấu hình:

| Biến | Mô tả | Giá trị mặc định | Bắt buộc |
|------|-------|------------------|----------|
| `DATABASE_URL` | Connection string cho PostgreSQL | `postgres://user:password@localhost/authdb?sslmode=disable` | Có |
| `JWT_SECRET` | Secret key để ký JWT tokens | `your-super-secret-jwt-key-change-this-in-production` | Có |
| `SERVER_URL` | URL công khai của authorization server | `http://localhost:8080` | Có |
| `PORT` | Port để server lắng nghe | `8080` | Không |
| `REDIS_URL` | Connection string cho Redis | - | Không |
| `LOG_LEVEL` | Mức độ logging (debug, info, warn, error) | `info` | Không |
| `ACCESS_TOKEN_EXPIRY` | Thời gian sống của access token (giây) | `3600` | Không |
| `REFRESH_TOKEN_EXPIRY` | Thời gian sống của refresh token (giây) | `2592000` | Không |
| `AUTHORIZATION_CODE_EXPIRY` | Thời gian sống của authorization code (giây) | `600` | Không |

### Database Configuration

Authorization Server hỗ trợ PostgreSQL làm database chính. Connection string có format:

```
postgres://username:password@host:port/database?sslmode=mode
```

Các tham số SSL mode:
- `disable`: Không sử dụng SSL (chỉ dùng cho development)
- `require`: Yêu cầu SSL
- `verify-ca`: Xác minh certificate authority
- `verify-full`: Xác minh đầy đủ certificate

Ví dụ cho production:

```bash
DATABASE_URL=postgres://authuser:secure_password@db.example.com:5432/authdb?sslmode=require
```

### JWT Configuration

JWT Secret là thành phần quan trọng nhất trong bảo mật của hệ thống. Nó được sử dụng để ký và xác minh tất cả JWT tokens.

**Yêu cầu cho JWT Secret:**
- Tối thiểu 32 ký tự
- Sử dụng ký tự ngẫu nhiên (a-z, A-Z, 0-9, ký tự đặc biệt)
- Không được hardcode trong source code
- Phải được bảo mật nghiêm ngặt

Tạo JWT Secret mạnh:

```bash
# Sử dụng openssl
openssl rand -base64 32

# Sử dụng /dev/urandom
head -c 32 /dev/urandom | base64

# Sử dụng Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Redis Configuration (Tùy chọn)

Redis được sử dụng để cache và lưu trữ session tạm thời. Mặc dù không bắt buộc, việc sử dụng Redis sẽ cải thiện đáng kể hiệu suất của hệ thống.

Connection string format:

```
redis://[username:password@]host:port[/database]
```

Ví dụ:

```bash
# Redis không authentication
REDIS_URL=redis://localhost:6379

# Redis với password
REDIS_URL=redis://:password@localhost:6379

# Redis với username và password
REDIS_URL=redis://username:password@localhost:6379/0
```

### HTTPS Configuration

Trong môi trường production, bạn **phải** sử dụng HTTPS. Authorization Server không tự xử lý TLS termination, vì vậy bạn cần sử dụng reverse proxy như Nginx hoặc load balancer.

#### Cấu hình Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name auth.your-domain.com;

    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name auth.your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

## Quản lý Client

Client trong OAuth 2.0 là các ứng dụng muốn truy cập vào tài nguyên được bảo vệ thay mặt cho người dùng. Authorization Server hỗ trợ hai loại client chính:

### Loại Client

#### Confidential Client
- Có khả năng bảo mật client secret
- Thường là server-side applications
- Ví dụ: Web applications chạy trên server, backend services

#### Public Client  
- Không thể bảo mật client secret một cách an toàn
- Thường là client-side applications
- Ví dụ: Single Page Applications (SPA), mobile apps, desktop apps

### Đăng ký Client mới

Để đăng ký một client mới, bạn cần gửi POST request đến `/clients` endpoint:

```bash
curl -X POST http://localhost:8080/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_access_token>" \
  -d '{
    "name": "My Web Application",
    "redirect_uris": [
      "https://myapp.com/callback",
      "https://myapp.com/auth/callback"
    ],
    "grant_types": [
      "authorization_code",
      "refresh_token"
    ],
    "scopes": [
      "read",
      "write",
      "profile"
    ],
    "is_public": false
  }'
```

Response sẽ trả về thông tin client bao gồm `client_id` và `client_secret` (nếu là confidential client):

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "client_id": "a1b2c3d4e5f6g7h8i9j0",
  "client_secret": "s3cr3t_k3y_f0r_c0nf1d3nt14l_cl13nt",
  "name": "My Web Application",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/auth/callback"
  ],
  "grant_types": [
    "authorization_code", 
    "refresh_token"
  ],
  "scopes": [
    "read",
    "write", 
    "profile"
  ],
  "is_public": false,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Grant Types được hỗ trợ

Authorization Server hỗ trợ các grant types sau:

#### Authorization Code
- Phù hợp cho web applications và mobile apps
- Bảo mật cao nhất
- Yêu cầu redirect URI
- Khuyến nghị sử dụng với PKCE

#### Client Credentials  
- Phù hợp cho server-to-server communication
- Không cần user interaction
- Client tự xác thực bằng client credentials

#### Refresh Token
- Sử dụng để làm mới access token
- Tăng security bằng cách giảm thời gian sống của access token

### Scopes

Scopes định nghĩa quyền truy cập mà client có thể yêu cầu. Bạn có thể định nghĩa custom scopes phù hợp với ứng dụng:

| Scope | Mô tả |
|-------|-------|
| `read` | Quyền đọc dữ liệu cơ bản |
| `write` | Quyền ghi/cập nhật dữ liệu |
| `profile` | Quyền truy cập thông tin profile người dùng |
| `email` | Quyền truy cập email người dùng |
| `admin` | Quyền quản trị (cần cẩn thận) |

### Quản lý Client

#### Lấy thông tin Client

```bash
curl -X GET http://localhost:8080/clients/{client_id} \
  -H "Authorization: Bearer <admin_access_token>"
```

#### Cập nhật Client

```bash
curl -X PUT http://localhost:8080/clients/{client_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_access_token>" \
  -d '{
    "name": "Updated App Name",
    "redirect_uris": [
      "https://myapp.com/new-callback"
    ]
  }'
```

#### Xóa Client

```bash
curl -X DELETE http://localhost:8080/clients/{client_id} \
  -H "Authorization: Bearer <admin_access_token>"
```

### Best Practices cho Client Management

1. **Redirect URI Validation**: Luôn validate redirect URI nghiêm ngặt để tránh open redirect attacks
2. **Scope Limitation**: Chỉ cấp những scopes thực sự cần thiết cho client
3. **Client Secret Rotation**: Định kỳ thay đổi client secret cho confidential clients
4. **Monitoring**: Theo dõi hoạt động của client để phát hiện bất thường
5. **Documentation**: Duy trì tài liệu về từng client và mục đích sử dụng

## Quản lý Người dùng

Hệ thống quản lý người dùng cung cấp các chức năng cơ bản để đăng ký, xác thực và quản lý thông tin người dùng.

### Đăng ký Người dùng

Endpoint đăng ký người dùng là public, cho phép tự đăng ký:

```bash
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john.doe@example.com", 
    "password": "SecurePassword123!",
    "full_name": "John Doe"
  }'
```

Response:

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "full_name": "John Doe",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Yêu cầu Password

Để đảm bảo bảo mật, password phải đáp ứng các yêu cầu sau:
- Tối thiểu 8 ký tự
- Chứa ít nhất 1 chữ hoa
- Chứa ít nhất 1 chữ thường  
- Chứa ít nhất 1 số
- Chứa ít nhất 1 ký tự đặc biệt

### Xác thực Người dùng

Xác thực được thực hiện thông qua OAuth 2.0 flow. Người dùng không trực tiếp gửi username/password đến API, mà thông qua authorization endpoint.

### Quản lý Thông tin Người dùng

#### Lấy thông tin người dùng

```bash
curl -X GET http://localhost:8080/users/{user_id} \
  -H "Authorization: Bearer <access_token>"
```

#### Cập nhật thông tin người dùng

```bash
curl -X PUT http://localhost:8080/users/{user_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "full_name": "John Smith",
    "email": "john.smith@example.com"
  }'
```

#### Xóa người dùng

```bash
curl -X DELETE http://localhost:8080/users/{user_id} \
  -H "Authorization: Bearer <access_token>"
```

### Password Hashing

Hệ thống sử dụng bcrypt để hash password với cost factor 12, đảm bảo:
- Password gốc không bao giờ được lưu trữ
- Khó bị brute force attack
- Tự động salt để tránh rainbow table attacks

### User Roles và Permissions

Hiện tại hệ thống hỗ trợ role-based access control cơ bản. Bạn có thể mở rộng bằng cách:

1. Thêm trường `role` vào user model
2. Implement middleware kiểm tra role
3. Định nghĩa permissions cho từng role

Ví dụ roles:
- `user`: Người dùng thông thường
- `admin`: Quản trị viên hệ thống
- `moderator`: Người kiểm duyệt

## Tích hợp OAuth 2.0

OAuth 2.0 là giao thức ủy quyền cho phép ứng dụng bên thứ ba truy cập vào tài nguyên của người dùng mà không cần biết password.

### Authorization Code Flow

Đây là flow được khuyến nghị cho hầu hết các ứng dụng web và mobile.

#### Bước 1: Chuyển hướng đến Authorization Endpoint

Client chuyển hướng người dùng đến authorization endpoint:

```
https://auth.your-domain.com/oauth/authorize?
  response_type=code&
  client_id=your_client_id&
  redirect_uri=https://yourapp.com/callback&
  scope=read%20write&
  state=random_state_string&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256
```

Tham số:
- `response_type`: Luôn là `code` cho authorization code flow
- `client_id`: ID của client đã đăng ký
- `redirect_uri`: URI để chuyển hướng sau khi ủy quyền
- `scope`: Các quyền được yêu cầu, phân tách bằng space
- `state`: Chuỗi ngẫu nhiên để chống CSRF attacks
- `code_challenge`: PKCE code challenge (khuyến nghị)
- `code_challenge_method`: Phương thức tạo code challenge (S256 hoặc plain)

#### Bước 2: Người dùng xác thực và cấp quyền

Authorization Server sẽ:
1. Kiểm tra xem người dùng đã đăng nhập chưa
2. Hiển thị trang đăng nhập nếu cần
3. Hiển thị trang consent để người dùng cấp quyền
4. Tạo authorization code nếu người dùng đồng ý

#### Bước 3: Nhận Authorization Code

Sau khi người dùng cấp quyền, Authorization Server chuyển hướng về redirect_uri:

```
https://yourapp.com/callback?
  code=AUTHORIZATION_CODE&
  state=random_state_string
```

Client phải:
1. Kiểm tra `state` parameter để chống CSRF
2. Lưu trữ `code` để đổi lấy access token

#### Bước 4: Đổi Code lấy Access Token

Client gửi POST request đến token endpoint:

```bash
curl -X POST https://auth.your-domain.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&
      code=AUTHORIZATION_CODE&
      redirect_uri=https://yourapp.com/callback&
      client_id=your_client_id&
      client_secret=your_client_secret&
      code_verifier=CODE_VERIFIER"
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def50200...",
  "scope": "read write"
}
```

#### Bước 5: Sử dụng Access Token

Client sử dụng access token để gọi API:

```bash
curl -X GET https://api.your-domain.com/user/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### PKCE (Proof Key for Code Exchange)

PKCE là extension bảo mật cho OAuth 2.0, đặc biệt quan trọng cho public clients.

#### Tạo Code Verifier và Code Challenge

```javascript
// Tạo code verifier (43-128 ký tự)
function generateCodeVerifier() {
  const array = new Uint32Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

// Tạo code challenge từ code verifier
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

### Client Credentials Flow

Phù hợp cho server-to-server communication:

```bash
curl -X POST https://auth.your-domain.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&
      client_id=your_client_id&
      client_secret=your_client_secret&
      scope=api:read"
```

### Refresh Token Flow

Khi access token hết hạn, sử dụng refresh token:

```bash
curl -X POST https://auth.your-domain.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&
      refresh_token=def50200...&
      client_id=your_client_id&
      client_secret=your_client_secret"
```

### Token Introspection

Resource server có thể kiểm tra tính hợp lệ của access token:

```bash
curl -X POST https://auth.your-domain.com/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic <base64(client_id:client_secret)>" \
  -d "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Response:

```json
{
  "active": true,
  "scope": "read write",
  "client_id": "your_client_id",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "exp": 1642694400,
  "iat": 1642690800
}
```

### Token Revocation

Thu hồi access token hoặc refresh token:

```bash
curl -X POST https://auth.your-domain.com/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic <base64(client_id:client_secret)>" \
  -d "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...&
      token_type_hint=access_token"
```

## Tích hợp OpenID Connect

OpenID Connect (OIDC) là lớp identity layer trên OAuth 2.0, cung cấp thông tin về người dùng đã xác thực.

### Discovery Endpoint

OIDC cung cấp discovery endpoint để client tự động khám phá cấu hình:

```bash
curl https://auth.your-domain.com/.well-known/openid-configuration
```

Response:

```json
{
  "issuer": "https://auth.your-domain.com",
  "authorization_endpoint": "https://auth.your-domain.com/oauth/authorize",
  "token_endpoint": "https://auth.your-domain.com/oauth/token",
  "userinfo_endpoint": "https://auth.your-domain.com/userinfo",
  "jwks_uri": "https://auth.your-domain.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "claims_supported": ["sub", "name", "email", "iat", "exp"]
}
```

### ID Token

Khi sử dụng scope `openid`, Authorization Server sẽ trả về ID Token cùng với Access Token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer", 
  "expires_in": 3600,
  "refresh_token": "def50200...",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

ID Token là JWT chứa thông tin về người dùng:

```json
{
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "aud": "your_client_id",
  "iss": "https://auth.your-domain.com",
  "iat": 1642690800,
  "exp": 1642694400,
  "name": "John Doe",
  "email": "john.doe@example.com"
}
```

### UserInfo Endpoint

Client có thể lấy thêm thông tin về người dùng từ UserInfo endpoint:

```bash
curl -X GET https://auth.your-domain.com/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Response:

```json
{
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "picture": "https://example.com/avatar.jpg"
}
```

### Standard Claims

OIDC định nghĩa các standard claims:

| Claim | Mô tả |
|-------|-------|
| `sub` | Subject identifier (user ID) |
| `name` | Full name |
| `given_name` | First name |
| `family_name` | Last name |
| `email` | Email address |
| `email_verified` | Email verification status |
| `picture` | Profile picture URL |
| `locale` | Locale/language preference |

### Scopes và Claims

| Scope | Claims được trả về |
|-------|-------------------|
| `openid` | `sub` |
| `profile` | `name`, `given_name`, `family_name`, `picture`, `locale` |
| `email` | `email`, `email_verified` |

### Implementing OIDC Client

Ví dụ implementation đơn giản bằng JavaScript:

```javascript
class OIDCClient {
  constructor(config) {
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.authEndpoint = config.authEndpoint;
    this.tokenEndpoint = config.tokenEndpoint;
    this.userInfoEndpoint = config.userInfoEndpoint;
  }

  // Bước 1: Chuyển hướng đến authorization endpoint
  authorize() {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid profile email',
      state: this.generateState(),
      code_challenge: this.generateCodeChallenge(),
      code_challenge_method: 'S256'
    });

    window.location.href = `${this.authEndpoint}?${params}`;
  }

  // Bước 2: Xử lý callback và đổi code lấy token
  async handleCallback(code, state) {
    // Verify state parameter
    if (state !== this.getStoredState()) {
      throw new Error('Invalid state parameter');
    }

    const response = await fetch(this.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.redirectUri,
        client_id: this.clientId,
        code_verifier: this.getStoredCodeVerifier()
      })
    });

    const tokens = await response.json();
    
    // Verify ID token
    const idToken = this.parseJWT(tokens.id_token);
    this.verifyIdToken(idToken);

    return tokens;
  }

  // Bước 3: Lấy thông tin user
  async getUserInfo(accessToken) {
    const response = await fetch(this.userInfoEndpoint, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    return await response.json();
  }

  parseJWT(token) {
    const parts = token.split('.');
    const payload = JSON.parse(atob(parts[1]));
    return payload;
  }

  verifyIdToken(idToken) {
    // Verify issuer
    if (idToken.iss !== this.issuer) {
      throw new Error('Invalid issuer');
    }

    // Verify audience
    if (idToken.aud !== this.clientId) {
      throw new Error('Invalid audience');
    }

    // Verify expiration
    if (Date.now() / 1000 > idToken.exp) {
      throw new Error('Token expired');
    }

    // In production, also verify signature
  }
}
```

Đây là phần đầu của hướng dẫn triển khai và sử dụng. Tôi sẽ tiếp tục với các phần còn lại.


## Bảo mật

Bảo mật là yếu tố quan trọng nhất trong một authorization server. Dưới đây là các biện pháp bảo mật cần thiết và best practices.

### HTTPS/TLS

**Bắt buộc sử dụng HTTPS trong production.** Tất cả giao tiếp với Authorization Server phải được mã hóa để bảo vệ:
- Authorization codes
- Access tokens
- Refresh tokens
- User credentials
- Client secrets

#### Cấu hình TLS

Sử dụng TLS 1.2 hoặc cao hơn với cipher suites mạnh:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_prefer_server_ciphers off;
ssl_ecdh_curve secp384r1;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

#### Certificate Management

- Sử dụng certificates từ trusted CA
- Implement certificate rotation tự động
- Monitor certificate expiration
- Sử dụng Certificate Transparency logs

### JWT Security

#### Signing Algorithm

Luôn sử dụng asymmetric algorithms (RS256, ES256) cho production:

```go
// Thay vì HS256
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
```

#### Key Management

- Rotate signing keys định kỳ (khuyến nghị 6 tháng)
- Sử dụng Hardware Security Modules (HSM) cho production
- Implement key versioning
- Publish public keys qua JWKS endpoint

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-01-key",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

#### Token Validation

Resource servers phải validate:
- Signature integrity
- Token expiration (`exp`)
- Issuer (`iss`)
- Audience (`aud`)
- Not before (`nbf`)

### Password Security

#### Hashing

Sử dụng bcrypt với cost factor cao:

```go
// Cost factor 12-14 cho production
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
```

#### Password Policy

Implement password policy mạnh:
- Tối thiểu 12 ký tự
- Kết hợp chữ hoa, chữ thường, số, ký tự đặc biệt
- Không cho phép passwords phổ biến
- Không cho phép reuse passwords cũ

```go
func ValidatePassword(password string) error {
    if len(password) < 12 {
        return errors.New("password must be at least 12 characters")
    }
    
    var hasUpper, hasLower, hasNumber, hasSpecial bool
    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsNumber(char):
            hasNumber = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            hasSpecial = true
        }
    }
    
    if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
        return errors.New("password must contain uppercase, lowercase, number and special character")
    }
    
    return nil
}
```

### Rate Limiting

Implement rate limiting để chống brute force attacks:

#### Token Endpoint

```go
// Limit token requests per client
tokenLimiter := rate.NewLimiter(rate.Every(time.Minute), 10)

func (h *AuthHandler) Token(c *gin.Context) {
    clientID := c.PostForm("client_id")
    
    if !tokenLimiter.Allow() {
        c.JSON(http.StatusTooManyRequests, gin.H{
            "error": "rate_limit_exceeded",
            "error_description": "Too many token requests"
        })
        return
    }
    
    // Process token request...
}
```

#### Authorization Endpoint

```go
// Limit authorization attempts per IP
authLimiter := rate.NewLimiter(rate.Every(time.Minute), 20)

func (h *AuthHandler) Authorize(c *gin.Context) {
    if !authLimiter.Allow() {
        c.JSON(http.StatusTooManyRequests, gin.H{
            "error": "rate_limit_exceeded"
        })
        return
    }
    
    // Process authorization...
}
```

### CSRF Protection

#### State Parameter

Luôn sử dụng và validate state parameter:

```javascript
// Client-side: Generate random state
const state = crypto.getRandomValues(new Uint32Array(4)).join('');
sessionStorage.setItem('oauth_state', state);

// Include in authorization URL
const authUrl = `${authEndpoint}?response_type=code&client_id=${clientId}&state=${state}`;

// Validate on callback
const urlParams = new URLSearchParams(window.location.search);
const returnedState = urlParams.get('state');
const storedState = sessionStorage.getItem('oauth_state');

if (returnedState !== storedState) {
    throw new Error('CSRF attack detected');
}
```

#### PKCE

Luôn sử dụng PKCE cho public clients:

```javascript
// Generate code verifier
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

// Generate code challenge
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(digest));
}
```

### Input Validation

Validate tất cả inputs để chống injection attacks:

```go
func ValidateRedirectURI(uri string) error {
    parsed, err := url.Parse(uri)
    if err != nil {
        return errors.New("invalid URI format")
    }
    
    // Must be HTTPS in production
    if parsed.Scheme != "https" {
        return errors.New("redirect URI must use HTTPS")
    }
    
    // No fragments allowed
    if parsed.Fragment != "" {
        return errors.New("redirect URI must not contain fragment")
    }
    
    return nil
}

func ValidateScope(scope string) error {
    // Only allow alphanumeric and specific characters
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9\s:._-]+$`, scope)
    if !matched {
        return errors.New("invalid scope format")
    }
    
    return nil
}
```

### Database Security

#### Connection Security

```go
// Use SSL for database connections
db, err := sql.Open("postgres", 
    "postgres://user:pass@host/db?sslmode=require&sslcert=client-cert.pem&sslkey=client-key.pem&sslrootcert=ca-cert.pem")
```

#### SQL Injection Prevention

Luôn sử dụng prepared statements:

```go
// Good - Uses prepared statement
stmt, err := db.Prepare("SELECT id, username FROM users WHERE email = $1")
if err != nil {
    return err
}
defer stmt.Close()

var user User
err = stmt.QueryRow(email).Scan(&user.ID, &user.Username)

// Bad - Vulnerable to SQL injection
query := fmt.Sprintf("SELECT id, username FROM users WHERE email = '%s'", email)
```

#### Database Encryption

- Encrypt sensitive data at rest
- Use database-level encryption (TDE)
- Encrypt backups
- Implement column-level encryption cho sensitive fields

### Security Headers

Implement security headers trong reverse proxy:

```nginx
# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Prevent clickjacking
add_header X-Frame-Options "DENY" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# XSS Protection
add_header X-XSS-Protection "1; mode=block" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;

# Permissions Policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Audit Logging

Log tất cả security events:

```go
type SecurityEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    EventType   string    `json:"event_type"`
    UserID      string    `json:"user_id,omitempty"`
    ClientID    string    `json:"client_id,omitempty"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
    Success     bool      `json:"success"`
    ErrorCode   string    `json:"error_code,omitempty"`
    Description string    `json:"description"`
}

func LogSecurityEvent(eventType string, c *gin.Context, success bool, description string) {
    event := SecurityEvent{
        Timestamp:   time.Now(),
        EventType:   eventType,
        IPAddress:   c.ClientIP(),
        UserAgent:   c.GetHeader("User-Agent"),
        Success:     success,
        Description: description,
    }
    
    // Log to security log file
    securityLogger.Info("security_event", zap.Any("event", event))
}
```

Security events cần log:
- Login attempts (success/failure)
- Token generation/validation
- Client registration/modification
- Admin actions
- Rate limit violations
- Invalid requests

## Monitoring và Logging

Monitoring và logging hiệu quả là cần thiết để duy trì và troubleshoot Authorization Server.

### Application Metrics

#### Key Performance Indicators (KPIs)

Monitor các metrics quan trọng:

| Metric | Mô tả | Threshold |
|--------|-------|-----------|
| Request Rate | Số requests per second | - |
| Response Time | Thời gian phản hồi trung bình | < 200ms |
| Error Rate | Tỷ lệ lỗi (4xx, 5xx) | < 1% |
| Token Generation Rate | Số tokens được tạo per minute | - |
| Active Sessions | Số sessions đang hoạt động | - |
| Database Connections | Số connections đến database | < 80% pool size |

#### Prometheus Metrics

Implement Prometheus metrics:

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    requestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_server_requests_total",
            Help: "Total number of requests",
        },
        []string{"method", "endpoint", "status"},
    )
    
    requestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "auth_server_request_duration_seconds",
            Help: "Request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "endpoint"},
    )
    
    tokensGenerated = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_server_tokens_generated_total",
            Help: "Total number of tokens generated",
        },
        []string{"token_type", "client_id"},
    )
    
    activeSessions = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "auth_server_active_sessions",
            Help: "Number of active sessions",
        },
    )
)

// Middleware to collect metrics
func MetricsMiddleware() gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        duration := time.Since(start).Seconds()
        status := strconv.Itoa(c.Writer.Status())
        
        requestsTotal.WithLabelValues(c.Request.Method, c.FullPath(), status).Inc()
        requestDuration.WithLabelValues(c.Request.Method, c.FullPath()).Observe(duration)
    })
}
```

#### Custom Business Metrics

```go
// Track OAuth flow completion rates
var (
    authorizationAttempts = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "oauth_authorization_attempts_total",
            Help: "Total authorization attempts",
        },
        []string{"client_id", "result"},
    )
    
    tokenExchanges = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "oauth_token_exchanges_total", 
            Help: "Total token exchanges",
        },
        []string{"grant_type", "client_id", "result"},
    )
)

func (h *AuthHandler) Token(c *gin.Context) {
    grantType := c.PostForm("grant_type")
    clientID := c.PostForm("client_id")
    
    // Process token request...
    
    if err != nil {
        tokenExchanges.WithLabelValues(grantType, clientID, "error").Inc()
        // Handle error...
        return
    }
    
    tokenExchanges.WithLabelValues(grantType, clientID, "success").Inc()
    tokensGenerated.WithLabelValues("access_token", clientID).Inc()
    
    // Return token...
}
```

### Structured Logging

Sử dụng structured logging với Zap:

```go
import (
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
)

func InitLogger() *zap.Logger {
    config := zap.NewProductionConfig()
    config.EncoderConfig.TimeKey = "timestamp"
    config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
    
    logger, _ := config.Build()
    return logger
}

// Structured logging for OAuth events
func LogOAuthEvent(logger *zap.Logger, eventType string, clientID, userID string, success bool, details map[string]interface{}) {
    fields := []zap.Field{
        zap.String("event_type", eventType),
        zap.String("client_id", clientID),
        zap.String("user_id", userID),
        zap.Bool("success", success),
    }
    
    for key, value := range details {
        fields = append(fields, zap.Any(key, value))
    }
    
    if success {
        logger.Info("oauth_event", fields...)
    } else {
        logger.Error("oauth_event", fields...)
    }
}
```

### Log Levels và Categories

#### Log Levels

- **DEBUG**: Detailed information for debugging
- **INFO**: General information about application flow
- **WARN**: Warning conditions that should be noted
- **ERROR**: Error conditions that need attention
- **FATAL**: Critical errors that cause application termination

#### Log Categories

```go
// Different loggers for different purposes
var (
    appLogger      = logger.Named("app")
    securityLogger = logger.Named("security")
    auditLogger    = logger.Named("audit")
    accessLogger   = logger.Named("access")
)

// Usage examples
appLogger.Info("server started", zap.String("port", "8080"))
securityLogger.Warn("suspicious activity", zap.String("ip", clientIP))
auditLogger.Info("user created", zap.String("user_id", userID))
accessLogger.Info("api access", zap.String("endpoint", "/userinfo"))
```

### Health Checks

Implement comprehensive health checks:

```go
type HealthStatus struct {
    Status    string            `json:"status"`
    Timestamp time.Time         `json:"timestamp"`
    Services  map[string]string `json:"services"`
    Version   string            `json:"version"`
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
    status := HealthStatus{
        Timestamp: time.Now(),
        Version:   "1.0.0",
        Services:  make(map[string]string),
    }
    
    // Check database connectivity
    if err := h.db.Ping(); err != nil {
        status.Services["database"] = "unhealthy"
        status.Status = "unhealthy"
    } else {
        status.Services["database"] = "healthy"
    }
    
    // Check Redis connectivity (if used)
    if h.redis != nil {
        if err := h.redis.Ping(context.Background()).Err(); err != nil {
            status.Services["redis"] = "unhealthy"
            status.Status = "unhealthy"
        } else {
            status.Services["redis"] = "healthy"
        }
    }
    
    // Overall status
    if status.Status == "" {
        status.Status = "healthy"
    }
    
    statusCode := http.StatusOK
    if status.Status == "unhealthy" {
        statusCode = http.StatusServiceUnavailable
    }
    
    c.JSON(statusCode, status)
}
```

### Alerting

#### Prometheus Alerting Rules

```yaml
groups:
- name: auth-server
  rules:
  - alert: AuthServerHighErrorRate
    expr: rate(auth_server_requests_total{status=~"5.."}[5m]) > 0.01
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High error rate on auth server"
      description: "Error rate is {{ $value }} errors per second"

  - alert: AuthServerHighResponseTime
    expr: histogram_quantile(0.95, rate(auth_server_request_duration_seconds_bucket[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time on auth server"
      description: "95th percentile response time is {{ $value }} seconds"

  - alert: AuthServerDatabaseDown
    expr: up{job="auth-server-db"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Auth server database is down"
      description: "Database connection is not available"

  - alert: AuthServerTokenGenerationSpike
    expr: rate(auth_server_tokens_generated_total[5m]) > 100
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Unusual token generation rate"
      description: "Token generation rate is {{ $value }} per second"
```

#### Grafana Dashboard

Tạo dashboard để visualize metrics:

```json
{
  "dashboard": {
    "title": "Authorization Server Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auth_server_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(auth_server_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(auth_server_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auth_server_requests_total{status=~\"4..\"}[5m])",
            "legendFormat": "4xx errors"
          },
          {
            "expr": "rate(auth_server_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors"
          }
        ]
      }
    ]
  }
}
```

### Log Aggregation

#### ELK Stack Configuration

Filebeat configuration:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth-server/*.log
  fields:
    service: auth-server
    environment: production
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "auth-server-%{+yyyy.MM.dd}"

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
```

Logstash configuration:

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  if [service] == "auth-server" {
    if [event_type] == "oauth_event" {
      mutate {
        add_tag => ["oauth"]
      }
    }
    
    if [event_type] == "security_event" {
      mutate {
        add_tag => ["security"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "%{service}-%{+YYYY.MM.dd}"
  }
}
```

#### Kibana Dashboards

Tạo dashboards cho:
- OAuth flow analysis
- Security events monitoring
- Performance metrics
- Error tracking
- User activity patterns

## Troubleshooting

### Common Issues

#### 1. Token Validation Failures

**Symptoms:**
- Resource servers reject valid tokens
- "Invalid or expired token" errors

**Possible Causes:**
- Clock skew between servers
- Wrong JWT secret
- Token expired
- Invalid signature

**Solutions:**
```bash
# Check server time synchronization
timedatectl status

# Verify JWT secret matches
echo $JWT_SECRET

# Check token expiration
jwt decode <token>

# Validate token manually
curl -X POST http://localhost:8080/oauth/introspect \
  -d "token=<access_token>"
```

#### 2. Database Connection Issues

**Symptoms:**
- "Connection refused" errors
- Slow response times
- Intermittent failures

**Solutions:**
```bash
# Check database connectivity
pg_isready -h localhost -p 5432

# Check connection pool settings
# Increase max connections if needed
max_connections = 200

# Monitor active connections
SELECT count(*) FROM pg_stat_activity;
```

#### 3. CORS Issues

**Symptoms:**
- Browser blocks requests
- "Access-Control-Allow-Origin" errors

**Solutions:**
```go
// Update CORS configuration
func CORS() gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        origin := c.Request.Header.Get("Origin")
        
        // Allow specific origins in production
        allowedOrigins := []string{
            "https://app.example.com",
            "https://admin.example.com",
        }
        
        for _, allowed := range allowedOrigins {
            if origin == allowed {
                c.Header("Access-Control-Allow-Origin", origin)
                break
            }
        }
        
        c.Header("Access-Control-Allow-Credentials", "true")
        c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    })
}
```

#### 4. PKCE Validation Failures

**Symptoms:**
- "Invalid code verifier" errors
- Authorization code exchange fails

**Solutions:**
```javascript
// Ensure proper PKCE implementation
function generateCodeVerifier() {
    // Must be 43-128 characters
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    return crypto.subtle.digest('SHA-256', data)
        .then(digest => base64URLEncode(new Uint8Array(digest)));
}

// Store verifier securely
sessionStorage.setItem('code_verifier', codeVerifier);
```

### Debugging Tools

#### JWT Debugging

```bash
# Decode JWT token
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | base64 -d

# Use jwt.io for online debugging
# Or use jwt-cli tool
jwt decode <token>
```

#### Database Debugging

```sql
-- Check active sessions
SELECT client_id, user_id, expires_at 
FROM access_tokens 
WHERE expires_at > NOW();

-- Check authorization codes
SELECT code, client_id, expires_at, created_at
FROM authorization_codes
WHERE expires_at > NOW();

-- Monitor token generation
SELECT client_id, COUNT(*) as token_count
FROM access_tokens
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY client_id;
```

#### Network Debugging

```bash
# Test OAuth endpoints
curl -v http://localhost:8080/oauth/authorize?response_type=code&client_id=test

# Check TLS configuration
openssl s_client -connect auth.example.com:443 -servername auth.example.com

# Monitor network traffic
tcpdump -i any -s 0 -w oauth_traffic.pcap port 8080
```

### Performance Optimization

#### Database Optimization

```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_access_tokens_user_client 
ON access_tokens(user_id, client_id);

CREATE INDEX CONCURRENTLY idx_access_tokens_expires_at 
ON access_tokens(expires_at) WHERE expires_at > NOW();

-- Cleanup expired tokens
DELETE FROM access_tokens WHERE expires_at < NOW() - INTERVAL '1 day';
DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour';
DELETE FROM refresh_tokens WHERE expires_at < NOW() - INTERVAL '1 day';
```

#### Connection Pool Tuning

```go
// Optimize database connection pool
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)
```

#### Caching Strategy

```go
// Implement Redis caching for frequently accessed data
func (s *TokenService) ValidateAccessToken(tokenString string) (*models.JWTClaims, error) {
    // Check cache first
    if cached, err := s.redis.Get(ctx, "token:"+tokenString).Result(); err == nil {
        var claims models.JWTClaims
        json.Unmarshal([]byte(cached), &claims)
        return &claims, nil
    }
    
    // Validate token
    claims, err := s.validateJWT(tokenString)
    if err != nil {
        return nil, err
    }
    
    // Cache valid token
    claimsJSON, _ := json.Marshal(claims)
    s.redis.Set(ctx, "token:"+tokenString, claimsJSON, time.Until(time.Unix(claims.ExpiresAt, 0)))
    
    return claims, nil
}
```

## API Reference

### OAuth 2.0 Endpoints

#### Authorization Endpoint

**`GET /oauth/authorize`**

Initiates the OAuth 2.0 authorization flow.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `response_type` | string | Yes | Must be "code" |
| `client_id` | string | Yes | Client identifier |
| `redirect_uri` | string | Yes | Callback URI |
| `scope` | string | No | Requested scopes (space-separated) |
| `state` | string | Recommended | CSRF protection token |
| `code_challenge` | string | Recommended | PKCE code challenge |
| `code_challenge_method` | string | Recommended | "S256" or "plain" |

**Response:**

Redirects to `redirect_uri` with:
- `code`: Authorization code
- `state`: Original state parameter

**Example:**

```http
GET /oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=read%20write&state=xyz789&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256 HTTP/1.1
Host: auth.example.com
```

#### Token Endpoint

**`POST /oauth/token`**

Exchanges authorization code for access token.

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | "authorization_code", "refresh_token", or "client_credentials" |
| `code` | string | Yes* | Authorization code (*for authorization_code grant) |
| `redirect_uri` | string | Yes* | Must match authorization request |
| `client_id` | string | Yes | Client identifier |
| `client_secret` | string | No** | Client secret (**required for confidential clients) |
| `code_verifier` | string | Recommended | PKCE code verifier |
| `refresh_token` | string | Yes* | Refresh token (*for refresh_token grant) |
| `scope` | string | No | Requested scopes for refresh |

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def50200...",
  "scope": "read write"
}
```

**Example:**

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=xyz789&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

#### Token Introspection

**`POST /oauth/introspect`**

Validates and returns information about a token.

**Authentication:** Client credentials required

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Token to introspect |
| `token_type_hint` | string | No | "access_token" or "refresh_token" |

**Response:**

```json
{
  "active": true,
  "scope": "read write",
  "client_id": "xyz789",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "exp": 1642694400,
  "iat": 1642690800
}
```

#### Token Revocation

**`POST /oauth/revoke`**

Revokes an access or refresh token.

**Authentication:** Client credentials required

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Token to revoke |
| `token_type_hint` | string | No | "access_token" or "refresh_token" |

**Response:** HTTP 200 OK (empty body)

### OpenID Connect Endpoints

#### Discovery Endpoint

**`GET /.well-known/openid-configuration`**

Returns OpenID Provider configuration.

**Response:**

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "claims_supported": ["sub", "name", "email", "iat", "exp"]
}
```

#### UserInfo Endpoint

**`GET /userinfo`**

Returns claims about the authenticated user.

**Authentication:** Bearer token required

**Response:**

```json
{
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "email_verified": true
}
```

### Management Endpoints

#### Create Client

**`POST /clients`**

Creates a new OAuth client.

**Authentication:** Admin token required

**Request Body:**

```json
{
  "name": "My Application",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"],
  "is_public": false
}
```

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "client_id": "abc123xyz789",
  "client_secret": "secret_key_for_confidential_client",
  "name": "My Application",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"],
  "is_public": false,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### Create User

**`POST /users`**

Registers a new user.

**Request Body:**

```json
{
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

**Response:**

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "full_name": "John Doe",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Error Responses

All endpoints return errors in the following format:

```json
{
  "error": "invalid_request",
  "error_description": "The request is missing a required parameter"
}
```

**Common Error Codes:**

| Error Code | Description |
|------------|-------------|
| `invalid_request` | Malformed or missing parameters |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Invalid authorization code or refresh token |
| `unauthorized_client` | Client not authorized for this grant type |
| `unsupported_grant_type` | Grant type not supported |
| `invalid_scope` | Requested scope is invalid |
| `access_denied` | User denied authorization |
| `server_error` | Internal server error |

---

**Tác giả:** Manus AI  
**Phiên bản:** 1.0  
**Ngày cập nhật:** 2024-01-15

