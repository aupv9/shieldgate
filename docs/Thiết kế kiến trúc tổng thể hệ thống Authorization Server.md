
# Thiết kế kiến trúc tổng thể hệ thống Authorization Server

## 1. Tổng quan kiến trúc

Hệ thống Authorization Server sẽ được thiết kế theo kiến trúc microservice, tập trung vào tính mô-đun, khả năng mở rộng và bảo mật. Nó sẽ đóng vai trò là trung tâm quản lý danh tính và ủy quyền cho các hệ thống tích hợp với nền tảng của người dùng, sử dụng các tiêu chuẩn công nghiệp như OAuth 2.0 và OpenID Connect.

### Các nguyên tắc thiết kế chính:

*   **Statelessness**: Hạn chế tối đa việc lưu trữ trạng thái phiên trên server để tăng khả năng mở rộng và chịu lỗi.
*   **Scalability**: Thiết kế để dễ dàng mở rộng theo chiều ngang, xử lý lượng lớn yêu cầu đồng thời.
*   **Security by Design**: Bảo mật được tích hợp từ giai đoạn thiết kế, bao gồm mã hóa, quản lý khóa an toàn, và tuân thủ các best practices về bảo mật.
*   **API-first**: Cung cấp các API rõ ràng, dễ sử dụng và có tài liệu đầy đủ để các hệ thống khác có thể tích hợp dễ dàng.
*   **Observability**: Tích hợp logging, monitoring và tracing để dễ dàng gỡ lỗi và theo dõi hiệu suất.

## 2. Các thành phần chính của hệ thống

Hệ thống Authorization Server sẽ bao gồm các thành phần chính sau:

*   **API Gateway**: Điểm truy cập duy nhất cho tất cả các yêu cầu từ client. Nó sẽ chịu trách nhiệm định tuyến, xác thực cơ bản (nếu có), rate limiting và bảo mật.
*   **Authorization Service (Core)**: Dịch vụ cốt lõi xử lý logic ủy quyền chính, bao gồm:
    *   Quản lý Client (đăng ký, quản lý thông tin client).
    *   Quản lý Người dùng (đăng ký, xác thực, quản lý hồ sơ).
    *   Quản lý Token (tạo, xác thực, thu hồi Access Token, Refresh Token, ID Token).
    *   Xử lý các luồng OAuth 2.0 (Authorization Code, Client Credentials, PKCE, v.v.).
    *   Xử lý OpenID Connect (cung cấp thông tin danh tính).
*   **Database**: Lưu trữ dữ liệu liên quan đến người dùng, client, token, và các cấu hình ủy quyền. Cần xem xét các loại cơ sở dữ liệu phù hợp với yêu cầu về hiệu suất và khả năng mở rộng.
*   **Cache/Key-Value Store**: Sử dụng để lưu trữ tạm thời các token, session hoặc các dữ liệu thường xuyên được truy cập để cải thiện hiệu suất.
*   **Logging & Monitoring System**: Thu thập và phân tích log, metric để theo dõi tình trạng hoạt động, phát hiện lỗi và các vấn đề bảo mật.

## 3. Luồng hoạt động cơ bản (Authorization Code Flow với PKCE)

Đây là luồng được khuyến nghị cho các ứng dụng client công khai (public client) như ứng dụng di động hoặc SPA, vì nó cung cấp bảo mật cao hơn so với Implicit Flow.

1.  **Client yêu cầu ủy quyền**: Ứng dụng client chuyển hướng người dùng đến `/authorize` endpoint của Authorization Server, kèm theo `client_id`, `redirect_uri`, `scope`, `response_type=code`, `code_challenge` và `code_challenge_method`.
2.  **Xác thực và chấp thuận của người dùng**: Authorization Server xác thực người dùng (nếu chưa đăng nhập) và yêu cầu người dùng cấp quyền cho ứng dụng client truy cập các `scope` được yêu cầu. Nếu người dùng chấp thuận, Authorization Server sẽ tạo một `authorization code`.
3.  **Authorization Server chuyển hướng**: Authorization Server chuyển hướng người dùng trở lại `redirect_uri` của client, kèm theo `authorization code`.
4.  **Client yêu cầu Access Token**: Ứng dụng client gửi `authorization code`, `client_id`, `redirect_uri`, `code_verifier` và `grant_type=authorization_code` đến `/token` endpoint của Authorization Server (thông qua kênh bảo mật).
5.  **Authorization Server cấp Token**: Authorization Server xác thực `authorization code` và `code_verifier`. Nếu hợp lệ, nó sẽ cấp `Access Token`, `Refresh Token` và `ID Token` (nếu là OpenID Connect) cho client.
6.  **Client truy cập tài nguyên**: Ứng dụng client sử dụng `Access Token` để gọi các API của Resource Server (nền tảng của người dùng). Resource Server sẽ xác thực `Access Token` bằng cách gọi Introspection Endpoint của Authorization Server hoặc tự xác minh JWT (nếu token là JWT).
7.  **Làm mới Access Token**: Khi `Access Token` hết hạn, client có thể sử dụng `Refresh Token` để yêu cầu một `Access Token` mới từ `/token` endpoint (với `grant_type=refresh_token`).

## 4. Database Schema (Ví dụ đơn giản)

### Bảng `users`

| Tên trường | Kiểu dữ liệu | Mô tả |
|---|---|---|
| `id` | UUID/INT | ID duy nhất của người dùng |
| `username` | VARCHAR(255) | Tên đăng nhập (duy nhất) |
| `email` | VARCHAR(255) | Email của người dùng (duy nhất) |
| `password_hash` | VARCHAR(255) | Hash của mật khẩu |
| `created_at` | TIMESTAMP | Thời gian tạo tài khoản |
| `updated_at` | TIMESTAMP | Thời gian cập nhật cuối cùng |

### Bảng `clients`

| Tên trường | Kiểu dữ liệu | Mô tả |
|---|---|---|
| `id` | UUID/INT | ID duy nhất của client |
| `client_id` | VARCHAR(255) | Client ID (duy nhất, công khai) |
| `client_secret` | VARCHAR(255) | Client Secret (bí mật, chỉ cho client confidential) |
| `name` | VARCHAR(255) | Tên ứng dụng client |
| `redirect_uris` | TEXT[] | Danh sách các URI chuyển hướng hợp lệ (mảng chuỗi) |
| `grant_types` | TEXT[] | Các loại grant flow được phép (mảng chuỗi) |
| `scopes` | TEXT[] | Các scope được phép (mảng chuỗi) |
| `is_public` | BOOLEAN | True nếu là public client (ví dụ: SPA, mobile app) |
| `created_at` | TIMESTAMP | Thời gian đăng ký client |
| `updated_at` | TIMESTAMP | Thời gian cập nhật cuối cùng |

### Bảng `authorization_codes`

| Tên trường | Kiểu dữ liệu | Mô tả |
|---|---|---|
| `id` | UUID/INT | ID duy nhất của code |
| `code` | VARCHAR(255) | Mã ủy quyền |
| `client_id` | UUID/INT | ID của client |
| `user_id` | UUID/INT | ID của người dùng |
| `redirect_uri` | VARCHAR(255) | URI chuyển hướng được sử dụng |
| `scope` | TEXT | Scope được cấp |
| `code_challenge` | VARCHAR(255) | Code challenge cho PKCE |
| `code_challenge_method` | VARCHAR(50) | Phương thức code challenge (S256, plain) |
| `expires_at` | TIMESTAMP | Thời gian hết hạn của code |
| `created_at` | TIMESTAMP | Thời gian tạo code |

### Bảng `access_tokens`

| Tên trường | Kiểu dữ liệu | Mô tả |
|---|---|---|
| `id` | UUID/INT | ID duy nhất của token |
| `token` | VARCHAR(255) | Giá trị Access Token (có thể là JWT) |
| `client_id` | UUID/INT | ID của client |
| `user_id` | UUID/INT | ID của người dùng |
| `scope` | TEXT | Scope được cấp |
| `expires_at` | TIMESTAMP | Thời gian hết hạn của token |
| `created_at` | TIMESTAMP | Thời gian tạo token |

### Bảng `refresh_tokens`

| Tên trường | Kiểu dữ liệu | Mô tả |
|---|---|---| 
| `id` | UUID/INT | ID duy nhất của token |
| `token` | VARCHAR(255) | Giá trị Refresh Token |
| `client_id` | UUID/INT | ID của client |
| `user_id` | UUID/INT | ID của người dùng |
| `expires_at` | TIMESTAMP | Thời gian hết hạn của token |
| `created_at` | TIMESTAMP | Thời gian tạo token |

## 5. API Endpoints (Ví dụ)

### 5.1. OAuth 2.0 / OpenID Connect Endpoints

*   **`/oauth/authorize` (GET)**: Endpoint ủy quyền. Người dùng được chuyển hướng đến đây để xác thực và cấp quyền.
    *   **Tham số**: `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`.
    *   **Phản hồi**: Chuyển hướng đến `redirect_uri` với `code` và `state`.

*   **`/oauth/token` (POST)**: Endpoint token. Client sử dụng `authorization code` hoặc `refresh token` để đổi lấy `Access Token`.
    *   **Tham số**: `grant_type`, `code`, `redirect_uri`, `client_id`, `client_secret`, `code_verifier`, `refresh_token`.
    *   **Phản hồi**: JSON chứa `access_token`, `token_type`, `expires_in`, `refresh_token`, `id_token` (nếu OIDC).

*   **`/oauth/introspect` (POST)**: Endpoint kiểm tra token. Resource Server có thể gọi để xác minh tính hợp lệ của `Access Token`.
    *   **Tham số**: `token`.
    *   **Phản hồi**: JSON chứa `active` (boolean), `scope`, `client_id`, `user_id`, `exp`, `iat`, v.v.

*   **`/oauth/revoke` (POST)**: Endpoint thu hồi token. Client có thể gọi để thu hồi `Access Token` hoặc `Refresh Token`.
    *   **Tham số**: `token`, `token_type_hint`.
    *   **Phản hồi**: HTTP 200 OK.

*   **`/.well-known/openid-configuration` (GET)**: Endpoint khám phá OpenID Provider. Cung cấp thông tin cấu hình của Authorization Server.
    *   **Phản hồi**: JSON chứa các endpoint, thuật toán được hỗ trợ, v.v.

*   **`/userinfo` (GET)**: Endpoint UserInfo. Client sử dụng `Access Token` để lấy thông tin hồ sơ người dùng.
    *   **Yêu cầu**: `Authorization: Bearer <access_token>`.
    *   **Phản hồi**: JSON chứa các claims về người dùng (ví dụ: `sub`, `name`, `email`).

### 5.2. Client Management Endpoints (cho quản trị viên)

*   **`/clients` (POST)**: Đăng ký client mới.
    *   **Yêu cầu**: JSON chứa `client_id`, `client_secret`, `name`, `redirect_uris`, `grant_types`, `scopes`, `is_public`.
    *   **Phản hồi**: Thông tin client đã đăng ký.

*   **`/clients/{client_id}` (GET)**: Lấy thông tin client theo ID.
*   **`/clients/{client_id}` (PUT)**: Cập nhật thông tin client.
*   **`/clients/{client_id}` (DELETE)**: Xóa client.

### 5.3. User Management Endpoints (cho quản trị viên hoặc người dùng tự quản lý)

*   **`/users` (POST)**: Đăng ký người dùng mới.
    *   **Yêu cầu**: JSON chứa `username`, `email`, `password`.
    *   **Phản hồi**: Thông tin người dùng đã đăng ký.

*   **`/users/{user_id}` (GET)**: Lấy thông tin người dùng theo ID.
*   **`/users/{user_id}` (PUT)**: Cập nhật thông tin người dùng.
*   **`/users/{user_id}` (DELETE)**: Xóa người dùng.

## 6. Công nghệ sử dụng (Golang)

*   **Ngôn ngữ lập trình**: Golang
*   **Web Framework**: Có thể sử dụng `net/http` tiêu chuẩn hoặc các framework nhẹ như `Gin` hoặc `Echo` để xây dựng API.
*   **Thư viện OAuth 2.0**: `github.com/go-oauth2/oauth2` là một thư viện mạnh mẽ để triển khai OAuth 2.0 server.
*   **Thư viện JWT**: `github.com/golang-jwt/jwt` hoặc `github.com/dgrijalva/jwt-go`.
*   **Băm mật khẩu**: `golang.org/x/crypto/bcrypt`.
*   **Cơ sở dữ liệu**: PostgreSQL (với `database/sql` và driver như `github.com/lib/pq`) hoặc MongoDB (với driver `go.mongodb.org/mongo-driver`).
*   **Cache**: Redis (với `github.com/go-redis/redis/v8`).
*   **Logging**: `logrus` hoặc `zap`.
*   **Monitoring**: Prometheus và Grafana.
*   **Containerization**: Docker.

## 7. Cân nhắc bảo mật

*   **Sử dụng HTTPS/TLS**: Bắt buộc cho tất cả các giao tiếp.
*   **Băm mật khẩu mạnh**: Luôn sử dụng các thuật toán băm mật khẩu an toàn như bcrypt.
*   **Quản lý Client Secret an toàn**: Đối với client confidential, `client_secret` phải được bảo vệ nghiêm ngặt.
*   **PKCE**: Luôn sử dụng PKCE cho các public client để ngăn chặn tấn công chiếm quyền ủy quyền code.
*   **Thời gian sống của Token**: Đặt thời gian sống ngắn cho Access Token và sử dụng Refresh Token để cấp lại. Refresh Token nên có thời gian sống dài hơn nhưng cũng cần được thu hồi khi cần.
*   **Thu hồi Token**: Triển khai cơ chế thu hồi token hiệu quả.
*   **Xác thực đầu vào**: Luôn xác thực tất cả đầu vào từ client để ngăn chặn các cuộc tấn công như SQL Injection, XSS.
*   **Rate Limiting**: Áp dụng giới hạn tốc độ cho các endpoint để ngăn chặn tấn công brute-force.
*   **Logging và Auditing**: Ghi lại các sự kiện quan trọng để phục vụ mục đích kiểm tra và phát hiện bất thường.
*   **CORS**: Cấu hình CORS đúng cách để chỉ cho phép các nguồn đáng tin cậy truy cập API.

Đây là bản thiết kế kiến trúc tổng thể. Các bước tiếp theo sẽ đi sâu vào việc tạo sơ đồ và documentation kỹ thuật chi tiết hơn.

