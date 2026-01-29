# 🛡️ ShieldGate OAuth - Bắt đầu ngay

## 1. Khởi động

```bash
docker-compose up -d
```

## 2. Fix port (nếu cần)

```bash
docker stop shieldgate-auth-server
docker run -d --name shieldgate-auth-server -p 8080:8080 --network shieldgate_shieldgate-network -e DATABASE_URL="postgres://authuser:cpQAILEOfZNHqBKTr16t5S4hx@postgres:5432/authdb?sslmode=disable" -e JWT_SECRET="wFZ15iJ0VeRsd7rYncSayvf8hOKXxUCBpDAPgMuTQ3LbI6lNot49qzGk2jEmHW" -e GIN_MODE=debug shieldgate-auth-server
```

## 3. Test OAuth

Mở `oauth-simple.html` trong browser hoặc truy cập:

```
http://localhost:8080/oauth/authorize?response_type=code&client_id=test-client-123&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

**Login:** test@example.com / password123

## Xong! ✅