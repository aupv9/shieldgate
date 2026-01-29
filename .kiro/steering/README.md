# ShieldGate Agent Steering Files

Thư mục này chứa các file steering để hướng dẫn AI agent trong quá trình phát triển project ShieldGate OAuth 2.0 Authorization Server.

## Mục đích

Agent steering giúp AI agent hiểu rõ:
- Cấu trúc và kiến trúc của project
- Coding standards và best practices
- OAuth 2.0/OIDC implementation patterns
- Testing guidelines và security practices
- Development workflow và deployment procedures

## Danh sách Steering Files

### 1. `project-overview.md`
**Mục đích**: Tổng quan về project ShieldGate
**Nội dung**:
- Thông tin cơ bản về project (tên, ngôn ngữ, kiến trúc)
- Cấu trúc thư mục và organization
- Các tính năng chính và OAuth flows được hỗ trợ
- Security features và compliance requirements

**Khi nào sử dụng**: Luôn được include để agent hiểu context của project

### 2. `coding-standards.md`
**Mục đích**: Định nghĩa coding standards và conventions
**Nội dung**:
- Go coding guidelines và naming conventions
- Error handling patterns
- Logging standards với structured logging
- Security practices và input validation
- Testing standards và database patterns
- HTTP handler patterns với consistent response structure

**Khi nào sử dụng**: Khi viết hoặc review code

### 3. `oauth-implementation.md`
**Mục đích**: Hướng dẫn implement OAuth 2.0 và OpenID Connect
**Nội dung**:
- Authorization Code Flow với PKCE implementation
- JWT token generation và validation
- OpenID Connect ID token và UserInfo endpoint
- Discovery endpoint configuration
- Security best practices cho OAuth flows
- Rate limiting và scope validation

**Khi nào sử dụng**: Khi làm việc với OAuth/OIDC functionality

### 4. `testing-guidelines.md`
**Mục đích**: Hướng dẫn testing comprehensive
**Nội dung**:
- Test structure và organization
- Unit, integration, và OAuth flow testing patterns
- Mock services và test utilities
- Security testing patterns
- Test coverage requirements
- CI/CD testing pipeline

**Khi nào sử dụng**: Khi viết tests hoặc setup testing infrastructure

### 5. `deployment-operations.md`
**Mục đích**: Hướng dẫn deployment và operations
**Nội dung**:
- Development environment setup
- Configuration management
- Docker và Kubernetes deployment
- Monitoring, logging, và observability
- Security operations và secret management
- Backup, recovery, và performance tuning

**Khi nào sử dụng**: Khi setup environment hoặc deploy application

### 6. `development-workflow.md`
**Mục đích**: Định nghĩa development workflow và processes
**Nội dung**:
- Git workflow và branch strategy
- Commit message conventions
- Pull request process và code review guidelines
- Development commands và tools setup
- Debugging guidelines và performance profiling
- Release process và deployment checklist

**Khi nào sử dụng**: Khi setup development environment hoặc follow development processes

## Cách Sử dụng

### Automatic Inclusion
Tất cả steering files được automatically include khi agent làm việc trong workspace này, giúp agent luôn có context đầy đủ về project.

### Manual Reference
Bạn có thể reference specific steering files bằng cách sử dụng `#` trong chat:
```
#steering/oauth-implementation.md - để focus vào OAuth implementation
#steering/testing-guidelines.md - để focus vào testing practices
```

### File-Specific Inclusion
Một số steering files có thể được configure để chỉ include khi làm việc với specific file types hoặc directories.

## Best Practices

### Khi Thêm Steering Rules Mới
1. **Specific và Actionable**: Viết instructions cụ thể, có thể thực hiện được
2. **Context-Aware**: Bao gồm đủ context để agent hiểu khi nào áp dụng
3. **Examples**: Cung cấp code examples và patterns cụ thể
4. **Consistent**: Đảm bảo consistency với existing steering files

### Khi Update Steering Files
1. **Incremental Updates**: Update từng phần nhỏ thay vì rewrite toàn bộ
2. **Version Control**: Track changes trong git để có thể rollback nếu cần
3. **Team Alignment**: Đảm bảo team đồng ý với changes
4. **Documentation**: Update README này khi thêm hoặc modify steering files

## Troubleshooting

### Agent Không Follow Steering Guidelines
- Kiểm tra file có syntax errors không
- Đảm bảo instructions đủ specific và clear
- Consider breaking down complex rules thành smaller, focused files

### Conflicting Guidelines
- Workspace-level steering takes precedence over global rules
- Later files trong alphabetical order có thể override earlier files
- Use specific file inclusion patterns để avoid conflicts

### Performance Issues
- Quá nhiều steering content có thể impact agent performance
- Consider using conditional inclusion based on file patterns
- Keep steering files focused và concise

## Maintenance

### Regular Reviews
- Review steering files quarterly để ensure relevance
- Update based on project evolution và new requirements
- Remove outdated hoặc conflicting guidelines

### Team Feedback
- Collect feedback từ developers về steering effectiveness
- Adjust guidelines based on real-world usage patterns
- Document common issues và solutions

---

**Note**: Steering files này được design để evolve cùng với project. Đừng ngần ngại update chúng khi requirements hoặc best practices thay đổi.