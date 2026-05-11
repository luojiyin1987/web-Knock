# Knock

`Knock` 是一个面向 Web 应用的通用鉴权网关 MVP，目标是先把统一认证的核心链路跑通：

- 客户端凭证校验
- 用户登录
- 访问令牌签发
- 刷新令牌轮换
- Session 查询
- Token introspection
- 登出撤销

当前实现刻意保持为零外部依赖，方便先验证接口模型，再替换为数据库、SSO、OIDC 或上游身份源。

## 快速开始

```bash
npm start
```

服务默认监听 `http://localhost:3000`。

打开浏览器访问：

```text
http://localhost:3000
```

页面内置一个测试控制台，默认示例账号如下：

- Client: `dashboard-web` / `dashboard-secret`
- Client: `internal-api` / `internal-secret`
- User: `alice` / `knock-knock`
- User: `bob` / `open-the-door`

## API

### `POST /v1/auth/login`

```json
{
  "clientId": "dashboard-web",
  "clientSecret": "dashboard-secret",
  "username": "alice",
  "password": "knock-knock"
}
```

### `POST /v1/auth/refresh`

```json
{
  "clientId": "dashboard-web",
  "clientSecret": "dashboard-secret",
  "refreshToken": "..."
}
```

### `GET /v1/auth/session`

Header:

```text
Authorization: Bearer <access-token>
```

### `POST /v1/auth/introspect`

```json
{
  "clientId": "internal-api",
  "clientSecret": "internal-secret",
  "token": "..."
}
```

### `POST /v1/auth/logout`

可以传 `refreshToken`、`accessToken`，或者直接使用 Bearer Token。

## 配置

支持的环境变量：

- `PORT`
- `KNOCK_ISSUER`
- `KNOCK_TOKEN_SECRET`
- `KNOCK_ACCESS_TTL_SECONDS`
- `KNOCK_REFRESH_TTL_SECONDS`
- `KNOCK_ALLOWED_ORIGINS`
- `KNOCK_CLIENTS`
- `KNOCK_USERS`

其中 `KNOCK_CLIENTS` 和 `KNOCK_USERS` 使用 JSON 字符串传入，例如：

```bash
export KNOCK_CLIENTS='[
  {"id":"dashboard-web","secret":"dashboard-secret","name":"Dashboard","scopes":["profile","introspect"]}
]'

export KNOCK_USERS='[
  {"id":"user-1","username":"alice","password":"knock-knock","displayName":"Alice","roles":["admin"]}
]'
```

## 后续建议

这个版本是网关骨架，不是生产配置。下一步通常会补这些能力：

1. 持久化存储：把 refresh token、client 和 user 切到 Redis / Postgres。
2. 标准协议：补齐 OAuth2 / OIDC 授权码、PKCE、JWKS、标准 discovery。
3. 身份源接入：LDAP、SAML、企业微信、飞书、GitHub、Google。
4. 安全加固：限流、审计日志、MFA、设备指纹、细粒度权限模型。
