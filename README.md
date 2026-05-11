# Knock

`Knock` 是一个面向 Web 应用的通用鉴权网关 MVP，目标是先把统一认证的核心链路跑通：

- 客户端凭证校验
- 用户登录（支持密码算法插件 + Cookie Session / Bearer Token 双通道）
- 访问令牌签发（JWT）
- 刷新令牌轮换
- Session 查询
- Token introspection
- 登出撤销
- ForwardAuth 网关检查（兼容 Traefik / Nginx）

当前实现刻意保持为**零外部运行时依赖**（仅开发期使用 `jose`、`zod`），方便先验证接口模型，再替换为数据库、SSO、OIDC 或上游身份源。

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

### Token 模式（API / 微服务）

#### `POST /v1/auth/login`

```json
{
  "clientId": "dashboard-web",
  "clientSecret": "dashboard-secret",
  "username": "alice",
  "password": "knock-knock"
}
```

响应包含 `accessToken`、`refreshToken`，同时设置 `knock_session` Cookie（浏览器场景自动使用）。

#### `POST /v1/auth/refresh`

```json
{
  "clientId": "dashboard-web",
  "clientSecret": "dashboard-secret",
  "refreshToken": "..."
}
```

#### `GET /v1/auth/session`

支持两种方式：

```text
Authorization: Bearer <access-token>
```

或携带 `knock_session` Cookie（浏览器场景无需手动传 Token）。

#### `POST /v1/auth/introspect`

```json
{
  "clientId": "internal-api",
  "clientSecret": "internal-secret",
  "token": "..."
}
```

#### `POST /v1/auth/logout`

可以传 `refreshToken`、`accessToken`，或者直接使用 Bearer Token / Cookie Session。

### ForwardAuth 模式（反向代理集成）

#### `GET /_auth`

用于 Traefik `forwardAuth` 或 Nginx `auth_request` 的鉴权检查端点。

- **API 请求**（`Accept: application/json`）：未认证返回 `401 Unauthorized`
- **浏览器请求**（`Accept: text/html`）：未认证返回 `302` 重定向到 `/_login?callback=<原始路径>`
- **认证成功**：返回 `200 OK` + `X-Forwarded-User: <username>` 响应头

反向代理配置示例（Traefik）：

```yaml
http:
  middlewares:
    knock-auth:
      forwardAuth:
        address: "http://knock:3000/_auth"
        authResponseHeaders: ["X-Forwarded-User"]
```

## 配置

支持的环境变量：

| 变量 | 说明 | 默认值 |
|---|---|---|
| `PORT` | 监听端口 | `3000` |
| `KNOCK_ISSUER` | JWT issuer | `knock.local` |
| `KNOCK_TOKEN_SECRET` | JWT 签名密钥 | `dev-knock-secret-change-me` |
| `KNOCK_ACCESS_TTL_SECONDS` | Access Token 有效期 | `900` |
| `KNOCK_REFRESH_TTL_SECONDS` | Refresh Token 有效期 | `604800` |
| `KNOCK_SESSION_TTL_SECONDS` | Cookie Session 有效期 | `86400` |
| `KNOCK_TRUST_PROXY` | 信任 `X-Forwarded-For` | `false` |
| `KNOCK_COOKIE_DOMAIN` | Cookie Domain（跨子域共享） | 不设置 |
| `KNOCK_ALLOWED_ORIGINS` | CORS 允许来源 | `["*"]` |
| `KNOCK_CLIENTS` | Client 配置 JSON | 见下文 |
| `KNOCK_USERS` | User 配置 JSON | 见下文 |
| `KNOCK_PASSWORD_ALGORITHM` | 默认密码算法 | `scrypt` |

其中 `KNOCK_CLIENTS` 和 `KNOCK_USERS` 使用 JSON 字符串传入，例如：

```bash
export KNOCK_CLIENTS='[
  {"id":"dashboard-web","secret":"dashboard-secret","name":"Dashboard","scopes":["profile","introspect"]}
]'

export KNOCK_USERS='[
  {"id":"user-1","username":"alice","password":"knock-knock","displayName":"Alice","roles":["admin"]}
]'
```

### 密码算法

支持通过插件注册多种密码算法，内置：

| 算法 | 说明 |
|---|---|
| `scrypt` | 默认，推荐 |
| `pbkdf2` | PBKDF2-HMAC-SHA512 |
| `hmac-sha512` | HMAC-SHA512（salted） |
| `plaintext` | 明文（仅测试用） |

自定义算法示例：

```js
import { registerAlgorithm } from "./src/lib/password-algorithms.js";

registerAlgorithm("bcrypt", {
  async create(password) { /* ... */ },
  async verify(password, record) { /* ... */ }
});
```

### 安全建议

- `KNOCK_TRUST_PROXY` 默认为 `false`。只有当服务明确部署在受信任的反向代理后面时，才应设置为 `true`，这样登录限流才会基于 `X-Forwarded-For` 取客户端 IP。
- 生产环境务必更换 `KNOCK_TOKEN_SECRET`。
- `plaintext` 算法仅用于测试，禁止用于生产环境。

## 代码质量

本项目使用 [pre-commit](https://pre-commit.com/) 进行代码质量检查，配置在 `.pre-commit-config.yaml`。

**pre-commit 在 CI 中自动运行**，本地开发无需安装。提交前会自动检查：

- 尾随空格、文件末尾换行符
- YAML/JSON 语法
- 合并冲突标记
- 敏感信息泄露（私钥、密码等）
- 禁止直接提交到 `main` 分支
- 禁止提交大文件（>500KB）
- 推送前自动运行 `npm test`

## 后续建议

这个版本是网关骨架，不是生产配置。下一步通常会补这些能力：

1. 持久化存储：把 refresh token、session、client 和 user 切到 Redis / Postgres。
2. 标准协议：补齐 OAuth2 / OIDC 授权码、PKCE、JWKS、标准 discovery。
3. 身份源接入：LDAP、SAML、企业微信、飞书、GitHub、Google。
4. 安全加固：审计日志、MFA、设备指纹、细粒度权限模型。
5. 可观测性：Prometheus `/metrics`、结构化日志。
