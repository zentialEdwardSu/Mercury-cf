# 🌩️ KV Sync Service API 文档

**Base URL:**

```
https://<your-worker-subdomain>.workers.dev
```

------

## 🔐 1. 认证接口

### `POST /auth/login`

**说明**
 为指定租户生成短期 JWT，供后续 API 使用。

**请求头**

```
Content-Type: application/json
```

**请求体**

```json
{
  "tenant_id": "tenant-001",
  "shared_secret": "example-shared-key"
}
```

**响应示例**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5..."
}
```

**错误响应**

| 状态码 | 含义                                        |
| ------ | ------------------------------------------- |
| 401    | 认证失败（租户不存在或 shared_secret 错误） |
| 400    | 请求体错误                                  |

------

## 📄 2. 文档读写接口

### `GET /tenant/:tenantId/docs/:docId`

**说明**
 获取指定文档的最新版本（加密后的 JSON 数据），客户端需自行解密。

**认证**

```
Authorization: Bearer <JWT>
```

**响应**

```json
{
  "ciphertext": "Base64-encoded-ciphertext",
  "version": 7
}
```

**错误响应**

| 状态码 | 含义                      |
| ------ | ------------------------- |
| 401    | 未授权（缺少或无效 JWT）  |
| 403    | JWT 所属租户与 URL 不匹配 |
| 404    | 文档不存在                |

------

### `PUT /tenant/:tenantId/docs/:docId`

**说明**
 上传或更新文档内容（客户端应先加密 JSON 数据）。

**认证**

```
Authorization: Bearer <JWT>
Content-Type: application/json
```

**请求体**

```json
{
  "ciphertext": "Base64-encoded-ciphertext",
  "version": 7
}
```

**响应**

```json
{
  "ok": true,
  "version": 8
}
```

**错误响应**

| 状态码 | 含义                       |
| ------ | -------------------------- |
| 401    | 未授权                     |
| 403    | 租户不匹配                 |
| 409    | 版本冲突（客户端版本落后） |

------

## 🧱 3. 数据结构定义

| 字段         | 类型   | 说明                                      |
| ------------ | ------ | ----------------------------------------- |
| `ciphertext` | string | AES-GCM 加密后的 JSON 数据（Base64 编码） |
| `version`    | number | 文档的递增版本号，用于同步检测冲突        |
| `tenant_id`  | string | 租户标识                                  |
| `doc_id`     | string | 文档标识                                  |
| `token`      | string | JWT 凭证                                  |

------

## ⚙️ 4. JWT 内容格式

**算法**: HS256
 **有效期**: 15 分钟

**Payload 示例**

```json
{
  "tenant": "tenant-001",
  "iat": 1690000000,
  "exp": 1690000900
}
```

------

## 🔒 5. 权限与租户模型

- **多租户隔离**：每个 `tenantId` 在 `TENANT_KV` 中维护自己的 `shared_secret`。
- **租户凭证**：租户凭证仅在 `/auth/login` 中用于签发 JWT，不参与数据加密。
- **数据加密**：文档内容端到端加密（客户端持有密钥）。服务器仅存储 opaque ciphertext。
- **版本冲突**：当 `PUT` 提交版本落后时返回 409，客户端可选择先 `GET` 再合并重试。

------

## 📦 6. SDK 实现建议

1. **模块分层**

   - `AuthClient`：封装 `/auth/login` 登录与 JWT 缓存。
   - `KVClient`：实现 `getDoc` / `putDoc` 并自动处理版本控制。
   - `Crypto`：负责本地 AES-GCM 加密与解密。

2. **典型调用流程**

   ```ts
   const token = await authClient.login(tenantId, sharedSecret);
   const kv = new KVClient(token);
   
   // 下载 & 解密
   const { ciphertext, version } = await kv.getDoc(tenantId, "settings");
   const json = await crypto.decrypt(ciphertext, key);
   
   // 修改 & 上传
   json.theme = "dark";
   const newCipher = await crypto.encrypt(json, key);
   await kv.putDoc(tenantId, "settings", newCipher, version);
   ```

3. **加密算法推荐**

   - AES-GCM 256bit
   - 使用随机 12-byte nonce
   - 输出格式：`base64(iv || ciphertext || tag)`