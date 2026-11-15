# 功能与支持范围

## 总览

| 领域 | 状态 | 说明 |
| --- | --- | --- |
| TLS 1.0–1.3 | 已实现 | 记录层、握手、密钥调度、HRR、KeyUpdate |
| ClientHello 自定义 | 已实现 | `ClientHelloSpec`、扩展类、GREASE、padding |
| 浏览器指纹 | 已实现 | Chrome / Firefox / Safari / iOS / Android / Edge / 360 / QQ / Go |
| TLS 1.3 | 已实现 | X25519、P-256/384/521、`X25519MLKEM768`、AES-GCM、ChaCha20、HRR、PSK、0-RTT |
| TLS 1.2 | 已实现 | ECDHE/RSA、AES-GCM、ChaCha20、CBC、3DES、EMS、ticket/session ID |
| TLS 1.0/1.1 | 已实现（opt-in） | CBC、legacy PRF；默认安全策略拒绝 CBC/RSA 静态密钥交换 |
| 证书验证 | 已实现 | RFC 5280 路径验证、hostname、EKU、CA 约束、PSL 通配符 |
| OCSP / CRL | 已实现 | stapled OCSP、主动查询、CRL 下载与校验 |
| SCT / CT | 部分实现 | 解析 SCT 并提供 `sct_verifier` 回调；不内置 CT log 列表 |
| ALPS | 部分实现 | 解析服务端协议列表，不实现 HTTP/2 ALPS 设置 |
| ECH | 已实现 | RFC 9849、HPKE、PSK、HRR、拒绝回退 |
| 会话恢复 | 已实现 | TLS 1.3 PSK、TLS 1.2 ticket/session ID |
| 0-RTT | 已实现 | `Config.early_data`；ECH + 0-RTT 未做真实服务端互操作验证 |
| 客户端证书 | 已实现 | 静态证书或 `get_client_certificate` 回调 |
| async API | 已实现（适配层） | `AsyncUConn` 使用线程池包装同步核心 |
| socket 兼容 | 已实现 | `makefile()`、`fileno()`、`recv_into()`、timeout/sockopt 委托 |
| 指纹工具 | 已实现 | JA3、ClientHello 解析、`Fingerprinter`、`ClientHelloSpec` JSON |
| HTTP/2 | 未实现 | 不属于 TLS 层 |
| QUIC | 未实现 | 独立传输协议 |
| ML-DSA | 未实现 | 等待 `cryptography`/底层库支持 |

## TLS 1.3

- 密钥交换：X25519、P-256、P-384、P-521、`X25519MLKEM768`
- 密码套件：AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305
- HelloRetryRequest
- KeyUpdate
- ALPN
- 客户端证书
- 证书压缩：zlib、brotli、zstd
- PSK 会话恢复（含 binder）
- 0-RTT early data

## TLS 1.2

- ECDHE_RSA、ECDHE_ECDSA、RSA 静态密钥交换
- AES-GCM、ChaCha20-Poly1305、AES-CBC、3DES
- Extended Master Secret
- ALPN
- 客户端证书
- OCSP stapling
- ticket / session ID 恢复

TLS 1.0/1.1 复用相同实现，需要显式启用 legacy 选项。

## 证书与吊销

- 基于 `cryptography.x509.verification` 的 RFC 5280 路径验证
- CA、KeyUsage、pathLen、NameConstraints、EKU、critical extensions
- 主机名与 IP SAN
- Public Suffix List 通配符校验
- 自定义根证书
- `insecure_skip_verify`
- OCSP stapling / 主动查询
- CRL 本地校验 / 下载
- SCT 列表解析与 `sct_verifier`

## ECH

- ECHConfigList 解析与 DoH 获取
- HPKE base mode：X25519 / P-256 / P-384 / P-521
- AES-GCM / ChaCha20-Poly1305
- ClientHelloInner / ClientHelloOuter
- ServerHello accept-confirmation
- ECH + PSK 会话恢复
- ECH + HelloRetryRequest
- ECH 拒绝回退
- retry configs（手动重试）

## 客户端认证

- 静态证书链 + 私钥
- `get_client_certificate` 动态选择
- TLS 1.2 / TLS 1.3 客户端 CertificateVerify
- 回调返回 `None` 时发送空 Certificate

## 工具与工程化

- `ClientHelloSpec.to_json()` / `from_json()`
- `utls.Fingerprinter`
- JA3 / JA3 hash
- `tools/gen_legacy_presets.py`
- `Config.from_go(...)` 和 Go 风格属性别名
- `py.typed`
- CI（Python 3.10–3.13）与覆盖率

## 未实现

- HTTP/2 协议本身
- QUIC
- 完整 CT log 策略
- Delegated Credentials 验证
- ML-DSA
- Kyber768 draft 预设（`HelloChrome_115_PQ` / `120_PQ`）
- 完全非阻塞的 async TLS 状态机
- ECH + 0-RTT 的真实服务端互操作验证

## 安全默认

- 默认验证证书链和主机名
- CBC/3DES 与 RSA 静态密钥交换默认拒绝
- 安装密钥后拒绝明文控制记录
- 区分 `close_notify` 与 TCP 截断
- 吊销 URL 默认阻止私网/loopback 和重定向
- ML-KEM 不是常数时间实现

详见 [安全说明](security.md)。
