# Changelog

## 0.1.0 - 2026-11-15

首个发布版本。

### TLS

- TLS 1.0–1.3 客户端，TLS 1.2 ECDHE/RSA，TLS 1.3 HRR、KeyUpdate、0-RTT
- X25519、P-256/384/521、`X25519MLKEM768`
- AES-GCM、ChaCha20-Poly1305、AES-CBC、3DES（legacy opt-in）
- RSA PKCS#1、RSA-PSS、ECDSA、Ed25519、Ed448
- TLS 1.3 PSK / TLS 1.2 ticket / session ID 会话恢复

### ClientHello 与指纹

- 完全自定义 `ClientHelloSpec`
- Chrome / Firefox / Safari / iOS / Android / Edge / 360 / QQ / Go 预设
- GREASE、padding、ALPS、trust_anchors、ECH-GREASE
- JA3、ClientHello 解析、`Fingerprinter`
- `ClientHelloSpec` JSON 导入/导出
- legacy 预设生成器

### ECH

- RFC 9849 ECHConfigList、HPKE、ClientHelloInner/Outer
- ECH + PSK 恢复
- ECH + HelloRetryRequest
- ECH 拒绝回退与 retry configs

### 证书与安全

- RFC 5280 证书路径验证
- Public Suffix List 通配符校验
- OCSP / CRL / SCT 回调
- TLS 降级 sentinel 与协商参数绑定
- `close_notify` / 截断区分，拒绝明文控制记录

### API

- 同步 `UConn`、asyncio `AsyncUConn`
- `makefile()` / `fileno()` / `recv_into()` socket 兼容
- 客户端证书选择回调、verify 回调、keylog
- `Config.from_go()` 与 Go 风格属性别名
- `py.typed`

### 工程化

- 137 个测试（5 个网络测试默认跳过）
- GitHub Actions CI（Python 3.10–3.13）
- 覆盖率报告
- PyPI Trusted Publishing 发布工作流
