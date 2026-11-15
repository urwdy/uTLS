# 安全说明

## 默认行为

- 默认校验服务端证书链、主机名和 EKU
- 只有显式设置 `insecure_skip_verify=True` 才跳过验证
- CBC/3DES 与 RSA 静态密钥交换默认拒绝
- 安装密钥后拒绝明文控制记录
- 区分 `close_notify` 与 TCP 截断
- 吊销 URL 默认阻止私网/loopback 和重定向

## 证书路径验证

使用 `cryptography.x509.verification`，覆盖：

- BasicConstraints CA
- KeyUsage
- pathLenConstraint
- NameConstraints
- ExtendedKeyUsage
- critical extensions
- 主机名与 IP SAN
- Public Suffix List 通配符

## OCSP / CRL / SCT

- 支持 stapled OCSP 和主动查询
- 支持本地 CRL 和按 DistributionPoint 下载
- 支持 SCT 列表解析与 `sct_verifier` 回调
- 完整 CT log 策略需要调用方提供

## SSRF 风险

`fetch_crls` / `fetch_ocsp` 会使用证书中的 URL。  
默认阻止私网/loopback 地址并禁止 HTTP 重定向；仅在可信场景开启，并设置合理超时。

## ML-KEM

纯 Python ML-KEM-768 便于审计，但**不是常数时间**。  
适合指纹/研究场景；高价值长期密钥保护请使用原生实现。

## Legacy TLS

以下能力默认关闭：

- CBC / 3DES
- RSA 静态密钥交换
- TLS 1.0/1.1

需要时显式设置：

```python
Config(
    allow_legacy_ciphers=True,
    allow_rsa_key_exchange=True,
)
```

## 已知限制

- 未实现 HTTP/2、QUIC、服务端 TLS
- 未实现完整 CT log 策略
- 未实现 Delegated Credentials 验证
- 未实现 ML-DSA
- `AsyncUConn` 是线程适配，不是完全非阻塞状态机
- 尚未经过独立安全审计

## 使用建议

- 只在授权环境使用
- 优先使用系统根证书或明确配置的根证书
- 不要默认开启 `insecure_skip_verify`
- 不要在高价值长期密钥场景依赖纯 Python ML-KEM
- 对不可信网络中的 OCSP/CRL 抓取保持谨慎
