# 概述

`uTLS` 是 [refraction-networking/utls](https://github.com/refraction-networking/utls) 的 Python 实现：一个可完全自定义 TLS ClientHello 指纹的客户端库。

## uTLS 是干什么的

普通 TLS 客户端通常通过 `SSLContext` 这类高层接口使用，ClientHello 由底层库自动生成。  
`uTLS` 让你**逐字节控制 ClientHello**，从而模拟真实浏览器或任意自定义客户端的 TLS 指纹。

它用 Python 实现：

- TLS 握手状态机
- TLS 记录层
- TLS 1.0–1.3 密钥调度
- ClientHello 扩展构造与解析
- 证书路径验证、OCSP/CRL、SCT 回调
- ECH（Encrypted Client Hello）
- 会话恢复与 0-RTT

密码学原语来自 `cryptography`；`X25519MLKEM768` 中的 ML-KEM-768 为纯 Python 实现。

## 可以控制什么

- cipher suite 顺序
- GREASE 占位符与位置
- 扩展类型、顺序和内部布局：SNI、ALPN、key_share、ALPS、ECH、padding、trust_anchors 等
- TLS 版本列表
- 签名算法列表
- 会话 ID 长度
- ClientHello 随机数和 padding 策略
- 浏览器预设或完全自定义 `ClientHelloSpec`

## 它不是

- **不是 HTTP/2 或 QUIC 实现**：只负责 TLS；HTTP/2 交给 `h2`/`httpx`，QUIC 交给 `aioquic`
- **不是服务端 TLS**：只实现客户端
- **不是代理、VPN 或反检测产品**
- **不保证绕过任何风控、WAF 或反爬系统**
- **不是经过独立安全审计的密码学产品**

## 设计取向

- 指纹保真优先：预设尽量贴近上游 uTLS/浏览器行为
- 默认安全：证书验证、主机名校验、协商参数绑定、截断检测默认开启
- 可组合：`ClientHelloSpec`、扩展类、预设、ECH 配置都可以独立替换
- 不隐藏边界：HTTP/2、QUIC、服务端 TLS 明确不属于本库

## 适合谁

- 需要精确控制 ClientHello 的兼容性测试
- TLS 指纹、ECH、会话恢复、0-RTT 研究
- 内部 mTLS / 私有 PKI 客户端
- 需要复现历史浏览器指纹的测试工具
- 需要自定义证书验证、keylog 或客户端证书选择的应用

## 使用边界

本项目适合授权测试、协议研究、兼容性验证和需要精确 ClientHello 的客户端。  
请遵守当地法律、服务条款和授权范围，不要用于未授权访问、绕过访问控制、欺诈或其他滥用场景。

下一步：

- [功能与支持范围](features.md)
- [使用指南](usage.md)
- [应用场景](scenarios.md)
- [安全说明](security.md)
