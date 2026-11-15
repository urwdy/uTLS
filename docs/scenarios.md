# 应用场景

以下场景都应建立在授权、合法和安全测试的前提下。

## 1. TLS 指纹兼容性测试

验证服务端、WAF、CDN 或反爬系统看到的 JA3/ClientHello 是否符合预期。

```python
import utls

conn = utls.connect(
    "tls.peet.ws",
    443,
    preset=utls.HelloChrome_133,
    alpn=["http/1.1"],
)
print(utls.ja3(conn.get_client_hello()))
print(conn.connection_state())
conn.close()
```

适合：

- 对比不同浏览器预设的 JA3
- 验证自定义 `ClientHelloSpec`
- 测试服务端对扩展顺序、GREASE、ALPS、ECH 的处理

## 2. 浏览器行为模拟

某些站点或 API 会根据 TLS 指纹、ALPN、扩展组合返回不同结果。  
在获得授权并遵守服务条款的前提下，可以用浏览器预设做兼容性测试：

```python
conn = utls.connect(
    "example.com",
    443,
    preset=utls.HelloChrome_Auto,
    alpn=["http/1.1"],
)
```

也可从真实浏览器/客户端抓包还原指纹：

```python
spec = utls.Fingerprinter().FingerprintClientHello(raw_client_hello)
conn = utls.connect("example.com", 443, client_hello=spec)
```

## 3. ECH 隐私与部署研究

测试 Encrypted Client Hello 的配置获取、接受/拒绝、HRR 和会话恢复：

```python
ech = utls.fetch_ech_config_list("crypto.cloudflare.com")
conn = utls.connect(
    "crypto.cloudflare.com",
    443,
    preset=utls.HelloChrome_120,
    ech_config_list=ech,
)
print(conn.connection_state().ech_accepted)
print(conn.connection_state().ech_public_name)
```

适合：

- 检查服务端是否接受 ECH
- 测试 ECH + PSK 恢复
- 测试 ECH + HelloRetryRequest
- 验证 ECH 被拒绝时的 outer 回退

## 4. mTLS / 私有 PKI

使用静态客户端证书，或通过回调动态选择证书：

```python
def select(acceptable_cas, signature_algorithms):
    return [cert_pem], key_pem

conn = utls.connect(
    "internal.example",
    443,
    config=utls.Config(
        server_name="internal.example",
        get_client_certificate=select,
    ),
)
```

适合：

- 内部服务 mTLS
- HSM/KMS 外部签名前的接口验证
- 多证书/多 CA 场景

## 5. 旧版 TLS 与历史指纹复现

TLS 1.0/1.1、CBC、3DES 和 RSA 静态密钥交换默认被拒绝。  
确需测试旧系统时显式开启：

```python
config = utls.Config(
    server_name="legacy.example",
    allow_legacy_ciphers=True,
    allow_rsa_key_exchange=True,
)
```

适合：

- 旧客户端/旧服务端兼容性验证
- 历史浏览器指纹复现
- 协议迁移评估

## 6. 协议与安全测试

可用于构造受控的 TLS 测试场景：

- HRR、KeyUpdate、0-RTT、会话恢复
- 证书链、EKU、NameConstraints、PSL 通配符
- OCSP/CRL
- ClientHello 解析与 JSON 回放
- 自定义证书验证、keylog 调试

## 7. 指纹抓包与回放

```python
raw = captured_client_hello
spec = utls.Fingerprinter().FingerprintClientHello(raw)
text = spec.to_json(indent=2)
```

可以把 Spec 保存为 JSON，后续恢复并重新构造 ClientHello。

参见：

- [使用指南](usage.md)
- [功能与支持范围](features.md)
- [安全说明](security.md)
