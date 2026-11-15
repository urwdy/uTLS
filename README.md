# uTLS (Python)

`uTLS` 是 [refraction-networking/utls](https://github.com/refraction-networking/utls) 的 Python 复刻：一个 **可完全自定义 TLS ClientHello 指纹** 的客户端库。

> 发行包名：`uTLS`，导入名：`utls`。本项目只提供库，不包含 CLI、示例脚本或完整 HTTP 客户端。

## 快速开始

```python
import utls

conn = utls.connect(
    "example.com",
    443,
    server_name="example.com",
    preset=utls.HelloChrome_Auto,
    alpn=["http/1.1"],
)

print(conn.connection_state())
conn.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
while chunk := conn.recv():
    print(chunk.decode("utf-8", "replace"), end="")
conn.close()
```

## 安装

```bash
uv sync
# 或
pip install .
```

要求 Python ≥ 3.10，运行时依赖 `cryptography>=42`、`brotli`、`zstandard`。

## 主要能力

- 逐字节控制 ClientHello：cipher suite、GREASE、扩展顺序与布局、版本、签名算法、padding
- TLS 1.0–1.3 客户端，支持 HRR、KeyUpdate、ALPN、客户端证书
- Chrome / Firefox / Safari / iOS / Android / Edge / 360 / QQ / Go 预设
- TLS 1.3 PSK 会话恢复、TLS 1.2 ticket/session ID、0-RTT
- ECH（RFC 9849），含 PSK、HelloRetryRequest、拒绝回退
- RFC 5280 证书路径验证、Public Suffix List 通配符、OCSP/CRL、SCT 回调
- `AsyncUConn`、`makefile()`/`fileno()` socket 兼容
- ClientHelloSpec JSON、`Fingerprinter`、JA3

## 文档

| 文档 | 内容 |
| --- | --- |
| [概述](docs/overview.md) | uTLS 是什么、设计目标、非目标 |
| [功能与支持范围](docs/features.md) | 当前实现、支持矩阵、未实现项 |
| [使用指南](docs/usage.md) | 预设、自定义 ClientHello、ECH、恢复、0-RTT、async、mTLS |
| [应用场景](docs/scenarios.md) | 指纹兼容性、浏览器模拟、ECH 研究、mTLS 等案例 |
| [模块地图](docs/modules.md) | `connection`、`hello`、`ech`、`verify` 等模块说明 |
| [uTLS 兼容性](docs/compatibility.md) | Go uTLS 对应关系、内置指纹列表 |
| [安全说明](docs/security.md) | 安全默认、证书验证、SSRF、已知限制 |
| [测试与开发](docs/testing.md) | 测试、CI、覆盖率、构建 |

## 边界

- 不实现 HTTP/2 或 QUIC：HTTP/2 交给 `h2`/`httpx`，QUIC 交给 `aioquic`
- 不实现服务端 TLS
- 不是代理、VPN 或反检测产品
- 尚未经过独立安全审计；生产使用前请自行评估

适合授权测试、协议研究、兼容性验证和需要精确 ClientHello 的客户端。请遵守法律和服务条款，不要用于未授权访问或绕过访问控制。

## 许可证

BSD-3-Clause，作者 Laoju &lt;hello@laoju.wang&gt;。详见 `LICENSE` / `NOTICE`。
