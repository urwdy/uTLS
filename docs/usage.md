# 使用指南

## 1. 快速开始

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

按 `Content-Length` 读取更稳妥；连接被异常截断时会抛出 `utls.RecordError`。

## 2. 使用预设

```python
conn = utls.connect("example.com", 443, preset=utls.HelloFirefox_148)
```

也可以使用字符串：

```python
conn = utls.connect("example.com", 443, preset="chrome")
conn = utls.connect("example.com", 443, preset="chrome_133")
```

预设列表见 [uTLS 兼容性](compatibility.md)。

## 3. 自定义 ClientHello

```python
from utls.extensions import *

spec = utls.ClientHelloSpec(
    tls_vers_min=utls.constants.VERSION_TLS12,
    tls_vers_max=utls.constants.VERSION_TLS13,
    cipher_suites=[0x1301, 0x1302, 0x1303, 0xC02F],
    extensions=[
        SNIExtension(),
        SupportedGroupsExtension([utls.constants.GROUP_X25519]),
        SupportedPointsExtension(b"\x00"),
        ALPNExtension(["h2", "http/1.1"]),
        KeyShareExtension([KeyShareEntry(utls.constants.GROUP_X25519)]),
        SupportedVersionsExtension([
            utls.constants.VERSION_TLS13,
            utls.constants.VERSION_TLS12,
        ]),
        PaddingExtension(padding_len_func=boring_padding_style),
    ],
)
conn = utls.connect("example.com", 443, client_hello=spec)
```

## 4. 保存、恢复和解析指纹

```python
spec = utls.utls_id_to_spec(utls.HelloChrome_133)
text = spec.to_json(indent=2)

restored = utls.ClientHelloSpec.from_json(text)
conn = utls.connect("example.com", 443, client_hello=restored)
```

从抓包 ClientHello 还原：

```python
fp = utls.Fingerprinter()
spec = fp.FingerprintClientHello(raw_client_hello)
```

PSK 扩展包含密钥材料，禁止通过 JSON 序列化。

## 5. 会话恢复

```python
conn = utls.connect("example.com", 443, preset=utls.HelloChrome_Auto)
# 读取应用数据以接收 NewSessionTicket
...
session = conn.session
conn.close()

conn2 = utls.connect(
    "example.com",
    443,
    config=utls.Config(server_name="example.com", session=session),
    preset=utls.HelloChrome_Auto,
)
print(conn2.connection_state().did_resume)
```

使用缓存：

```python
cache = utls.ClientSessionCache()
config = utls.Config(server_name="example.com", session_cache=cache)
```

## 6. 0-RTT

```python
conn = utls.connect(
    "example.com",
    443,
    config=utls.Config(
        server_name="example.com",
        session=session,
        early_data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ),
    preset=utls.HelloChrome_Auto,
)
print(conn.connection_state().early_data_accepted)
```

0-RTT 有重放风险，只对幂等请求启用。

## 7. ECH

```python
ech = utls.fetch_ech_config_list("crypto.cloudflare.com")
conn = utls.connect(
    "crypto.cloudflare.com",
    443,
    preset=utls.HelloChrome_120,
    ech_config_list=ech,
)
print(conn.connection_state().ech_accepted)
```

直接传配置：

```python
config_list = utls.parse_ech_config_list(base64_text)
conn = utls.connect("example.com", 443, ech_config_list=config_list)
```

ECH 细节：

- 自动通过 Cloudflare DoH 获取 `ech=` HTTPS 记录
- 也接受 `ECHConfigList`、`ECHConfig`、bytes、base64
- 服务器拒绝时抛 `ECHRejectedError`，其中 `retry_configs` 可用于重试
- ECH 被拒绝后可检查 `ConnectionState.ech_accepted` / `ech_public_name`

## 8. 调试与自定义校验

```python
def keylog(line: str) -> None:
    print(line, end="")

def verify(chain, name: str) -> None:
    if name != "example.com":
        raise ValueError("unexpected server identity")

config = utls.Config(
    server_name="example.com",
    keylog_writer=keylog,
    verify_peer_certificate=verify,
)
```

握手完成后校验：

```python
def on_connection(conn):
    state = conn.connection_state()
    if state.alpn_protocol not in ("h2", "http/1.1"):
        raise RuntimeError("unexpected ALPN")

config = utls.Config(
    server_name="example.com",
    verify_connection=on_connection,
)
```

SCT：

```python
def check_sct(cert, scts):
    if not scts:
        raise ValueError("no SCT")

config = utls.Config(
    server_name="example.com",
    sct_verifier=check_sct,
)
```

## 9. 客户端证书回调

```python
def select_client_cert(acceptable_cas, signature_algorithms):
    # 根据 CA、签名算法、外部状态选择证书。
    return [cert_pem_bytes], private_key_pem_bytes

config = utls.Config(
    server_name="example.com",
    get_client_certificate=select_client_cert,
)
conn = utls.connect("example.com", 443, config=config, preset=utls.HelloChrome_120)
```

回调返回 `None` 表示不提供证书。

## 10. async

```python
import asyncio
import utls

async def main():
    conn = await utls.AsyncUConn.connect(
        "example.com",
        443,
        preset=utls.HelloChrome_120,
        alpn=["http/1.1"],
    )
    try:
        await conn.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = b""
        while chunk := await conn.recv():
            data += chunk
    finally:
        await conn.close()

asyncio.run(main())
```

`AsyncUConn` 用线程池包装同步 `UConn`；取消阻塞中的读写不会立即中断底层系统调用。

## 11. socket 兼容

```python
conn = utls.connect(...)
stream = conn.makefile("rb")
conn.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
status = stream.readline()
body = stream.read()
```

`UConn` 还提供 `fileno()`、`recv_into()`、`gettimeout()`、`settimeout()`、`getsockopt()` 等方法。

## 12. Go 风格配置

```python
config = utls.Config.from_go(
    ServerName="example.com",
    MinVersion=utls.constants.VERSION_TLS12,
    MaxVersion=utls.constants.VERSION_TLS13,
    RootCAs=[ca_der],
)
```

也可以构造后设置属性别名：

```python
config = utls.Config()
config.ServerName = "example.com"
config.RootCAs = [ca_der]
config.VerifyPeerCertificate = verify
```

参见：

- [应用场景](scenarios.md)
- [安全说明](security.md)
- [uTLS 兼容性](compatibility.md)
