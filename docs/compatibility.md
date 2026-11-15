# 与 Go uTLS 的对应关系

## API 映射

| uTLS (Go) | uTLS (Python) |
| --- | --- |
| `tls.UClient(conn, cfg, id)` | `utls.UConn(sock, Config(...), hello_id)` / `utls.connect(...)` |
| `uconn.Handshake()` | `conn.handshake()` / `conn.Handshake()` |
| `uconn.BuildHandshakeState()` | `conn.build_handshake_state()` |
| `uconn.ApplyPreset(spec)` | `conn.apply_preset(spec)` |
| `uconn.ConnectionState()` | `conn.connection_state()` |
| `ClientHelloID` | `utls.ClientHelloID(client, version)` |
| `ClientHelloSpec` + `TLSExtension` | `utls.ClientHelloSpec` + `utls.extensions.*` |
| `UTLSIdToSpec(id)` | `utls.utls_id_to_spec(id)` |
| `uconn.HandshakeState.Hello.Raw` | `conn.get_client_hello()` |
| `Config.VerifyPeerCertificate` | `Config.verify_peer_certificate` / `VerifyPeerCertificate` |
| `Config.GetClientCertificate` | `Config.get_client_certificate` / `GetClientCertificate` |
| `Config.KeyLogWriter` | `Config.keylog_writer` / `KeyLogWriter` |
| `Config.VerifyConnection` | `Config.verify_connection` / `VerifyConnection` |
| `Config.EncryptedClientHelloConfigList` | `Config.ech_config_list` / `EncryptedClientHelloConfigList` |

`Config.from_go(ServerName=..., MinVersion=..., RootCAs=...)` 接受常见 Go 字段名。

## 内置指纹

| 预设 | 说明 |
| --- | --- |
| `HelloChrome_120` | Chrome 120，GREASE、ECH-GREASE、ALPS(old)、padding |
| `HelloChrome_131` / `HelloChrome_133` | Chrome 131/133，`X25519MLKEM768`、ALPS(new) |
| `HelloChrome_155` / `HelloChrome_Auto` | Chrome 155，ML-DSA 签名算法、trust_anchors、ML-KEM |
| `HelloFirefox_120` / `HelloFirefox_148` / `HelloFirefox_Auto` | Firefox；148 含 ML-KEM 与 hybrid key share 复用 |
| `HelloSafari_16_0` / `HelloSafari_26_3` / `HelloSafari_Auto` | Safari；26.3 含 ML-KEM |
| `HelloIOS_14` / `HelloIOS_Auto` | iOS 14 |
| `HelloIOS_11_1` / `HelloIOS_12_1` / `HelloIOS_13` | iOS 11.1 / 12.1 / 13 |
| `HelloAndroid_11_OkHttp` | Android 11 OkHttp（TLS 1.2） |
| `HelloEdge_106` / `HelloEdge_Auto` / `HelloEdge_85` | Edge 106 / 85 |
| `HelloChrome_58` / `70` / `72` / `83` / `87` / `96` / `100` / `102` / `106` | 历史 Chrome 指纹 |
| `HelloFirefox_55` / `63` / `99` / `102` / `105` | 历史 Firefox 指纹 |
| `Hello360_7_5` / `Hello360_11_0` / `Hello360_Auto` | 360 浏览器 |
| `HelloQQ_11_1` / `HelloQQ_Auto` | QQ 浏览器 |
| `HelloGolang` | 接近 Go `crypto/tls` 的常规指纹 |
| `HelloRandomized*` | 随机组合的合法指纹 |

`Hello*_Auto` 指向当前支持的最新版本。未包含 Kyber768/ML-KEM-1024 的 `HelloChrome_115_PQ`、`HelloChrome_120_PQ` 以及 PSK 变体。

## 预设别名

```python
utls.connect("example.com", 443, preset="chrome")
utls.connect("example.com", 443, preset="chrome_133")
utls.connect("example.com", 443, preset="firefox")
utls.connect("example.com", 443, preset="safari")
```

`utls.resolve_client_hello_id("chrome-133")` 可以显式解析名称。
