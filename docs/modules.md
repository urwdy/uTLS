# 模块地图

| 模块 | 作用 |
| --- | --- |
| `utls.connection` | `UConn`、`Config`、握手、连接状态、会话、ECH 集成 |
| `utls.hello` | `ClientHelloSpec`、ClientHello 构造/解析 |
| `utls.extensions` | 所有 ClientHello 扩展类型 |
| `utls.presets` | 浏览器/客户端预设与别名解析 |
| `utls.ech` | ECH 配置、HPKE、inner/outer、HRR |
| `utls.verify` | 证书链、主机名、签名、CRL |
| `utls.ocsp` | OCSP 请求和响应验证 |
| `utls.ct` | SCT 列表解析 |
| `utls.crypto` | 记录层加密、HKDF/PRF、key share |
| `utls.mlkem` | 纯 Python ML-KEM-768 |
| `utls.session` | `SessionState`、`ClientSessionCache` |
| `utls.fingerprint` | JA3、ClientHello 解析、`Fingerprinter` |
| `utls.spec_json` | `ClientHelloSpec` JSON 序列化 |
| `utls.aio` | asyncio 适配 |
| `utls.stream` | `UConn.makefile()` 文件包装 |
| `utls.psl` | Public Suffix List 匹配 |
| `tools/` | legacy 预设生成器 |

## 调用层次

```text
用户代码
  |
  +-- UConn / AsyncUConn
        |
        +-- hello.ClientHelloSpec / extensions
        +-- presets
        +-- crypto / mlkem
        +-- record / stream
        +-- verify / ocsp / ct
        +-- ech
        +-- session
```

## 关键入口

```python
utls.connect(...)
utls.wrap_socket(...)
utls.UConn(sock, config, preset)
utls.AsyncUConn.connect(...)
utls.ClientHelloSpec(...)
utls.utls_id_to_spec(...)
utls.Fingerprinter()
utls.parse_ech_config_list(...)
utls.fetch_ech_config_list(...)
```

## 数据对象

- `ClientHelloSpec`：ClientHello 描述
- `ECHConfig` / `ECHConfigList`：ECH 配置
- `SessionState`：可恢复会话
- `ConnectionState`：握手结果、ALPN、ECH 状态、证书等

## 工具脚本

- `tools/gen_legacy_presets.py`：从 Go uTLS spec dump 生成 legacy 预设
- `tools/legacy_specs.json`：预设快照
