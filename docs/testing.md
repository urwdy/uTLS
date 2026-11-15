# 测试与开发

## 运行测试

```bash
uv run python -m unittest discover -s tests -t .
# 或
python -m unittest discover -s tests -t .
```

## 覆盖率

```bash
uv run coverage run -m unittest discover -s tests -t .
uv run coverage report
```

`pyproject.toml` 已配置 `coverage` 的 source 与 branch 统计。

## 可选网络测试

```bash
UTLS_NETWORK_TESTS=1 uv run python -m unittest tests.test_network
```

网络测试包括：

- 与 `tls.peet.ws` 比对 JA3
- 真实 ECH 握手
- ECH + PSK 恢复
- ECH + HelloRetryRequest

网络测试依赖公网服务，可能因服务端配置或网络状态偶发失败。

## CI

`.github/workflows/ci.yml`：

- 触发：`push`、`pull_request`，以及手动 `workflow_dispatch`
- Python 3.10、3.11、3.12、3.13
- `uv sync --locked`
- 完整离线测试 + coverage report
- 上传 coverage XML
- 独立 build job：构建 sdist/wheel、校验 wheel 内容并上传 artifact
- 手动触发时可选择运行公网测试（`run_network_tests`）

## 构建

```bash
uv lock --check
uv build
```

wheel 会包含：

- `utls/py.typed`
- `utls/_public_suffix_list.dat`
- `utls/spec_json.py`
- `utls/ct.py`
- `utls/psl.py`

## 工具

- `tools/gen_legacy_presets.py`：生成 `utls/_legacy_presets.py`
- `tools/legacy_specs.json`：预设快照
- `tools/README.md`：工具说明
