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
- `Open Develop PR`：推送到 `develop` 后自动创建 `develop -> main` PR
- `Auto Merge`：为 `develop -> main` PR 启用 GitHub auto-merge；检查通过后由 bot 合并

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

## Git 分支模型

项目采用 git-flow，并限制 `main` 只能通过 PR 合并：

- `main`：稳定发布分支，受分支保护
- `develop`：日常集成分支，所有改动只提交到这里
- `feature/*`：功能分支，从 `develop` 切出
- `release/*`：发布准备分支
- `hotfix/*`：紧急修复分支，从 `main` 切出

`main` 的保护规则要求以下检查通过：

- `Test (Python 3.10)`
- `Test (Python 3.11)`
- `Test (Python 3.12)`
- `Test (Python 3.13)`
- `Build sdist and wheel`

发布流程：

```bash
git checkout develop
# 更新版本号、CHANGELOG、测试
git commit -am "chore(release): vX.Y.Z"
git push origin develop
```

然后在 GitHub 创建 `develop -> main` PR。  
`.github/workflows/auto-merge.yml` 会为 PR 启用 GitHub auto-merge；CI 和 build 全部通过后，由 GitHub Actions Bot 自动合并到 `main`。

合并后可创建 annotated tag：

```bash
git checkout main
git pull --ff-only
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

不要直接向 `main` 推送提交。


## 工具

- `tools/gen_legacy_presets.py`：生成 `utls/_legacy_presets.py`
- `tools/legacy_specs.json`：预设快照
- `tools/README.md`：工具说明
