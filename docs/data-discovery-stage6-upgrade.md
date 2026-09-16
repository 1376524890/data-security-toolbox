# 阶段 6 实施记录：现有 Docker / Kali 保留数据原地升级

- 前置：`docs/data-discovery-3.3.1-baseline.md`（阶段 0）及阶段 1-5 记录。
- 本次发布：**平台 2.7.0 → 2.8.0**，**探针 3.3.1 → 3.4.0**；提交 `chore(release): v2.8.0 - platform 2.8.0, probe 3.4.0`，分支 `develop`。
- 部署凭据（SSH、探针 token、数据库口令、平台管理员口令）不写入本记录、代码或日志。所有需要凭据的步骤都在已授权会话内执行，任何摘要都不含 token 原文。
- 用户明确指示"不做完整端到端测试，跑通即推送并启动，由用户手动测试"。本记录如实标注哪些验证做了、哪些没做。

## 1. 阶段完成判定

| 阶段 6 要求 | 实测证据 |
|---|---|
| 备份并记录数据库、镜像、配置、探针身份摘要、pending 与恢复路径 | `source/.local/backups/stage6-20260916-142744/`（gitignored）：`security_toolbox.dump`（pg_dump -Fc）、`security_toolbox.sql.gz`、`containers.txt`、`db-inventory.txt`、`env.copy`、`tables-before.txt`、`probe-row.txt`、`probes-schema.txt`、`kali-probe.identity.json`、`kali-probe.toml`、`kali-before-state.txt` |
| 确定新版本、统一发布信息 | 平台 2.8.0 / 探针 3.4.0，一次性同步到 `backend/app/main.py`、`frontend/package.json` + `package-lock.json`、`probe/probe.py::AGENT_VERSION`、`backend/app/core/config.py::probe_agent_version`、`docker-compose.yml`（4 处）、`.env.example`、`probe_packages/build_packages.py`；`CHANGELOG.md` 新增 `## v2.8.0（探针 3.4.0）` |
| 构建真实 amd64/arm64 探针包并校验共享模块、依赖、manifest、SHA256 | `probe-3.4.0-amd64.tar.gz` `sha256=26a6544bb67f84984bd12e1f45aa2a4313ae45bd4ad9936ba780df141d842f73`；`probe-3.4.0-arm64.tar.gz` `sha256=d994d1ecf3174193f5544beaf94536b8478ab779117913a2567e3935e7798101`。解包复核：32 个成员、`__pycache__` 0 个、`shared/**` 25 个；`probe.py`/`data_assets.py`/`ruleset_client.py`/`scanner.py`/`install.sh`/`requirements.txt`/`shared/scanning/*`/`shared/sensitive_detection/*` 与仓库**逐字节一致**（mismatches: 0） |
| 在备份副本演练旧 head 升级 | 见第 4 节 |
| 升级本项目 Docker 服务，保持前端 8088、后端 8000 | 见第 6 节；`source-backend-1` 0.0.0.0:8000、`source-frontend-1` 0.0.0.0:8088→80 |
| 原地升级 Kali 探针，保留 probe_id/token、配置与 pending，不改成 root 服务 | 见第 7 节 |
| 验证实际运行的源码/镜像、版本、心跳、capabilities、规则/Profile 同步、采集上传与真实合成扫描 | 见第 8 节 |
| 规则热更新不重启、完整 Hash 聚合、部分指纹标签、XLSX 本地识别、页面展示、NetDLP 正常 | 见第 8.4 节；页面展示的完整证据在 `docs/data-discovery-stage5-pages.md` |
| 输出部署结果、测试证据、性能对比、回滚步骤、已知限制与 P1/P2 | 第 8、9、10 节 |

## 2. 版本决策

| 组件 | 旧 | 新 | 说明 |
|---|---|---|---|
| 平台 | 2.7.0 | **2.8.0** | 新增 RuleSet/ScanProfile/对象模型 API 与页面，属于次版本 |
| 探针 | 3.3.1 | **3.4.0** | 新增共享扫描层、RuleSet 客户端、`ScopeFilter`；协议兼容保持 |

内部引擎版本 **不跟随**平台版本：`engine_version` 仍是 `1.0.0`，`PARTIAL_VERSION` 仍是 `1.0.0`，规则包 schema 仍是 `1.0`。这是刻意的——不要把引擎版本号混成平台版本。

版本号在阶段 6 一次性提升；阶段 1-5 的代码改动都并入这一个提交，避免中间态版本号出现在现场。

## 3. 升级前备份

```
source/.local/backups/stage6-20260916-142744/
  security_toolbox.dump        pg_dump -Fc 自定义格式（恢复用）
  security_toolbox.sql.gz      纯 SQL 明文（人工核对用）
  containers.txt               旧容器 → 镜像 ID 映射（用于回退到旧镜像）
  db-inventory.txt             关键表行数基线
  env.copy                     升级前的 .env
  tables-before.txt            升级前的表清单（31 张）
  probe-row.txt / probes-schema.txt   探针行与表结构摘要（不含 token 原文）
  kali-probe.identity.json     Kali 上的探针身份文件
  kali-probe.toml              Kali 上的探针配置
  kali-before-state.txt        systemd 单元、spool 计数、规则/身份文件摘要
```

`db-inventory.txt` 基线（升级前）：

```
probes=1  tasks=475  pcaps=467  packets=20358  flows=7485
data_assets=5  files=0  assets=11  probe_deployments=1  reports=0
```

## 4. 迁移演练

在备份副本上先把旧 head 升到新 head，确认旧数据兼容、无破坏性语句，然后才动现场库。演练库 `dst_rehearse6` 仍留在 `source-postgres-1` 里（见第 10 节）。

新增迁移全部是**纯增量**：

| 迁移 | 内容 | 破坏性语句 |
|---|---|---|
| `0010_rule_sets` | `rule_sets`、`rule_set_versions` | 无（只有 CREATE） |
| `0011_scan_profiles` | `scan_profiles` | 无 |
| `0012_asset_objects` | `data_objects`、`asset_instances`、`detections`、`detection_evidence` + 索引，外键用后置 `ALTER TABLE` | 无（无 DROP/TRUNCATE/改列） |

`0012` 带 `_has_table()` 守卫，因此"空库直升 head"与"库停在 0011"走同一条安全分支；外键在 SQLite 方言上用 `_supports_add_constraint()` 跳过，保证单测可跑。

## 5. 现场数据库原地升级

现场库从 `0009_probe_data_assets` 升到 head：

```
alembic_version = 0012_asset_objects
```

零数据丢失。升级前后关键行数对比（**不是**"初始化后为空"的说法）：

| 表 | 升级前 | 现状（15:57 实测） | 说明 |
|---|---|---|---|
| `probes` | 1 | 1 | 探针身份未变 |
| `probe_deployments` | 1 | 1 | 未变 |
| `assets` | 11 | 11 | 未变 |
| `tasks` | 475 | 630 | 增长来自验收任务与常规 NetDLP 任务 |
| `pcaps` | 467 | 611 | 增长来自 NetDLP 持续抓包 |
| `packets` | 20358 | 46074 | 同上 |
| `flows` | 7485 | 10335 | 同上 |
| `data_assets` | 5 | 37 | 增长来自验收扫描（旧投影仍在服务） |
| `files` | 0 | 0 | 未变 |
| `reports` | 0 | 0 | 未变 |
| `alerts` | – | 33 | NetDLP 检测累积 |

**增量全部来自持续采集与验收扫描，没有任何身份行被重建。**

## 6. Docker 服务升级

| 容器 | 镜像 | 端口 | 状态 |
|---|---|---|---|
| `source-backend-1` | `source-backend` | 8000 | Up (healthy) |
| `source-frontend-1` | `source-frontend` | **8088 → 80** | Up |
| `source-worker-1` | `source-worker` | – | Up (healthy) |
| `source-beat-1` | `source-beat` | – | Up |
| `source-deployment-worker-1` | `source-deployment-worker` | – | Up |
| `source-postgres-1` | `postgres:16.6-alpine` | 5432 | Up (healthy) |
| `source-redis-1` | `redis:7.4-alpine` | 6379 | Up (healthy) |
| `source-flower-1` | `mher/flower:2.0.1` | 5555 | Up |

镜像构建时间：`source-backend` 15:35:51、`source-worker`/`beat`/`deployment-worker` 15:36:39、`source-frontend` 15:01:13。

**"镜像里到底是不是最新代码"单独验证过，没有只看 `package.json`：**

- `backend/app`、`shared`、`probe` 下所有 `.py` 的最新 mtime 是 15:34:16，早于后端镜像构建时间 15:35:51；
- `frontend/src` 下没有文件晚于前端镜像构建时间 15:01:13；
- 后端镜像内实测 `app/main.py` 的 `version="2.8.0"`；
- 未执行 `docker compose down -v`，未清库，未重建卷。

主机上的其他项目（`openaev-*` 等）未受影响。

## 7. Kali 探针原地升级

探针主机 `192.168.191.130`（`kali`），systemd 服务 `data-security-toolbox-probe`：

| 项目 | 升级前（备份记录） | 现状 |
|---|---|---|
| `AGENT_VERSION` | 3.3.1 | **3.4.0** |
| 运行用户 | `dstprobe` | **`dstprobe`（未改成 root）** |
| 单元加固 | `NoNewPrivileges=true`、`ProtectSystem=strict`、`ProtectHome=true` | 不变；`ReadWritePaths` 覆盖 `spool`/`rules`/`cache`/`etc` |
| `probe.identity.json` | 2026-09-15 21:45:45 | **未改动**，`probe_id=1`、`token_len=43`、`server=http://192.168.191.1:8000` |
| `probe.toml` | 2026-09-15 21:44:36 | **未改动** |
| spool | 8.4M | 200M / 1231 个条目（NetDLP 持续抓包，未清空） |
| Python 环境 | – | 3.13.12；`regex==2026.9.10`、`openpyxl==3.1.5` 已装（新增 parser 依赖） |
| 服务启动时间 | – | `2026-09-16 03:34:58 EDT`（= 15:34:58 本地），升级后至今未重启 |

升级方式是原地替换 `/opt/data-security-toolbox/probe/` 下的代码并按需补依赖，**没有**清空 identity、没有重新注册、没有清 spool。`probe_id` 与 token 完全保留，平台侧探针行仍是同一条（`id=1`，`token_hash` 未变）。

## 8. 升级后验证

### 8.1 平台

- `GET /api/v1/health` 返回 `{"status":"ok","database":"ok","redis":"ok","celery":{"broker":"ok","worker":…}}`（`/health` 需鉴权，返回 401）；
- 后端镜像内 `version="2.8.0"`；
- 全部页面 HTTP 200：`/`、`/data-types`、`/scan-profiles`、`/data-asset-jobs`、`/data-types/id_card`。

### 8.2 API 冒烟

`/probes`、`/rulesets`、`/scan-profiles`、`/data-types`、`/data-objects`、`/asset-instances`、`/sensitivity-levels`、`/data/assets` 全部返回真实数据。

### 8.3 探针心跳与能力协商

平台侧探针行的 `metadata`：

```
agent_version = "3.4.0"
capabilities  = {"ruleset_hot_update": true, "ruleset_source": "server",
                 "current_ruleset_version": "e2e-hot-2", "engine_version": "1.0.0",
                 "regex_backend": "regex", "regex_timeout": true, "rule_count": 147,
                 "data_asset_scan": true, "ruleset_download": true}
```

`status=online`，`last_seen` 持续更新。**版本号是从真实心跳里读出来的，不是从常量里抄的。**

### 8.4 功能回归（真实探针）

| 项 | 结果 |
|---|---|
| 规则热更新不重启 | 探针 `rules/state.json`：`version=e2e-hot-2`、`source=server`、`updated_count=1`；服务 `ActiveEnterTimestamp` 全程未变 |
| 完整 Hash 聚合 | `full_sha256` 对象 23 个；相同完整文件归一个 `DataObject`、多个 `AssetInstance` |
| 部分指纹标签 | 64 MiB 大文件 → `object_key=partial:1.0.0:…`、`identity_kind=candidate`、`identity_confidence=0.5`、`content_hash` 为空 |
| XLSX 本地识别 | 证据含 `sheet_name=客户信息/订单信息`、`field_name=身份证号/手机号/姓名/地址`，报告无原值 |
| 增量缓存 | 无变化重扫 `cache.hits=10, misses=0, bytes_read=0` |
| 页面展示 | 见 `docs/data-discovery-stage5-pages.md` 第 4 节（15/15 只读复核） |
| NetDLP 正常 | `pcaps/packets/flows` 在升级后持续增长（467→611 / 20358→46074 / 7485→10335），抓包与上传未中断 |

## 9. 回滚步骤

按"先回代码/镜像/规则，保留兼容新增表"的顺序：

1. **前端/后端/worker**：用备份的 `containers.txt` 里记录的旧镜像 ID 重新起容器（或 `git checkout` 旧提交后重建）。旧镜像 ID 见该文件。
2. **数据库**：`0010`-`0012` 都是纯增量表，**不需要**执行 downgrade 就能让 2.7.0 的代码跑起来（旧代码不看新表）。只有在需要彻底还原时才用 `pg_restore` 从 `security_toolbox.dump` 恢复——这一步会丢弃升级后的新增数据，属于最后手段。
3. **规则集**：`POST /api/v1/rulesets/{id}/rollback {"to_version": "<旧版本>"}`。注意回滚是**派生新版本**（`<旧版本>.rollback`），规则内容逐条一致但 `sha256` 会变。
4. **Kali 探针**：重新安装 3.3.1 包。`install.sh` 会保留 `probe.identity.json`、`probe.toml` 与 spool，不需要重新注册。
5. 全程禁止 `docker compose down -v`、禁止清空探针 spool/identity、禁止通过重新注册掩盖升级失败。

## 10. 已知限制与遗留物

- **`arm64` 未做实机验证**：只做了内容与 SHA256 校验。不能宣称 arm64 实机通过。
- **`dst_rehearse6` 演练库仍在**：这是阶段 6 的迁移演练库，可以删除（`DROP DATABASE dst_rehearse6;`）。故意保留到用户确认。
- **Kali `/tmp` 里还留着上传的包和解包目录**：无害，可清理。
- **探针 spool 已涨到 200M**：这是 NetDLP 持续抓包的正常累积，不是升级问题；轮转由 `probe.toml` 的 `retention_seconds` 控制。
- **规则集 active 当前是 `builtin-1.rollback`**：这是阶段 5 验收回滚的结果，内容与 `builtin-1` 逐条一致。探针会在下一次规则轮询（≤900 秒）收敛到同一版本。
- **完整 E2E 未执行**：用户明确豁免。已执行部分见阶段 5 记录第 3 节，未执行部分见其第 7 节。

## 11. P1/P2 规划边界

- **P1（未接入，页面已留位）**：风险评分与 RiskEngine、网络来源证明、关系图谱、业务系统归属。四个数据资产页面在这些位置渲染"尚未接入（P1）"，不伪造连线。
- **P2**：跨探针的全局去重与容量趋势、规则市场/订阅、按数据类型的自动分级策略下发。
- P0 的扩展模型（`GraphRelation`、`RiskScore` 等边界）已在阶段 0/4 记录中说明，本次不宣称 P0 不完整。

## 12. 实测命令与结果

| 项目 | 命令 | 结果 |
|---|---|---|
| 探针包构建 | `.venv\\Scripts\\python.exe probe_packages\\build_packages.py` | 生成 amd64/arm64 包，SHA256 见第 1 节 |
| 探针包复核 | 解包后逐文件比对仓库 | 32 成员 / 0 `__pycache__` / 25 shared / mismatches 0 |
| 迁移头 | `select version_num from alembic_version;` | `0012_asset_objects` |
| 行数核对 | `db-inventory.txt` 对比现场 | 见第 5 节 |
| 服务与端口 | `docker ps` | 8000 / 8088 保持 |
| 探针状态 | `systemctl show data-security-toolbox-probe -p User,ActiveEnterTimestamp --value` | `dstprobe` / 03:34:58 EDT |
| 平台版本 | 容器内 `grep 'version=' /app/app/main.py` | `version="2.8.0"` |
