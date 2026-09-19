# Project Status

## 2026-09-19 最新发布状态：v2.12.0 源码发布与解耦指南

本段优先于下方历史快照。发布现有整改，以 `v2.12.0` Git 注释标签标识；遵守“不修改代码”，
平台自报仍为 2.11.0、探针源码声明仍为 3.5.0，本轮不重建镜像或探针包、不操作真实探针。
本机数据库只读核验为 `0015_alert_hits (head)`；健康检查 ok、测试导入关闭。
前端 typecheck 与 34 项单测通过；本轮隔离后端 579 passed / 17 failed，具体限制见
[发布记录](docs/releases/v2.12.0.md)。历史“未提交”“仅 6 项失败”保留为当时快照，不代表本轮核验口径。
解耦作为后续文档任务，本轮不移动函数、拆分模块或更改判定逻辑。


> 项目整体状态快照。长期稳定信息见 `AGENTS.md`，当前任务见 `TASK.md`，架构见 `docs/architecture.md`。
> 数据均为实测，采集时间：2026-09-17。

## 2026-09-19 业务逻辑与数据真实性整改（未提交）

按工作区 `业务逻辑与数据真实性整改清单.md` 的 29 项整改完成代码修改并重建镜像部署，未做历史数据重算，未提交。

- 判定口径：DNS 隧道/CVE/端口扫描/脚本上传/C2 心跳/数据引擎/文件类型共 8 处的误报与漏检判定收紧（详见 `TASK.md` 顶部）。
- 状态与关联：事件阶段只按规则 id 归类；`alert_hits` 记录被抑制的每次命中；扫描覆盖决定类别替换与实例退役；
  计数按受影响对象重算；数据资产与文件改用 `file_id` 关联；重新分析标记并清理上一轮派生结果；投影重建按快照恢复。
- 展示真实性：测试数据导入默认关闭（生产禁用并返回 403，`/health.features.test_data_import` 暴露状态）；
  敏感发现页与数据类型中心的总数改为服务端全表聚合/跨类型去重，未观测资产单独统计；
  分级覆盖 `sensitivity_levels` 统一作用于类型、对象、实例视图并给出 `level_source`。
- 数据库：新增迁移 `0015_alert_hits`（`alert_hits` 表 + `detections.sample_limit`），head 变为 `0015_alert_hits`；迁移幂等。
- 验证：后端全量仅剩 6 项既有环境失败；前端 typecheck 与 34 项单测通过。
- 部署：按 `AGENTS.md` 用 legacy builder 重建 backend/worker/beat/deployment-worker/frontend 镜像并重建容器，
  backend 启动时自动执行 `0014_probe_removal -> 0015_alert_hits`；`/health` 全绿（tshark/zeek/suricata 可用，
  `features.test_data_import=false`，探针在线）。
- 历史数据 dry-run（只读）：`scripts/remediation_dry_run.py`，报告 `整改dry-run报告-2026-09-19.txt`。
  与清单快照一致的问题：对象 #6 缓存计数与实际不符、14 个对象类别无当前检测支撑、旧投影 3 条列名被写成敏感类别。
  待执行的修复动作与规模已列出，尚未落库。
- 真实探针验证：探针 #2 `test123`（kali / 192.168.191.130，agent 3.4.1）在线，下发 3 次受限真实采集（`/etc`，row 预算）。
  文件检测按类别各自保留置信度、`hit_count == sample_hit_count`、`sample_limit` 已落库、证据不含原值；
  类型中心 3 类 / 12 对象 / 12 实例只来自真正命中的文件。
- 探针验证暴露并修复 3 处：(a) 目录条目只上报子项类目并集且 `counts={}`，服务端却为每个类目建了 `hit_count=0` 的伪检测，
  污染对象类型数与类型中心——现在只对上报了计数的类目建检测，探针侧目录证据新增 `aggregate: true`；
  (b) 目录/端口推断条目没有解析覆盖度，原先默认 `coverage="complete"`，Partial 采集里的目录也显示“已完整扫描”——
  现在回退到本次报告的覆盖率与终止原因（实测目录节点显示 `partial / row_budget`）；
  (c) 探针本地严重度映射滞后一步，`se_organisationsnummer` 上报 `Low` 而检测为 `Medium`，旧投影照抄上报值——
  现在投影取平台映射与上报值中更严格者（`Unknown` 保持原样），与重建路径一致（实测列表/详情同为 Medium）。
- 真实库数据修复：删除 5 条伪造零命中目录检测（无证据行）；按已记录的 Partial 报告 `e4099b01…`（`file_budget`）
  把 5 个目录实例的 `coverage` 由 `complete` 修正为 `partial`；把 1 行弱于对象模型的投影 `sensitivity` 修正为 `Medium`。
  文件类检测与证据未改动。

## 2026-09-18 v2.11.0 发布

平台版本 2.11.0（探针保持 3.5.0），发布标签 `v2.11.0`，数据库迁移仍为 `0014_probe_removal (head)`，升级无需迁移。
本版把「引擎规则库」与「PCAP 工作台」两块未提交改动纳入发布：规则文件真实加载与上游在线同步、
命中规则快照与告警规则解释、引擎总览页、抓包内传输文件提取与文本/Hex 预览、手动上传定位与包列表分页。
更新内容见 `CHANGELOG.md` 的 `v2.11.0` 段，版本策略见 `docs/versioning.md`。
发布前验证：前端 34 passed + `vue-tsc --noEmit` 通过；后端定向回归通过，全量后端 16 项失败与既有基线一致
（探针包缺失、Windows/Linux 行尾、容器内 Suricata 能力等环境相关）。本版未改动探针代码，探针包无需重建。
发布提交与 `v2.11.0` 标签已推送 `origin`（`develop` → `f85a024`）；推送前用 ruff 清零了本版新增文件的 lint
（26 处 E501、6 处可自动修复项、1 处 E731、1 处未使用导入），仅剩 2 处 2026-09-02 的历史 E501 按 `AGENTS.md`
惯例不动。运行中的容器仍是发布前镜像（`/openapi.json` 报 2.10.0），除版本号外已是本版代码；要显示 2.11.0
需按 `AGENTS.md` 用 legacy builder 重建 backend / frontend 并重建容器。

## 2026-09-18 09:10 PCAP 最新状态

手动重复上传现在直接打开已有记录；原问题已用 `2.pcapng -> duplicate=true, id=651` 复现。
上传进度、独立超时、任务跟踪、包列表分页/布局/IPv6、传输文件持久化及文本/Hex/下载已部署。
真实手动上传 #2112 / 任务 #2144 成功并提取 5 项内容，全部下载与预览字节验证一致；
既有 #651 / 任务 #2145 成功，284 包，第二页从 101 开始，单包字节和协议树正常。
最新测试：后端相关 49 passed、前端 34 passed，类型检查与构建通过；无浏览器截图验收。
新文件预览端点及原下载端点按抓包清单校验文件 ID，详见 `docs/architecture.md` 和 `TASK.md`。

## 2026-09-18 规则库状态

规则展示、在线同步、命中快照及原生执行修复已部署到本机全部应用容器，详见 `TASK.md` 顶部。
通过前端网关实测：15 个引擎均有规则，共 3,512 项资源；Suricata 实际加载 52,270 条签名。
历史告警 #1 / #5 可解释；真实 PCAP 重分析 #2080 成功，新 Finding #834 含规则快照。
规则中心已支持引擎筛选、搜索、分页和懒加载，不再使用旧类型页签混淆引擎。
在线源完成初次拉取；外部组件规则与实际接入状态分别标识，不能把下载当作目标机检测已完成。
测试：后端最新定向 33 passed / 1 deselected，前端 31 passed，类型检查及生产构建通过；
全量后端仍有既有 16 项失败，尚未逐项修复，不能笼统认定全部与代码无关。
本机 backend/worker 健康；无测试数据导入、无真实探针主机操作。工作区尚未提交。
下方原快照中的未部署、规则数、检测规则页签、全量测试仍在运行等描述已被本段覆盖。

## 当前版本（原快照）

> 2026-09-17 恢复会话实测更新：运行后端已包含内置规则解析，DLP 告警 #1 和端口扫描
> 告警 #5 均返回规则与命中条件；`/test/status` 为 `present=false`。工作区另有未部署的
> 规则目录、在线同步及引擎参数接入改动，超出下方原快照范围，详见 `TASK.md` 顶部恢复核验。
> 挂载当前工作区的全量 pytest 仍在运行，旧测试基线不能证明这些新增改动已通过。

| 项 | 值 | 来源 |
| --- | --- | --- |
| 平台 | 2.11.0 | `backend/app/main.py`（FastAPI version）、`frontend/package.json` |
| 探针 | 3.5.0 | `probe/probe.py:AGENT_VERSION`、`backend/app/core/config.py:probe_agent_version` |
| 数据库迁移 | `0014_probe_removal (head)`；工作区新增未提交的 `0015_alert_hits`（整改清单第 07/18 项） | `alembic current` |
| 分支 / 最新提交 | `develop` / `f85a024`（发布提交 + lint 清零，tag `v2.11.0`） | `git log --oneline` |
| 工作区 | 有未提交改动（业务逻辑与数据真实性整改，见上方 2026-09-19 段） | `git status` |
| 未推送提交 | 无：`develop` 与标签 `v2.11.0` 均已推送（`e815a54..f85a024`） | `git log origin/develop..HEAD --oneline` |
| 远端 | `origin` = `https://github.com/1376524890/data-security-toolbox.git` | `git remote -v` |

## 已实现模块

- 探针侧：流量分段采集（tshark/dumpcap）、资产盘点、数据资产清单（只上传身份/推断列/敏感类目计数）、
  文件内容分析（哈希 + 敏感数据检测）、中心规则集下载与原子替换、心跳、受控远程扫描、
  安装/卸载（`probe/install.sh`、`probe/uninstall.sh`）。
- 服务端检测层（`app/engine/`）：资产、合规、数据、协议、风险、流量六个引擎 + 统一 `DetectionPipeline`。
- 威胁情报：`app/threat_intel`（IOC 命中 `TI_IOC_001`、本地 CVE 关联 `CVE_*`）、
  情报源接入（Feodo / URLhaus / 自建 JSON-CSV，`app/services/intelligence_service.py`）、离线情报导入。
- 关联与告警：`app/incident_engine`（多 Finding 聚合成 Incident）、告警生成/抑制/投递（Webhook、SMTP）。
- 第三方适配：`app/integrations/`（Zeek、Suricata、Presidio、MISP、osquery/Wazuh、OpenSCAP、离线包管理）。
- 平台能力：任务调度（Celery + beat）、报告生成、探针下发与回收（SSH + 事件流水 + 审计）、
  数据目录/数据对象（`data_objects` / `asset_instances`）、规则库（146 条）、本地 CVE 库（394,371 条）、操作审计（部分）。
- 前端控制台：`dashboard`、`asset`、`data-security`、`network`、`operations`、`operations-admin`、
  `threat`、`engines`、`tools` 九个业务域。

## 未实现模块 / 功能缺口

- **全量操作审计**：`audit_logs` 目前只有 2 条写入路径（`api/data_catalog.py` 的 rebuild / backfill），
  其余写操作、列表页、导出均未记录。
- **`vulnerabilities` 表无写入方**：全仓只有 `asset_detail` 读取它，当前 0 行。
  CVE 命中实际以 Finding（`rule_id = CVE_*`）形式存在，不落该表。
- **情报源无定时同步**：`beat_schedule` 五项任务中不含 `intel_sync`，只能由前端手动触发。
- **前端无情报源数据资产页**：`/intelligence/providers` 已有 UI（威胁情报 → 情报源），但 IOC 库本身仍近乎为空（见下）。

## 已知 Bug

1. 后端存在 16 个**环境相关**失败用例：镜像不含 `tests/`、`pyproject.toml`、`probe_packages/` 时必然失败，
   与代码无关（见「测试状态」的口径说明）。
2. `protocol_engine` 的 `PROTO_DNS_TUNNEL_001` 证据只有域名与报文计数、不含主机地址，
   因此该事件仍归属 `global`（当前 55 条事件中 1 条）。要归属需在 DNS 解析层保留查询源地址。
3. `iocs` 表只有 1 条真实指标：Feodo 官方 recommended 列表当前真实内容就是 1 条（`# END 1 entries`）。
   资产 IOC 页签在未命中时为空属预期，非缺陷。

已修复（`0cf03de`，已部署验证）：资产详情「关联检测 / 关联事件」长期为空、事件退化成 `global`、
多主机事件只对一台主机可见、IOC 联动不读 `matched_iocs`、findings 去重签名对流量 findings 恒为空。

已修复（本轮，已部署验证）：

1. **幽灵引擎 `rules`**：`app/rules/interpreter.py::interpret_rules()` 曾硬编码 `engine="rules"`，
   而注册表里没有这个引擎。流量引擎（网络规则）与合规引擎（合规规则）的规则命中全部落到该名字下，
   导致安全引擎页面按引擎过滤恒为 0、检测中心「引擎」列显示不存在的值、66 条告警 `source='rules'`。
   现由调用方传入 `self.name`；历史数据（79 条 finding / 18 条事件内条目 / 66 条告警 `source`）已按真实
   归属纠正为 `traffic_engine`。
2. **引擎下拉硬编码**：`EngineDetail.vue` / `DetectionCenter.vue` / `SensitiveDiscovery.vue` 三处硬编码的
   引擎名与 `detection_findings.engine` 真实取值不一致，所有按引擎过滤都返回空。现统一读
   `GET /engine/registry`（新增 `slug` / `label` / `rule_count` / `detection_engine` / `detection_count`）。
3. **规则数显示为空**：`EngineDetail.vue` 曾用 `health[name].rule_count` 覆盖适配器上报的真实值，
   而 `/health` 只有 `tshark/zeek/suricata`，`Sigma/Wazuh/osquery/OpenSCAP` 因此渲染成 `-`；
   Sigma 页的「规则资源」读 `/offline/resources` 的 `sigma_rules`（库内不存在）故恒显示「暂无」。
   现规则数与规则清单统一来自规则库（`GET /rules?engine=`），并锁定「卡片规则数 == 清单条数」不变量。
4. **Suricata 规则数假 0**：`workers/tasks.py::_worker_capability()` 只统计离线目录，
   而 `run_suricata` 同时加载随包规则；实测 `/health.suricata.rule_count` 由 0 修正为 2（2 个 `sid:`）。

## 技术债务

- ruff E501 存量约 1,000+ 处（`line-length = 100`），只约束新增代码。
- 前端无 lint/format 配置，仅靠 `vue-tsc` + `vitest`。
- `frontend/src/mocks/`（假数据适配器）与生产代码同仓，仅靠 `VITE_DEMO_MODE` 构建期开关隔离。
- 控制台顶部仍保留「测试数据 → 导入/清除测试数据」入口（`frontend/src/App.vue`），
  与「只用真实数据」的交付要求冲突，待决策是否在生产构建隐藏。
- 本机 `docker compose build` 会被挂起的 buildx 客户端卡死，必须改用 legacy builder（见 `AGENTS.md`）。
- **66 条历史告警的 `fingerprint`/`correlation_key` 仍是 `rules` 派生值**：本轮只纠正了可见的 `source`。
  重算 fingerprint 会与 13:59 新产生的正确告警（`a64dc8ad…`）碰撞，合并 66 条历史实例超出「标签纠正」的范围。
  影响面：同一条件再次命中时新建告警实例而非抑制递增；新数据的 fingerprint 正确。
- **两个「规则数」口径并存**：注册表 `rule_count` = 规则**文件数**（与规则清单一致，suricata=1）；
  `/health.suricata.rule_count` = 实际加载的 **`sid:` 条数**（suricata=2）。两者都真实但单位不同，暂未统一。
- **「检测规则」页签按文件类型而非引擎分组**：`RulesCenter.vue` 的 `sigma`/`suricata`/`yara` 页签仍用
  `RuleItem.type`，而 `app/rules/network`、`app/rules/compliance` 下的 YAML 会被归到 `sigma` 页签。
  接口已提供真实 `engine` 字段（数据正确），页签改造待做；页面不为空，属标签精度问题。

## 当前架构

详见 `docs/architecture.md`。一句话概览：

```
探针（采集/上传/心跳） --HTTPS/X-Probe-*--> FastAPI（鉴权、入库、建任务）
                                              |
                                         Redis 队列
                                              |
                        Celery worker（15 个检测/适配引擎 -> RiskEngine -> Finding/Alert/Incident）
                                              |
                                        PostgreSQL + 文件存储
                                              |
                              FastAPI 查询 API --> Vue 控制台（nginx）--> 报告
```

## 数据库状态

实测行数（`psql` 直查 `security_toolbox`）：

| 表 | 行数 | 表 | 行数 |
| --- | --- | --- | --- |
| assets | 214 | asset_instances | 205 |
| data_assets | 447 | data_objects | 245 |
| detection_findings | 815 | incidents | 55 |
| alerts | 122 | pcaps | 1,745 |
| flows | 32,356 | tasks | 1,775 |
| reports | 2 | rules | 146 |
| local_cves | 394,371 | iocs | **1** |
| probes | 1 | audit_logs | 2 |
| vulnerabilities | **0** | graph_relations | 1,018 |
| detections | 5 | detection_evidence | 3 |

（本轮修复后重新采集：`detection_findings` **820**、`incidents` **56**、`alerts` **122**、
`engine='rules'` 已归零；引擎分布 `protocol_engine` 375、`threat_intel` 332、`traffic_engine` 98、
`dlp_engine` 14、`compliance_engine` 1、`rules` 0。表内其余数字为上一轮采集值。）

要点：

- 资产 214 条中有 200 条是 `192.168.191.168` 的 service 级资产（端口扫描真实产物），非脏数据。
- 数据资产 447 条全部属于探针主机 `192.168.191.130`（真实采集，`extra.host`）。
- 严重度分布：High 794 / Medium 1（无 Critical、Low）。
- 事件归属分布（修复后）：`192.168.191.168` 28、`192.168.191.1` 15、`192.168.110.168` 6、`127.0.0.1` 3、
  `139.199.215.251` 1、`1.12.12.12` 1、`global` 1（DNS 隧道，证据本身无主机）。
- `audit_logs` 现有 2 行，均为 `incidents.rebuild_attribution`（actor=admin），
  证明维护端点按设计写审计；覆盖面仍远小于「全量操作审计」。
- `detections` / `detection_evidence`（数据对象的敏感类目明细，由 `data_object_service` 写入）与
  `detection_findings`（引擎检测结果）是两套并存模型，当前行数 5 / 3 / 815，勿混淆。
- **确认库内无测试数据**：`GET /api/v1/test/status` → `present=false`。

## API 状态

- OpenAPI 实测：**140 个路径 / 154 个操作**，前缀 `/api/v1`（较上一轮 +1：`POST /incidents/rebuild-attribution`）。
- 路由按域拆分：`api/v1.py`（主体）、`extensions.py`、`data_catalog.py`、`deployments.py`、
  `libraries.py`、`profiles.py`、`rulesets.py`。
- 列表统一 `page` / `page_size` → `{items, total, page, page_size}`。
- 认证：控制台会话 Cookie / Bearer；探针 `X-Probe-ID` + `X-Probe-Token`。
- 全量 GET 冒烟：跳过下载/流式/导出端点后共 **89 个 GET**，77 个 200；
  其余 12 个为参数/鉴权语义导致的预期非 2xx（探针专用接口无 `X-Probe-*` 返回 401；
  合成 id=1 在 `asset_instances`/`scan_profiles`/`detections` 等表不存在返回 404；
  `crypto/probe-profile`、`probes/{id}/command-status` 缺必填查询参数返回 422）。

## 前端状态

- 构建期常量隔离 mock：`VITE_DEMO_MODE=true` 才会挂 `src/mocks/adapter.ts`（`api/client.ts`），生产构建不启用。
- 页面分包：9 个业务域模块；驾驶舱、资产中心、PCAP 工作台、协议分析、事件中心、告警中心、IOC 情报、情报源、规则库等。
- 近期修复：驾驶舱环形图（统一 `severityOrder` / `severityLabels` / `severityTagColors`）、
  协议分布只显示应用层、PCAP 告警证据改用命中规则的真实 evidence。
- 上一轮：安全引擎页/检测中心/敏感发现的引擎选项与过滤全部改读注册表；引擎页新增「规则清单」
  （可按引擎列出真实规则文件、展开看规则正文）。
- 本轮：安全引擎组菜单由 12 个逐引擎入口**收敛为单一「引擎总览」**（`/engines` 路由 +
  `modules/engines/EnginesOverview.vue`，一张表列出全部引擎的名称/类型/版本/状态/规则文件数/检测数/来源，
  行点击进 `/engines/<slug>`）；告警详情新增 `components/evidence/RuleMatchPanel.vue`
  （上半「命中规则」含命中条件、处置建议、规则来源与规则原文，下半「命中内容」按证据键渲染表格/标签并脱敏），
  取代 `AlertCenter.vue` 原先的「检测来源」描述块。
- 单测 31/31 通过，`vue-tsc --noEmit` 干净（本轮复跑）。

## 后端状态

- FastAPI（8000，容器 healthy）+ Celery worker + beat + 独立 `deployment-worker`（探针下发/回收）。
- 检测引擎 6 个 + 情报/适配/关联三套子系统；`evidence` 中的资产身份解析本轮统一到
  `evidence_asset_keys()` / `evidence_ioc_keys()`。
- 规则归属的**唯一来源**：`_rule_file_entries()` 同时服务 `GET /rules` 与 `/engine/registry` 的
  `rule_count`，两者的数字不可能再互相矛盾。
- 全量基线（固定口径，见「测试状态」）：HEAD `e815a54` 521 用例 / 16 环境失败；
  资产归属轮 525 用例 / 同样 16 个失败；本轮 **531 用例 / 同样 16 个失败**（失败集合逐条一致）。

## Docker 状态

运行中的服务（`docker compose -p source`）：`postgres`、`redis`、`backend`、`worker`、`beat`、
`deployment-worker`、`frontend`、`flower`。另有独立的 `openaev-*` 集成栈在跑（第三方靶场/系统，非本项目服务）。

端口：后端 8000，控制台 `${HTTP_PORT}`=8088。

构建注意：必须 `DOCKER_BUILDKIT=0` 走 legacy builder，否则永久卡住（见 `AGENTS.md`）。

## 测试状态

| 套件 | 命令 | 基线 |
| --- | --- | --- |
| 后端全量（固定口径） | 见下方 `docker run` 说明 | HEAD `e815a54` = 521 用例 / 16 失败；本轮 = **532 用例 / 16 失败，失败集合逐条一致（零回归）** |
| 前端单测 | `frontend/` 下 `npx vitest run`（本机 node 22.19 + 仓库 `node_modules`） | 31/31 通过 |
| 前端类型 | `frontend/` 下 `npx vue-tsc --noEmit` | 干净 |

**镜像不含 `tests/`、`pyproject.toml`、`probe_packages/`**，因此 `docker exec ... pytest` 无法直接跑用例。
固定口径（HEAD 与当前改动用完全相同的命令各跑一次，再逐条比对失败集合）：

```powershell
$src = (Resolve-Path ".\00-数据安全工具箱\source").Path
docker run --rm -v "${src}\backend\app:/app/app" -v "${src}\backend\tests:/app/tests" `
  -v "${src}\backend\pyproject.toml:/app/pyproject.toml" -v "${src}\probe:/app/probe" `
  -v "${src}\shared:/app/shared" -v "${src}\probe_packages:/app/probe_packages" `
  -w /app source-backend:latest python -m pytest -q
```

该口径下的 16 个失败全部由环境缺失/降级引起，与本次改动无关：

- `tests/deployment/test_package.py` 4 个（容器内 `probe_packages` 未构建出 manifest）
- `tests/shared/test_distribution.py` 10 个（安装脚本可执行位、分发清单等依赖完整仓库布局）
- `tests/test_api.py::test_health`（无 Redis 时为 `degraded`）
- `tests/test_gap_fixes.py::test_integrations_reports_worker_zeek_suricata_capability`（无 worker 能力上报）

## 最近的重要设计决定

1. **资产身份 = IP**。事件的 `evidence.asset` 由「ip:host:service:port 复合串」改为 IP，展示标签之外另存
   `evidence.assets`（事件覆盖的全部主机），使多主机事件能被每台相关资产查到。
2. **身份解析集中一处**：`evidence_asset_keys(evidence)` / `evidence_ioc_keys(evidence)` 供事件关联、
   findings 去重、维护端点共用，避免同一份 evidence 在不同模块解读出不同资产。
3. **维护端点只重算派生数据**：历史事件的错误归属通过重算 `asset`/`assets` 修复，
   不新增、不删除事件，不改 `fingerprint`，因此不会产生重复事件。
4. **协议分布只统计应用层**：`protocol_layer()` 区分 link/network/transport/application，前端图表过滤到应用层，
   原始计数器与逐包协议树保持原样（不损失取证信息）。
5. **探针卸载的删除白名单固定**：删除目标必须来自脚本内常量，不读命令行参数、不读目标机文件，
   符号链接只删链接本身，成功后才删平台记录。
6. **交付环境禁用任何演示数据**：`POST /api/v1/test/import` 与 `VITE_DEMO_MODE` 均不得用于生产/演示环境。
7. **身份与展示分离**：`_asset_identity()` 解析用于关联的身份（嵌套资产取 `ip`），`_short_asset()` 仍是展示标签
   （`ip:service:port` 复合串）。把展示串当身份用是本次缺陷的共同根因。
8. **多主机事件同时归属多台主机**：`evidence.asset` 只是展示用的首标签，`evidence.assets` 才是成员集合，
   查询侧一律按成员判定（LIKE 只做候选过滤，Python 侧精确判定，保证 SQLite 测试与 PostgreSQL 行为一致）。
9. **引擎名由后端定义**：控制台路由段（`/engines/sigma`）与落库引擎名（`sigma_log_engine`）历史上不一致，
   前端再各自硬编码一份名单，必然漂移。现由 `ENGINE_PRESENTATION` + `GET /engine/registry` 统一提供
   `slug` / `label` / `detection_engine`，前端不再持有任何引擎名单。
10. **规则库单一来源**：`_rule_file_entries()` 是规则文件与引擎归属的唯一枚举点，`/rules` 与注册表的
    规则数共用它；"规则数"必须等于该引擎的规则清单条数。
11. **告警必须能自我解释**：`AlertDetail` 追加 `rule` 字段，由 `_rule_definition()` 三层解析——
    规则库文件 → 代码内置规则（`app/rules/builtin.py`）→ 数据驱动规则（DLP 策略、本地 CVE 库）。
    「代码实现的规则没有规则文件」不再是显示空白的理由：定义就写在实现它的模块旁边，
    `source` 指向那个 `.py`，条件文本与代码里的阈值逐条对齐。
12. **导航按「谁在用」收敛，不按引擎数量展开**：引擎是平台的实现细节，逐引擎单列菜单会随引擎增长而膨胀，
    且与「引擎总览」重复。导航只留一个入口，引擎的差异化信息放到总览表格与详情页里。

## 兼容性变更记录

| 变更 | 影响面 | 说明 |
| --- | --- | --- |
| 事件 `evidence.asset` 语义改为 IP | 前端事件中心展示、事件搜索 | 展示更短更可读；`assets` 为新增字段，不影响旧字段解析 |
| 事件 `evidence.assets` 新增 | 新增字段 | 旧数据缺该字段，查询侧已做兼容（缺失即跳过） |
| `/api/v1/protocols` 增加 `layer` 字段 | 新增字段 | 旧消费者忽略即可；`tree` 排序改为按计数倒序 |
| `/api/v1/pcap/alerts` 的 alert 项 evidence 改为命中规则的 evidence | 修复错误数据 | 原先返回告警自身元数据（id/severity/时间），非规则证据 |
| 新增 `POST /api/v1/incidents/rebuild-attribution` | 新增端点 | 只重算已有事件的 `asset`/`assets`/`stages`/`title`，不增删事件、不改 `fingerprint`；写 `audit_logs` |
| `asset_detail` 的「关联检测」匹配范围扩大 | 同一资产可能返回比以前更多的 findings | 由「只看 `evidence.asset.ip`/`evidence.ip`」扩大到所有主机拼写，实测 192.168.191.130 由 0 变 99 |
| `/api/v1/engine/registry` 每项追加 `slug` / `label` / `rule_count` / `detection_engine` / `detection_count` | 新增字段，纯追加 | 旧消费者只读 `name`/`version` 不受影响；`detection_engine` 是该引擎真正落库的引擎名 |
| `/api/v1/alerts/{id}` 追加 `rule` 字段 | 新增字段，纯追加 | 值为命中规则的 `rule_id`/`engine`/`type`/`title`/`severity`/`condition`/`recommendation`/`file`/`content`/`detection`；规则库文件、代码内置规则、DLP 策略与本地 CVE 库四种来源统一成同一形状，解析不到时为 `null` |
| 控制台新增前端路由 `/engines` | 仅前端路由 | 「引擎总览」；`/engines/:name` 详情页与后端接口未变 |
| 安全引擎导航组由 12 项收敛为 1 项 | 仅前端导航 | 引擎入口不再逐个出现在侧边栏，全部经由 `/engines` 进入；原有 `/engines/<slug>` 链接仍可直接访问 |
| `/api/v1/rules` 每项追加 `engine`，并新增 `engine=` 查询参数 | 新增字段 + 新增可选参数 | 原有 `rule_type` 参数保留；返回项新增 1 个字段 |
| `/api/v1/rules` 的 `type` 取值分布 | 规则归类变化 | `app/rules/network`、`app/rules/compliance` 下的规则此前被标成 `sigma`（按扩展名猜的），现按**加载它的引擎**给出 `engine` 标签，`type` 仍保留扩展名语义 |
| 历史数据的引擎归属纠正 | `detection_findings.engine` 79 行、`incidents.findings.items[*].engine` 18 条、`alerts.source` 66 行 | 仅纠正错误归属，不新增/不删除记录，不改 `fingerprint`/`id` |
| `/engines/*` 页面的「检测」卡片由「本页条数」改为「真实总数」 | 前端显示 | 之前固定最多 20；现取 `total` |
| 安全引擎菜单新增 6 个平台引擎入口 | 前端导航 | 原菜单只指向 6 个第三方适配器，而检测结果来自平台引擎，导致那些引擎不可达 |

禁止修改项与硬约束见 `AGENTS.md`「禁止修改的内容」。
