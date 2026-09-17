# Changelog

## v2.10.0（探针 3.5.0）

- **探针卸载（远程回收主机）**：此前只能删除平台记录，主机上的服务、systemd 单元与生产文件必须人工清理，
  文档与前端提示都明确写着「不会卸载远程服务」。现在平台可以完整回收探针：通过 SSH 上传并执行
  `probe/uninstall.sh`，停止服务、删除 systemd 单元，并删除 `/opt/data-security-toolbox`（运行时代码与虚拟环境）、
  `/etc/data-security-toolbox`（`probe.toml`、`probe.token`、`ca.pem`）、`/var/lib/data-security-toolbox`
  （采集分段、规则与扫描缓存）以及安装器自带的 dumpcap/tcpdump 副本，**成功后才删除平台记录**。
  卸载复用下发的同一条 SSH 通道、同一套凭据加密、事件日志与状态机（`probe_deployments.action='uninstall'`），
  因此控制台有实时进度和完整的删除清单。
- **干净的删除语义**：卸载脚本以 root 运行且幂等，删除目标只来自固定白名单——不读命令行参数、不读目标机上的文件
  （以 root 从可变文件读取删除目标等于提权原语）。符号链接只删链接本身、不跟随；删除前先
  `stop`/`disable`/`reset-failed` 并清理仍在运行的探针进程，避免它在删除过程中继续写回 spool。
  `dstprobe` 系统账号只在安装器留下的 `.created-user` 标记证明由本探针创建时（或 `--remove-user`）才删除，
  否则默认保留共用账号。标记在删除任何文件之前一次性读出——实测发现，若在删除应用目录后再读，真实删除路径下
  该账号会被错误地保留（`--dry-run` 反而正常），此问题已修复并有回归测试覆盖。
- **可审计的结果**：脚本以一行 `DST_UNINSTALL {...}` 结束，返回已删除 / 本就不存在 / 按选项保留 / 未能删除的
  路径、释放空间与退出码；平台解析后写入 `result`，控制台在卸载详情里展示。有残留时为
  `REMOVAL_PARTIAL` 并逐条列出残留项；没有汇总行时为 `REMOVAL_FAILED`（bash 中止、sudo 拒绝或连接中断，
  主机状态未知，平台不做任何断言）。失败后重新发起一次卸载即可重试，脚本幂等。卸载成功时平台立即作废该探针
  的 token（`token`/`token_hash` 清空、状态置 `offline`），因为文件已经不在主机上。
- **一键删除 = 先卸载再删记录**：`DELETE /api/v1/probes/{probe_id}` 支持可选请求体 `remove_remote`，
  即「探针管理 → 删除」的默认行为：先清理主机，成功后再由 worker 删除平台记录；失败则保留记录
  （记录里存着仍需清理的主机地址）。不带请求体保持原语义，只删除记录。
- **安装失败的主机也能回收**：卸载只依赖一条 SSH 连接和一个 shell，不依赖目标机上存在任何探针文件，
  因此预检不通过、安装中断、等待注册超时（卡在 90%）的主机都能直接回收——这类主机上通常已经留下一个
  正在运行的服务，正是最需要清理的对象。
- **卸载记录与接口**：`ProbeDeployment` 新增 `action` 与 `removal_options`（迁移 `0014_probe_removal`，
  幂等且有 downgrade），部署页用「动作」列区分安装/卸载并展示清理结果与清理选项；新增
  `POST /api/v1/probe-deployments/removal` 与 `DELETE /api/v1/probe-deployments/{id}`（历史记录清理，
  永不动主机）。卸载凭据仅用于本次任务，任务结束（含失败）后立即销毁。
- **探针包**：包内新增 `uninstall.sh`；`install.sh` 写入 `.created-user` / `.installed-capture-tool` 标记，
  并把卸载脚本复制到 `/opt/data-security-toolbox/uninstall.sh`，离线主机可直接
  `sudo bash /opt/data-security-toolbox/uninstall.sh`。`uninstall.sh` 一并纳入 CRLF 与可执行位校验。
- **部署事件序号修复**：`ProbeDeploymentEvent.seq` 原先按已加载集合的长度计算，而会话是
  `expire_on_commit=False` 且不自动 flush，集合一旦被缓存就不再增长，同一行的每条事件会拿到同一个序号
  （实测一条卸载记录为 `1 REMOVING` / `1 REMOVED`，历史安装记录为 `1,1,1,1` 这类序列）。控制台用
  `seq > after` 增量拉取进度，重复序号会让进度停在那里不再前进。现在序号取自该行已持久化的最大 `seq` + 1，
  安装（下发）与卸载（回收）两条路径都有唯一递增序号的回归测试。
- **版本**：平台升至 2.10.0，探针升至 3.5.0；探针包 `probe_packages/probe-3.5.0`（amd64 / arm64）已重建并校验
  SHA256，amd64 `960857d304d06fc356dacd40e2918eb04f57a1471ea29ec8908c3e1ebae60f95`、
  arm64 `866830c0a7a6283fe974a5577e98e67c4aa1498d59bd80ce42caa28852dfc398`。数据库迁移新增
  `0014_probe_removal`，升级需执行 `alembic upgrade head`（镜像启动时自动执行）。使用说明、路径清单与
  卸载选项见 `docs/probe-removal.md`，运维步骤见 `docs/部署与运行手册.md` 5.6。

## v2.9.0（探针 3.4.1）

- **探针目录采集权限**：任务在 `/home/kali`、`/root` 等管理员下发目录报 Permission denied。探针 systemd 单元
  把 `ProtectHome` 由 `true` 改为 `read-only`，并新增仅用于读取与目录遍历的 `CAP_DAC_READ_SEARCH`；
  探针仍以 `dstprobe` 运行，保持只读系统保护与不跟随符号链接的范围限制。单个目录不可读不再中断其余目录。
  该权限允许探针读取普通账户原本无权读取的文件，可采集范围仍由管理员下发的采集目录决定。
- **探针重新入网**：`install.sh` 为升级需要会保留 `probe.identity.json`，而探针原先「本地已有身份就不再注册」，
  导致平台新部署下发的一次性入网令牌永远不会被消费——删除探针后重新添加会一直停在 90%
  `service started; awaiting registration`，直到 5 分钟回调超时判 `CALLBACK_TIMEOUT`；探针进程健康，
  但心跳用已注销的 `probe_id` 收到 401（心跳 401 被静默吞掉）。现在平台推送的
  `bootstrap_token + deployment_id` 优先于旧身份，探针会重新入网并替换身份；令牌已消费或失效且本地仍有身份时
  退回本地身份，而不是退出让 systemd 反复重启。实机（Kali 192.168.191.130）确认重启后 1 秒内完成换号，部署转为 ONLINE。
- **探针服务未重启**：平台用 `--install-only` 装完包就直接 `systemctl start`，而重试/升级时探针服务本来就在运行，
  `systemctl start` 对已运行的 unit 是空操作，新代码与新配置从未生效（磁盘上是新版，`MainPID` 仍是 3 小时前的老进程，
  日志继续刷 401）。改用 `systemctl restart`，并在 `tests/deployment/test_registration_flow.py` 断言不再出现 `systemctl start`。
- **探针包 CRLF**：`install.sh`、systemd 单元与 `offline/load-images.sh` 在本机 Windows 检出
  （`core.autocrlf=true`）下带 CRLF，远端 bash 在第 2 行即失败：`set: pipefail : invalid option name`。
  新增 `.gitattributes` 强制 `*.sh`/`*.service` 为 LF；探针包构建统一以 LF 写出文本成员并补齐可执行位
  （Windows 无 POSIX 权限位，此前包内 `install.sh` 是 0666）；部署侧解包后仍会兜底清理 CR 并校验，因此旧包也仍可安装。

- **网络扫描**：平台与探针默认端口由 1000 降为 200，平台对指定网段逐地址执行扫描，
  避免存活预探测漏掉仅开放其他端口的主机（此前这类主机会被 `0 hosts up` 直接跳过）；
  页面去除底层工具名称，继续提供显式端口与执行探针选择。修复网段展开在超大网段下的内存与耗时问题。
- **检测规则**：新增 Suricata 明文私钥传输基线（`backend/app/integrations/suricata/rules/dst_sensitive.rules`）
  与 YARA 私钥/云凭据基线（`backend/app/rules/data/sensitive_files.yar`），基线同时进入规则列表和实际检测；
  YARA 改为按 UTF-8 内容编译，修复 Windows 中文规则路径读取失败。
- **网络 DLP 原始证据**：命中敏感传输时保存原始二进制，新增
  `GET /dlp/transfers/{task_id}/{object_id}/content` 返回 SHA256、哈希范围、前 4096 字节的十六进制预览，
  并支持完整捕获字节下载；片段哈希不再标为完整文件哈希，原始字节单独落盘，列表与告警仍只携带元数据。
  历史 PCAP 需重新分析才产生字节证据。

- **资产详情 500**：运行日志显示 PostgreSQL 在提取 JSON 证据字段时拒绝 `\u0000`。写入层把 NUL 表示为可见的
  `\x00`，迁移 `0013_safe_json_evidence` 修复历史 JSON，保留记录及原本的字面转义字符串。修复后
  `/api/v1/assets/11` 与 `/api/v1/data/assets/242` 均返回 200。
- **CVE 与前端**：`GET /offline/cves` 支持 `page` / `page_size` 服务端分页并返回总数，不传 `page` 时保持旧的数组响应；
  前端改为服务端分页、中文分页控件、CVE 中文描述优先、搜索可重置；PCAP 告警证据改为独立弹窗，统一 SVG 图标尺寸。
- **`.env.example`**：补充 `DEPLOYMENT_BACKEND_URL` 的用途、地址格式与示例——必须是探针可访问的
  协议 + IP/域名 + 端口，不要填容器名、`localhost` 或 `/api/v1` 后缀；只有自签证书才需要 CA 文件。
- **版本**：平台升至 2.9.0，探针升至 3.4.1；探针包 `probe_packages/probe-3.4.1`（amd64 / arm64）已重建并校验 SHA256，
  amd64 `6684b46616124a0cc643c1b8abc613469d8cfae81a8979c2fb3f660ec4e56677`、
  arm64 `293b7a35e3e71bd0b603c99a018b25695a92e1ab8455013420f52863a2a9f32e`。数据库迁移新增
  `0013_safe_json_evidence`，升级需执行 `alembic upgrade head`。已安装探针升级到 3.4.1 后才会拿到入网与采集权限修复。
- 缺陷现象、实机验证过程与安装步骤见 `docs/bugfix-2026-09-16.md`；探针部署卡在 90% 的排查步骤见
  `docs/部署与运行手册.md` 的 Q7。

## v2.8.0（探针 3.4.0）

- **统一敏感数据引擎**：`shared/sensitive_detection` 成为平台与探针唯一的检测实现，文件引擎、
  网络 DLP 文本阶段和探针侧采集对同一取值给出一致的类目、级别与置信度；报告清洗
  （`report_guard`）同时约束两条上报通道，只输出规则、识别器、字段与计数。
- **共享扫描预算与采样**：`shared/scanning` 提供 ScanBudget、分段指纹、Magic 探测、增量缓存
  与 XLSX/CSV/TSV/JSONL/SQL 解析；XLSX 在探针本地解析，证据带工作表与列信息。
- **中央 RuleSet 与热更新**：新增规则集与不可变发布版本（迁移 `0010_rule_sets`），探针按
  manifest 比对后拉取整包，规则更新不需要重启探针，且一个任务只使用一个规则版本快照。
- **ScanProfile 与增量扫描**：新增版本化扫描配置（迁移 `0011_scan_profiles`），任务下发时
  固化配置快照；文件、引擎与规则版本未变化时复用缓存结果，不重复读取内容。
  `exclude_paths`（支持绝对子树与裸目录名）和 `file_types` 白名单现由探针实际执行，
  并在 `coverage.scope_filter` 中回报过滤计数。
- **对象/实例/检测模型**：新增 `data_objects` / `asset_instances` / `detections` /
  `detection_evidence`（迁移 `0012_asset_objects`），数据类型中心、对象详情、实例详情与
  证据查询接口（`/data-types`、`/data-objects`、`/asset-instances`、`/detections/{id}/evidence`）；
  完整 Hash 才能声明"确认副本"，部分指纹只作为带标记的"疑似副本"候选，作用域内身份单独标注。
- **采集进度与生命周期**：探针按聚合计数上报进度，进度永远不会改变任务状态；完整作用域才
  允许把未见到的实例置为 `NOT_OBSERVED`，取消、Partial、失败与迟到报告都不会回滚当前视图。
- 新增前端页面：数据类型中心、数据类型详情、数据对象详情、资产实例详情、扫描配置、
  采集任务；旧「数据资产」页面与路由保留。
- 修复端到端验收发现的三个缺陷：
  1. 探针计算了分段指纹却从未上报摘要值，导致大文件永远只能退化为作用域内身份，
     "疑似副本"路径实际上是死代码；现按 `Fingerprint.as_evidence()` 上报摘要与布局，
     并只接受十六进制摘要，避免脱敏占位符变成对象主键。
  2. 会话关闭了 `autoflush`，`recount_object` 统计不到同一事务中刚被清扫的实例，
     对象在改名/删除后会继续虚报活跃副本数；现于重算前刷新。
  3. 数据资产任务拒绝旧探针时提示的最小版本写死为 3.3.1，改为读取配置中的当前探针版本。
- **版本**：平台升至 2.8.0，探针升至 3.4.0；探针包含 `shared/scanning` 与
  `shared/sensitive_detection`，新增 `regex`、`openpyxl` 依赖（缺失时降级能力并如实上报，
  不阻止探针启动）。探针包 `probe_packages/probe-3.4.0`（amd64 / arm64）已重建并校验 SHA256。
- 已安装探针需升级到 3.4.0 才能使用共享引擎、规则热更新与本地 XLSX 识别；
  升级使用 `install.sh` 原地替换，保留 `probe.identity.json`（probe_id/token）、`probe.toml`
  与 spool 中待上传报告。

## v2.7.0（探针 3.3.1）

- 修复「网络防泄密」把 Docker / 容器主机的全部明文 TCP 出站流量判为告警：规则新增置信度，
  IP / MAC / 日期等定位符与低精度上游模式只作为传输证据；只有「敏感实体 + 置信度 ≥ 告警阈值（默认 0.6）」
  的命中才产生告警，finding 置信度按命中规则精度取值，不再是固定 High。
  回环 / 链路本地 / 组播流量不计为数据外发（`exclude_cidrs` 可扩展），非文本载荷不再按明文扫描，
  并修正 Presidio 宽松邮箱模式把数据库连接串 `user@host` 判为邮箱的问题；详见 `docs/dlp-detection-quality.md`。
- 新增探针任务停止、任务记录删除、领取与执行超时处理，停止后忽略迟到结果。
- 探针数据资产改用完整路径识别，按扫描范围更新状态，改进 TSV/JSONL/压缩 SQL 采样及读取限制。
- 修复定时采集覆盖待上传报告，新增探针协作停止检查；详见 `docs/probe-task-lifecycle.md`。
- **版本**：平台升至 2.7.0，探针升至 3.3.1；探针包 `probe_packages/probe-3.3.1`（amd64 / arm64）已随本次
  变更重建，无需数据库迁移。

## v2.6.0（feature/network-scan-and-probe-data-assets）

- 修复「资产中心 · 网络扫描」扫不到资产：容器/加固主机上 ICMP+ARP 探测被拦截时 `nmap -sn` 会判定
  `0 hosts up` 并跳过端口扫描。现统一使用 `-Pn -sT`，并新增零依赖的 TCP-connect 扫描引擎兜底
  （无需 root/NET_RAW/nmap，nmap 缺失、被拒或返回空时自动接管），扫描不再受运行环境影响。
- 扫描能力补全：存活发现改为 TCP-connect（`nmap` 仅在 TCP 扫描无结果时作补充）、支持显式端口列表、
  多主机并发（默认 4）、每主机 `--host-timeout` 上限（避免单台过滤主机拖住整个网段扫描）、
  非标准端口被动 banner 识别、HTTP/TLS 指纹。
- 新增网络路径自检：若扫描路径存在透明代理/NAT 拦截（保留地址 192.0.2.1 等被应答），扫描结果会带上
  明确告警，提示改用探针扫描，避免产出不可信资产。
- 「资产中心」扫描面板支持选择扫描来源（平台 / 探针）：指定探针时下发有界的探针侧扫描任务，
  结果经 `POST /probes/{id}/inventory` 回传；扫描进度、引擎、存活主机与服务资产数量均在页面展示。
- 探针数据资产采集：新增探针侧 `[data]` 采集（目录遍历、文件身份、字段推断、敏感类目统计、
  本机数据库服务登记），**仅上传文件名/字段/类目计数，不上传原始数据**；支持定时采集与平台下发任务
  （`POST /probes/{id}/data-assets/jobs`、探针 `POST /probes/{id}/data-assets`，幂等）。
- 「数据资产」页新增「从探针采集数据资产」入口，可按探针筛选，并展示来源探针、主机、路径、
  敏感类目、状态与字段明细。
- 探针部署新增数据资产采集配置（目录/周期/文件上限/深度/数据库服务），生成的 `probe.toml` 增加
  `[scan] allow_remote` 与 `[data]` 段；新增迁移 `0009_probe_data_assets`（`probe_deployments.data_config`）。
- 新增测试：扫描引擎（区间展开、端口选择、TCP 探测、兜底、拦截自检）、探针数据资产采集、
  探针上报入库与任务下发/鉴权、探针部署数据资产配置持久化与 `probe.toml` 生成。
- **版本**：平台升至 2.6.0，探针升至 3.3.0；探针部署包 `probe-3.3.0`（amd64 / arm64）已重建并附
  SHA256 清单，打包清单与 `install.sh` 补齐 `data_assets.py`（缺失会导致探针启动即 ImportError）。
- 已安装探针需升级到 3.3.0 才能使用探针侧扫描与数据资产采集；升级步骤见
  `docs/network-scan-and-probe-data-assets.md`。
- 修复探针部署包目录接口 `GET /probe-deployments/packages`：`list_packages()` 之前对每个历史版本都返回
  当前版本的 SHA256（`find_package` 只按配置版本取包），现按目录版本分别校验并返回各自摘要。

## v2.5.0（feature/v2.2-probe-intel-dlp）

- 探针采集支持所有网卡：Linux 默认 `capture.interface = "any"`，注册/心跳上报各网卡 IPv4/IPv6 及启用状态；部署表单可填写平台任一可达网卡作为回连地址。
- 网络防泄密规则库：展示内置/Presidio/手工规则并可逐条启停；从官方 PyPI 下载并校验 SHA256 导入 Presidio 静态正则（不含 NLP/上下文评分/Python 校验器）；支持手工添加名称、敏感类别与正则，历史 PCAP 可重新分析。
- CVE 漏洞库：支持下载/更新官方 Grype DB v6 与离线导入（`.tar.zst`/`.tar.gz`/tar/SQLite）；在线校验 SHA256、检查 schema、流式分批写入并事务回滚；按 CVE 去重、计算 CVSS 2/3/4 分数，保留手工记录；大库后台导入并显示进度。
- 检查规则中心：支持添加/导入 Suricata 与 YARA 规则；Suricata 校验行、SID 完整性及冲突（运行时可用时执行 `suricata -T`）；YARA 经 yara-python 编译、禁用 include。
- 修复与适配：前端代理上传限制提升至 2 GB（解压 12 GB）以支持 Grype 大文件；探针版本升至 3.2.1，提供 amd64 / arm64 部署包与 SHA256 清单。

## v2.4.0（feature/v2.2-probe-intel-dlp）

- 探针侧资产扫描改为受限、无特权的 TCP connect 扫描：必须显式配置目标，限制主机、端口、并发和总时长；支持管理员下发任务、断线暂存和幂等回传资产清单。
- 新增威胁情报源管理：本地 JSON/CSV 导入导出、IOC 启停、Feodo Tracker、URLhaus 和自建情报源同步；同步任务限流并限制下载体积与记录数。
- 新增旁路网络 DLP：有界 TCP 重组、明文 HTTP/表单/文件对象提取、敏感字段/关键词/SHA256 指纹检测、脱敏证据及覆盖范围说明。
- 修复 `dpkt` 后备解析器将 IPv4 地址以二进制写入 JSON 证据的问题，并兼容 SQLite 无时区时间值的健康检查。
- 更新探针示例、Compose 情报源变量，并新增探针扫描、IOC 规范化和 DLP 脱敏测试。

## v2.3.2（feature/nuclei-integration）

- 修复 PCAP 解析 bug：`dns.resp.len` 等 tshark 字段返回逗号列表时 `int()` 抛
  `invalid literal for int()`；新增 `_first_num` 助手解析首个数值，覆盖
  tcp_streams / app_analysis 相关字段
- 修复 nuclei 扫描入库 bug：`_run_correlations_and_alerts` 返回 `(Alert,bool)`，
  误当 `(alert_id,bool)` 传给 publish_alert；改为 `alert.id`
- 测试数据导入幂等：按 probe+sha256/segment_id 跳过已存在记录，避免
  `uq_pcap_probe_segment` 唯一约束报错
- 新增 test_nuclei / test_protocol(_first_num) 用例；crypto 测试探针名改为唯一


## v2.3.1（feature/nuclei-integration）

- 扫描自动化集成到探针：
  - 探针新增 `[scan]` 配置（enabled / interval_seconds / targets / discovery / top_ports / nuclei / nuclei_tags）
  - 探针 `scan_loop` 定时调用 `POST /api/v1/probes/{id}/scan`（探针鉴权），自动触发 nmap+nuclei 网络环境扫描；
    targets 为空时自动按探针自身 IP 推导 /24
  - 新增 `POST /api/v1/probes/{id}/scan`（探针鉴权）与 `ProbeScanRequest` schema；
    `_is_probe_api` 白名单放行 `/probes/{id}/scan`
  - `probe.toml.example` 补充 `[scan]` 说明


## v2.3.0（feature/nuclei-integration）

- 新增 Nuclei 主动漏洞扫描集成：
  - `nuclei_service`：运行 `nuclei -u <target> -t <templates> -jsonl`，解析结果并归一化为发现
  - `/api/v1/scan` 支持 `nuclei`、`nuclei_tags`、`nuclei_templates` 参数；扫描任务对 nmap 发现的
    HTTP/HTTPS 服务 URL 逐个跑 nuclei，结果进入 detection/alert/incident 流水线（引擎 `nuclei_engine`）
  - 前端「资产中心」扫描面板新增 Nuclei 开关与 tags 输入
  - worker 镜像安装 nuclei 二进制（Dockerfile 下载 + 本地部署时 COPY）
  - 新增 test_nuclei 单测


## v2.2.3

- 新增「测试数据」管理：`POST /api/v1/test/import`（导入手工测试包，标注为 test-demo 探针）、`POST /api/v1/test/clear`（清除测试数据）、`GET /api/v1/test/status`
- 前端头部新增「测试数据」下拉：导入/清除测试数据；导入后设置 sessionStorage，**刷新页面自动清除、恢复原样**
- docker-compose 为 backend 挂载 `data_security_toolbox_manual_testpack`（只读）


## v2.2.2

- 密码评估工具新增「从探针自动识别并填充」：新增 `GET /api/v1/crypto/probe-profile`，聚合探针采集的服务 banner、TLS 握手（cipher suite/JA3/SNI）与无认证信号，自动填充密码算法/套件/协议/密钥长度后评估
  - TLS 十六进制套件 ID 解码为 IANA 名称，识别 CBC/RSA/3DES 等弱套件与 TLSv1.2/1.3 协议
  - 识别服务级密码/认证类型（SSH 主机密钥、MySQL/Redis 认证、TLS）与无认证/匿名访问风险，并入评估发现（GB/T 39786）
  - 画像对算法/套件/协议/密钥长度/密钥管理标注 detected/inferred/default，诚实反映覆盖度



## v2.2.1

- 落实 `docs/gap-analysis.md` 本机可完善项（P0/P1 + Zeek 默认组件）：
  - 新增「安全审计」前端页面（`/audit`，菜单「安全审计」），调用 `/audit/summary`、`/audit/logs`
  - 安全事件中心新增「手工关联」入口（调用 `POST /incidents/correlate`）
  - 检测中心新增「手动流水线」入口（调用 `POST /engine/pipeline`）
  - `/integrations` 读取 worker capability，修复 Zeek/Suricata 在 API 容器视角误报 unavailable；Dockerfile 将 Zeek/Suricata 纳入 API 镜像默认组件
  - 后端 `FileRecord` 持久化 md5（模型/序列化/上传/元数据任务 + alembic 0007 迁移）
  - 修复探针心跳 metadata 互相覆盖：`heartbeat`/`register` 改为深度合并
  - 修复网络文件恢复下载 404：`IntegrationAdapterEngine` 将瞬态工作区提取文件持久化到 `storage/network_files`

## v2.2

- 新增《数据安全工具箱作业指导书》（`docs/数据安全工具箱作业指导书.docx` + `.md`）：按 SIP-Logger 模板结构（封面/修订页/目的/适用范围/职责/安装部署/配置指南/运维管理/升级管理/附录 API）编写，覆盖全部功能点
- 重写 `docs/user-guide.md`：由 6 行精简版扩充为完整使用教程（系统概览、当前服务状态、访问与登录、四条核心使用路径、管理台导航、关键 API 速查、报告、离线部署、常见问题与边界）
- 更新 `CHANGELOG.md`：记录本次文档变更

## v1.0

- 数据资产识别
- 元数据分析
- 算法评估
- PCAP 协议与流量分析
- 安全审计
- 任务系统
- 报告系统
- Docker Compose 部署
- Probe Agent
- Vue 3 管理控制台

## v2.0

- 统一 DetectionEngine 插件化架构
- DetectionContext / DetectionResult / EngineRegistry / Pipeline
- 规则驱动网络检测（YAML）
- TCP 流重组、TLS/DNS/HTTP 深度分析
- C2 Beacon、端口扫描、高包速率检测
- PII/密钥/YARA/Presidio 数据安全检测
- 统一风险评分模型
- 合规检查与威胁情报引擎
- Sigma 风格日志检测
- 数据资产地图与资产关系图
- 专业安全报告（资产、风险排行、敏感数据、检测结果、整改建议）
- Engine 单元测试、PCAP 集成测试、Benchmark

## v2.1

- Incident 真实时间窗口聚类与多 Incident 生成
- Offline Resource Manager：IOC/CVE/Suricata/Sigma/模型真实导入、去重、版本与 manifest
- Integration 完整健康状态与能力元数据
- 统一分页、筛选与关联查询
- Dashboard 风险趋势、Severity、Engine、敏感数据分布
- PCAP Workbench：Overview/Flows/Packets/Protocols/DNS/HTTP/TLS/Files/Alerts
- 管理控制台信息架构、公共组件与设计系统
- 敏感样本统一脱敏
