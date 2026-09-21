# 资产与数据安全增强：Agent 执行任务书

日期：2026-09-20。交付类型：实施任务书；本文中的功能尚未实施。

## 执行指令与授权范围

请直接完成下述代码、测试、分发包和运行说明，不停留在方案讨论。先顺序阅读 source 下 AGENTS.md、TASK.md、PROJECT_STATUS.md、docs/architecture.md，再执行 git status、git log --oneline -10，核对最新代码。相对路径均以 source 为根。

用户本次要求：优化资产与数据安全业务及显示逻辑；增加目标数据库直连盘点与数据规则匹配；修复指定目录采不到资产，使用 Linux root 身份进行采集。root 指操作系统执行身份，不代表扫描根目录 /，也不代表数据库必须使用 root 账号。本次功能工作取代旧任务“只做结构移动、行为不变”的范围限制；既有架构边界继续遵守。

真实联调仅针对用户指定目标和目录。优先读取当前采集任务中的目标及配置；文档里的 test123 / 192.168.191.130 是历史记录，不能据此猜测当前目标。缺少目标、目录或凭据时先完成独立开发与隔离验证，最后一次性列出真实联调所需信息；不可宣称真实验收完成。不要打印 .env、SSH 密码或数据库凭据。

禁止调用 POST /api/v1/test/import，禁止生产 VITE_DEMO_MODE，禁止写入目标业务数据、扩大卸载白名单、回改已发布迁移或回滚用户修改。测试样例只存在隔离测试环境，不能进入交付环境。

## 已核实基线与定位

任务书核对时 HEAD=a51bffe，工作树干净，平台 v2.13.0，探针 3.5.0，迁移 0015_alert_hits；执行时重新核对。

- probe/data-security-toolbox-probe.service 和 probe/install.sh 生成的单元均为 User=dstprobe，同时已有 CAP_DAC_READ_SEARCH；不能把失败直接归结为缺少 root。
- 单元使用 ProtectSystem=strict、ProtectHome=read-only、PrivateTmp=true。PrivateTmp 可能影响 /tmp 可见性，需结合真实失败目录验证。
- probe/data_assets.py::detect_local_databases 只识别端口；include_databases 并不等于读取数据库内容。
- 文件扫描在 probe/data_assets.py，遍历 _walk；检查 scope 过滤、SKIP_DIRECTORIES、符号链接跳过、预算、缓存、errors 与 complete。
- 采集路由 api/data_collection.py，协议 api/data_collection_schemas.py，建任务 services/probe_task_service.py；上述后端路径均位于 backend/app。
- 数据对象实现位于 backend/app/services/data_objects/，旧 data_object_service.py 仅为兼容门面。
- 前端资产中心 useAssetCenter.ts，数据安全 useDataAssetList.ts / useDataAssetCollection.ts / useDataAssetJobs.ts 等 composable；具体清单见 docs/数据资产开发入口.md。

## P0：指定目录 root 采集闭环

1. 沿“页面路径输入 → profile 覆盖 → Task 配置快照 → 探针领取 → 遍历 → 上报 → 入库投影 → 列表过滤”复现并记录故障节点。检查实际在线版本、allow_remote、effective UID、能力和 systemd 生效配置，不能只检查源码。
2. 按用户要求将采集运行身份改为 root，同步静态 service、install.sh 的生成单元、升级流程、README 和分发包。保留只读文件系统保护与固定可写目录；验证 root 配合 CapabilityBoundingSet 后的实际可读能力。采集 /tmp 时必须处理 PrivateTmp 带来的宿主目录隔离。不要使用 chmod -R 777、全盘 chown 或任意 shell 拼接解决问题。
3. root 执行的代码、配置和加载资源应由 root 持有且不可被普通用户改写，检查升级残留所有权。保留受控命令白名单，拒绝参数注入、路径越界和符号链接逃逸；不新增通用远程 shell。
4. 指定绝对目录优先于 profile 默认目录，显式排除规则仍生效；展示最终生效路径、过滤规则、文件类型、深度与预算。重叠目录去重。缓存命中仍应产生可见盘点结果。
5. 无权限、目录不存在、全部过滤、预算耗尽、上报失败分别报告；提供遍历目录数、发现文件数、过滤数、读取失败数、入库数及有上限的错误明细。空目录可成功，但必须明确“完成，发现 0”；失败不能变成成功空列表。
6. 部分/失败/取消扫描不退役未访问资产；重复和迟到上报不能覆盖新结果或复活取消任务。完整扫描的退役限于本次实际覆盖范围。
7. 提供幂等 root 升级/回退脚本及明确调用示例；脚本先检查目标服务、旧配置与文件归属，备份单元，重启后验证 UID=0、心跳与实际指定目录。使用 scripts/build_probe_packages.py 的现有流程更新版本/校验和，不能只改源码不发包。

P0 验收：隔离 Linux 下 root 私有目录、普通目录、中文/空格路径、空目录、不存在目录、排除目录、/tmp、重复扫描、取消/超时都有断言；授权真实目录做一次采集，记录任务 ID、实际 UID、采集数及页面结果。没有真实条件时明确标记待验收。

## P1：资产与数据安全业务、显示逻辑

1. 先写出当前问题和修复后的行为映射，逐项复现。区分主机、服务、文件对象、物理实例、数据库实例、表/字段与敏感发现，不能把不同粒度累加为同一个资产总数。
2. API 明确每个统计的单位与范围；顶部总数用服务端全量去重汇总，不能对分页求和。采样行数、匹配值数、命中字段数、对象数分别展示；无数据为 0，未知/未扫描为“未扫描/未知”。
3. 资产中心可追溯所属主机与来源；数据安全入口支持按来源、任务、主机、数据库、敏感类别及等级筛选并跳转详情。敏感发现展示规则 ID/版本、匹配位置、时间、脱敏证据和覆盖范围。
4. 任务页统一展示 Pending/Running/Success/Partial/Failed/Cancelled 的业务语义、当前阶段、进度和错误原因。采集完成自动刷新结果；切换筛选重置分页，过期请求不得覆盖新请求，卸载清理轮询，失败刷新保留上次成功数据并显示错误。
5. 不将业务判定塞回 Vue 模板；API 仍经 frontend/src/api，状态留在 composable；后端复用 data_objects 的身份、投影、覆盖与查询边界。

P1 验收：相同筛选下统计/列表/详情口径一致；重复采集不膨胀；部分扫描不误删；未命中不等于未采集；从任务可定位对应资产和发现；前端回归覆盖竞态、失败、分页和终态刷新。

## P2：目标数据库直连、盘点及内容规则匹配

首期交付 MySQL 与 PostgreSQL 两种实际驱动，不做只有选项的占位支持。其他数据库留适配器扩展点。默认由服务端 worker 连接用户配置的数据库地址；连通性测试必须在同一执行网络完成。平台无法到达目标时报告明确原因，不能把后端 localhost 当目标主机；探针代理/SSH 隧道不作为首期隐含功能。

1. 新增连接管理：名称、引擎、host、port、database、用户名、密码、TLS 配置；支持创建、修改、删除、测试连接、选择 schema/表、启动采集、查看历史。管理员鉴权、操作审计、字段校验；仅支持明确的驱动，不接受任意 SQL 或任意连接参数执行代码。
2. 凭据加密存储，密钥与数据库分离；可参考 deployment/credential.py 的 AES-GCM 模式，但数据库凭据需独立生命周期/AAD，不直接套 SSH 临时凭据 TTL。API 不回传密码；任务和队列只传连接 ID/版本引用，不存明文密码/DSN；异常和日志脱敏。
3. 数据库只读权限与只读事务，限定连接/语句/任务超时，限制连接并发、表数、行数、字节数。只读读取元数据与样本，不执行 DDL/DML、锁表、写临时业务表或无界 COUNT(*)；TLS 按用户配置验证证书。
4. 用适配器统一 test_connection、discover、read_batches、close；使用 SQLAlchemy Inspector 或官方驱动读取库/schema/表/列/类型/主键/注释。用户选定范围才读取数据，系统 schema 默认排除；标识符通过方言引用，参数化值。
5. 有主键时分批按稳定键读取；无主键表使用有界读取并明确覆盖限制，不宣称跨批快照一致。默认有界采样并在 UI 标明“采样检测”；全量模式仍受硬预算限制，超过预算为 Partial。空表仍保留元数据资产。
6. 对实际读取的单元格执行现有 DLP/敏感规则，复用共享检测与规则版本管理，不以表名/字段名猜测代替内容检测。字段名推断与内容命中分开标识。记录规则快照/版本、schema/表/列、实际扫描行数/值数、命中次数和脱敏证据；不持久化整表、原始敏感值或原始敏感主键。
7. 设计来源感知的稳定身份：连接/数据库实例、database、schema、table、column；与文件实例的 (probe_id, path) 身份隔离，不伪造 probe_id 或文件路径，不按内容哈希合并两张业务表。优先扩展现有对象/实例/发现链路，无法复用时写清适配边界和兼容策略。
8. 增加数据库连接与任务所需模型及新 Alembic 迁移，不修改 0015 及之前迁移。任务纳入 task_service/task_dispatch 与现有 worker 注册边界，支持取消、互斥、幂等、重试、进度、断连与权限错误；删除连接与正在运行任务的行为必须定义并测试。
9. 打通“新增连接 → 测试 → 选择表 → 采集元数据 → 读取样本 → 规则匹配 → 资产/发现详情”前后端闭环，文件与数据库来源可分辨，任务参数有不可变快照，凭据变更导致任务如何处理需明确。

P2 验收：两种数据库均用隔离实例和只读账号验证；覆盖空表、NULL、中文、特殊表名、无主键、大表限额、单表无权限、断连、超时、取消、重试、重复扫描、凭据更新。已知规则样本应有预期命中，阴性样本不能误判；异常/响应/任务中无明文凭据或敏感原值。目标数据库数据与结构保持不变。真实数据库联调只读，缺少连接信息时明确待验收。

## 验证、部署与交付

- 先记录同环境测试基线，再跑相关后端行为测试及边界测试；全量失败逐项与基线比对。参考 docs/数据资产开发入口.md 的最小回归，再补新增数据库与 root Linux 测试。
- 前端执行 npm run typecheck、npm test -- --run、npm run build；检查生产构建无 demo 模式。
- 新迁移在隔离数据库验证 upgrade 及可行的 rollback，记录新增 API 与旧 API 兼容结果；git diff --check。
- 按仓库要求用 legacy builder，构建前查看磁盘余量（本机近期发生 Docker 磁盘增长问题）；不能为构建删除用户数据。提供与新 schema 匹配的回退说明。
- 更新 TASK.md、PROJECT_STATUS.md、docs/architecture.md 及部署说明：分开记录已实现、隔离验证、已部署、真实验收与待办。不可把 HTTP 200 当成业务完成证据。
- 最终提交交付：故障根因及修复点、修改文件、测试结果、实际可运行的启动/迁移/root 升级与回退命令、数据库连接操作说明、真实验收任务 ID 或待提供参数。按 P0 → P1 → P2 顺序完成，不做到一个阶段就结束整个任务。

## 官方参考资料

以下为已检索参考，开发时核对采用版本的 API 和驱动行为：

- SQLAlchemy Inspector 元数据反射（schema/表/列等）：https://docs.sqlalchemy.org/en/20/core/reflection.html
- MySQL InnoDB 一致性非锁定读取及并发 DDL 限制：https://dev.mysql.com/doc/refman/8.4/en/innodb-consistent-read.html

上述资料用于实现参考，不代表项目目前已有数据库直连能力。

## 2026-09-20 实际故障补充与整改顺序

- 任务 4437：/root/home 返回目录不存在或不可读取，0 文件；不能断言纯权限问题。/home/kali 的历史任务 3435 成功返回 58 资产。必须区分不存在、非目录、无权限、符号链接与空目录。
- 任务 4441：/var 返回 Partial，9 资产、7 文件；/var/backups/dpkg.status.0 触发 row_budget。root 不解决预算限制；需检查单文件截断是否不必要地终止全任务，并展示真实原因。
- 在线探针观测为 3.4.1，源码 3.5.0；不能把源码配置当作线上生效配置。
- 数据资产抽查 2187 条中 1439 条 PCAP 名称记录（时点值）。根因：PCAP 分析 context.path 进入 DataEngine 文档分支，unsupported 被登记为 Unknown 文件资产；run_pipeline 每次新增，并丢弃 scan_status/scan_reason。不是指定目录扫描出来的文件。
- 优先停止原始抓包在文档资产分支登记，保留 PCAP 流量/DLP/YARA 分析；不能按扩展名删除用户盘点到的合法文件。保留普通文件不支持解析的状态和来源。
- 历史修复必须精确匹配 PCAP 存储记录与空来源元数据的错误投影，先 dry-run、再可回退归档/审计，不删除原始 PCAP、Finding 或传输证据，不能全表按 .pcap 后缀删除。
- 任务状态展示：Failed 不得显示“采集完成”；Partial 显示预算或覆盖原因；兼容旧任务的 result.coverage/result.budget；目录计数字段 directories_scanned 不得误读 directories_visited。

执行进展以 TASK.md 顶部的本次整改章节为准。先完成上述止增和诊断，再继续 P0 root 与分发包、P1 完整业务展示、P2 数据库直连；未验证/未部署必须逐项标注。
