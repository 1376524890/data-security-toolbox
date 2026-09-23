# Changelog

## 2026-09-24 — v3.2.0：漏洞库不再卡在「任务不存在」、抓包段不再刷屏任务监控、大屏两张图分开并画出数据链路

平台版本自 3.1.0 升到 **3.2.0**（`backend/app/main.py`、`frontend/package.json` 与
`frontend/package-lock.json`），探针保持 3.7.0，**无新增 Alembic 迁移**（head 仍为
`0019_policy_group_fingerprints`）。三处改动都来自运营侧的真实报障。

- **漏洞库永久停在 `Error: 任务不存在`**：Grype 任务的 id 存在浏览器 `localStorage`，任务状态文件
  存在服务端 `storage_dir/library_jobs/`，而**重新部署会换掉 `storage_dir`**。页面于是拿着一个
  新容器从没听说过的 id 去轮询 `GET /offline/grype/jobs/{id}`，`job_path` 找不到文件返回
  `404 任务不存在`；`poll()` 把 404 当普通错误写进 `error` 后**照旧每 2 秒再排一次**——报错清不掉，
  轮询也停不下来。现在 `api/client.ts` 把 HTTP 状态码挂到 Error（`failure.status`），
  `useVulnerabilityLibrary` 认 404 为「这条记录已经不存在」：清 `localStorage`、复位 `busy`、
  提示一次「已清除本地记录」，并**结束轮询**；非 404 的失败仍旧重试并记入 `error`。
  **判别依据是状态码，不是文案**，服务端改措辞不会让这段逻辑失效。
- **pcap 抓包段刷屏任务监控**：`default_task_filter()` 原先完全押
  `payload['monitor_task_id'] IS NULL` 来判断「是不是监控任务的子任务」，而挂链只发生在上传那一刻
  （`api/pcaps.py` 的 `ensure_monitor_task` + `attach_segment`）。**上传时没有 Running 监控任务**、
  或**挂链机制存在之前建的行**，都会留下没有链接的段，它们满足过滤条件，于是一条条裸 `pcap` 行挤满
  任务中心——本机实测 `GET /tasks` 共 94 行、最新 8 行全是 `pcap`，库里 76 行段没有链接。
  默认列表现在**直接排除 `kind='pcap'`**（用 `monitoring.SEGMENT_KIND`，不写字符串字面量），
  不再依赖那个可能不存在的字段；段的可达性不变，`kind=pcap` 仍能翻到全部段。实测 `GET /tasks`
  总数 **94 → 18**、无 `pcap` 行，驾驶舱「最近任务」（同一过滤器）只显示 monitoring/scan/file_source_scan。
  **过滤即修复，没有改一行历史数据**。
- **大屏「数据流动」与「地理位置态势」改成两个可切换视图，并在图上画出数据链路**：中心列原先上下
  并列两张图、各占一半高度（一张地图矮到看不清自己的连线）。现在同一时刻只渲染一张
  （`数据流动` 默认 / `地理位置态势`），当前图拿满整列高度；切换状态 `centerView` 与 `metric` 一样
  归 `useDashboardScreen`。地理态势里**画出数据流动链路**：从内网 hub 到每个目的国家/地区一条曲线，
  **粗细=数据量、颜色=该组敏感等级**、虚线沿 hub→目的地流动（方向是静态线说不出来的），悬停给出
  「内网 → 美国 · 2 主机 · 4.0 KB · L3 高敏感个人信息」。链路按**目的地区分组**绘制，
  **不画主机到主机**——`GET /dashboard/geo-map` 只把目的地址判定到国家、没有主机级坐标，
  画主机连线等于声称一个没人测量过的几何。另外**地球改为朝向数据量最大的境外目的地**：
  地球只能朝一面，原先固定 105°E，`-98.6°` 的美国落在背面被 `filter(visible)` 静默丢弃；
  现在背面剩下的组会在脚注里计数（「地球背面 N 组未绘制」），不再无声消失。
- **测试**：前端 22 文件 / **124 项通过**（新增 4 项：漏洞库 404 清记录并停表、502 保持等待、
  中心列切换、`centerView` 默认值），`vue-tsc --noEmit` 无输出。后端全量（容器内，需带
  `--ignore=tests/test_rule_libraries.py`）**29 failed / 978 passed / 5 skipped / 2 errors**，
  29 条与发布前基线**逐条一致、零新增**；改动文件 ruff 无违规。

## 2026-09-24 — v3.1.0：抓包队列不再被空段拖垮、流量误报的口径修正，密码评估结果回到资产中心

平台版本自 3.0.0 升到 **3.1.0**（`backend/app/main.py`、`frontend/package.json` 与
`frontend/package-lock.json`），探针保持 3.7.0，**无新增 Alembic 迁移**（head 仍为
`0019_policy_group_fingerprints`）。本版全部内容来自 2026-09-23/24 三批真机排障。

- **探针抓包改抓「真的有流量的网卡」**：`deployment/preflight.py` 原先用 `ls /sys/class/net`
  列出全部非 lo 名字，`capture_interface_for` 取第一个非虚拟的，于是真机上把**网线没插**的 `enp1s0`
  排在了 `UP` 的 `wlan0` 前面——部署记录 ONLINE、心跳正常、段也在上传，只有「永远没有内容」这一个症状。
  preflight 现在读 `operstate`，只把内核报告为 up 的网卡交给选择逻辑，完整清单另存 `all_interfaces`
  供控制台展示；驱动把 operstate 报成 `unknown` 时回退到全部非 lo 名字。
- **空抓包段不再占用 60 秒分析时间**：零包的段仍会跑全部引擎，而 Suricata 对读不出包的 pcap 不是快速
  失败（耗尽自身 ~60 秒启动预算才抛异常）。30 秒一段、60 秒一段地分析，积压必然无界增长（真机实测
  探针 8 四十分钟内 pending 段 7 → **75**）。`analyze_pcap_task` 现在在跑引擎前判断包数为空，写一条
  `capture` 模块结果后直接收尾。
- **单个引擎抛异常不再中止整段分析**：`EngineRegistry.run` 逐个引擎隔离，失败只记 warning 并挂到
  `context.data["engine_errors"]`，其余引擎照常产出；任务把 `engine_errors` 落成 `engine_error`
  模块的结果——**盲区要看得见，不能读成「干净抓包」**。
- **死掉的分析任务与「已回收却仍显示 pending」的行**：新增 60 秒 beat 任务
  `security_toolbox.sweep_stale_analyses`，把 Running 超过 900 秒的任务判 Failed、段记录 `pending → failed`；
  `pcap_storage.release` 删文件时同时把 `pending` 标成 `evicted`（已 `analyzed` 的不动）。
  真机一次收掉 **208 行**幻影积压。
- **流量误报的两处口径错误**（本版「误报严重」的主因）：
  `RollingTrafficState` 原先只按**源地址**建键并直接数 `dst_port`，抓包流是单向的，DNS 服务器的应答
  （`114.114.114.114:53 → 客户端:临时端口`，一客户端一条流、目的端口各不同）于是把**每台繁忙服务器
  在每一段里都判成在扫描它自己服务的网**——改为按 `(probe, src, dst)` 建键、用
  `traffic_scope.service_port()` 取服务侧端口；
  `NET_RATE_001` 与遗留 `high_packet_rate` 原先都算 `packets / max(span, 0.001)`，**只有一个包的会话**
  （跨度为 0）算出 **1000 pps**、直接越过 `packet_rate > 500`——改为共用
  `traffic_scope.conversation_rate()`，跨度下限 0.05 秒（单包读 20 pps，1000 包/10 ms 仍读 20000 pps）。
- **存量误报清理**：走 `POST /admin/findings/purge-false-positives`，只清本轮**改过口径**的三条规则
  （`NETWORK_PORT_SCAN` / `NET_RATE_001` / `high_packet_rate`），先 dry-run 对齐再实删，共
  **119 条 finding + 6 条级联告警**；`NET_SCAN_001` 的口径本轮没动，按行证据判定仍然成立，故保留。
- **密码评估结果回到资产中心**：新增 `资产中心 → 密码评估`（`/data-assets?view=crypto`）。
  检查任务的密码评估结果原先只在**任务中心详情抽屉**里能看到，运营侧看不到；新页面列出
  `payload.crypto_assess` 且真正产出 `result.crypto_profiles` 的检查任务，复用既有
  `CryptoAssessmentPanel` 与同一套评估逻辑（GB/T 39786 / GM/T），不新增第二套打分口径。
  `GET /tasks` 不能按 payload/result 字段过滤，因此服务端分页、前端过滤，并保留服务端总数，
  页面显示「共 N 条检查任务，其中 M 条含密码评估结果」。

本版不含新增迁移、不改 API 路径与返回结构、不动探针版本。

## 2026-09-22 — v3.0.0：一键离线部署套件与平台 3.0.0

平台版本自 2.14.0 升到 **3.0.0**（`backend/app/main.py`、`frontend/package.json` 与
`frontend/package-lock.json`），探针保持 3.7.0，迁移 head = `0019_policy_group_fingerprints`。

- **一键离线部署**：新增 `deploy/` 套件——`deploy.sh`（环境自检 → `docker load` → 按配置生成 `.env` →
  授权数据目录给容器用户 10001 → 端口预检 → `docker compose up -d --no-build --pull never` → 等 backend
  健康 → 打印地址与管理员口令）、`deploy.conf`（**唯一配置入口**，全部参数带中文注释，`auto` = 首次生成、
  以后沿用；命令行 > deploy.conf > 内置默认）、`undeploy.sh`（停栈保留数据，`--purge` 二次确认后删数据目录）、
  `README-离线部署.md`（含排错表）。目标机只要求 Docker Engine 20.10+ 与 compose v2，不需要外网、
  Python、Node 或抓包工具。
- **交付打包**：新增 `scripts/make_offline_release.py`——硬链接暂存（不额外占盘）→ 把 `deploy/` 拷到包根 →
  生成 `VERSION` / `SHA256SUMS.txt` → `tar --hard-dereference` + `gzip -1` 出
  `dist-release/dst-toolbox-<ver>-linux-<arch>.tar.gz` 与其 `.sha256`；缺镜像归档时拒绝打包。
  包内含 6 个 arm64 镜像、探针 3.7.0 分发包、全量源码与 `.git`、`frontend/node_modules`，
  服务器上可继续开发。
- **交互式配置**：在终端直接跑 `deploy.sh` 会先逐项提问必要参数（项目名、数据目录、端口、探针回连地址、
  管理员账号、数据库名/用户、五个口令与密钥、可选的通知/情报/主机审计集成），回车 = 取 `deploy.conf` 的值、
  口令留空 = 自动生成（隐藏回显）；确认摘要里不回显口令明文。确认后**非口令项写回 `deploy.conf`**
  （只改真正变了的项，行尾中文注释保留），口令只留在 `.env`，所以重跑不会退回旧值也不会换钥。
  `--non-interactive` 全自动（stdin 不是终端时自动如此，部署脚本里默认如此），`-i/--interactive` 强制提问。
- **交付包里没有 `.env`**：`make_offline_release.py` 显式排除操作者的 `.env`（里面有真实口令与现场 IP），
  只带 `.env.example` 模板，目标机的 `.env` 一律由 `deploy.sh` 生成。
- **README 部署章节**改为指向 `deploy/`（旧的 `docker load` + 手工 `docker compose up` 步骤保留为手动路径）。

本版同时收进此前几批已上线但未发版的内容（态势大屏、综合驾驶舱与浅色控制台、CVE 规则库与网络资产、
出境明细与离线地理表、任务中心向导化与监控任务分段归集、政策组只读评估），完整清单与验证证据见
[docs/releases/v3.0.0.md](docs/releases/v3.0.0.md)。

## 2026-09-22 — 数据安全综合驾驶舱、浅色控制台与图表主题联动（平台 2.14.0，未升版本号）

控制台现在有**两个首页**：`/` 仍是壁挂用的数据安全态势大屏（深色、无侧边栏/顶栏、固定 1920×1080），
新增 `/cockpit` 数据安全综合驾驶舱作为**日常使用页**（在控制台壳层内）；`/screen` 重定向到 `/`，
历史链接不落空。两个首页共用同一条 `GET /dashboard/overview`，因此同一时刻不可能对不上数字。

- **驾驶舱页面**：八张 KPI 卡、数据安全健康度环、资产/风险两个分布环形（可切换维度）、合规进度板、
  本周重点关注、安全流水线、数据流动卡片与最近任务。视图只留版式、路由与格式化，投影与刷新都在
  `modules/dashboard/cockpit/composables/useDashboardCockpit.ts`（30 秒刷新，timer 归 composable 并在
  卸载时清除）；**刷新失败保留上一次成功的数据**并显示「数据刷新失败…（下方为最近一次成功的数据）」，
  不把页面清空成 0。
- **接口**：`GET /dashboard/overview` 增加驾驶舱块（`_cockpit_blocks`，与大屏共用同一份组件/告警/事件口径）；
  新增 `GET /dashboard/trend?range=7d|24h`（发现/事件/告警与三类流向共用一条零填充时间轴，流向按
  `flows.start_time` 落桶）与 `GET /dashboard/tasks?limit=`（复用 `/tasks` 的 `visible_tasks` + 默认过滤 +
  `serialize_task`，只读、不做监控汇总）。全部按行实时聚合，不落缓存、不写死。
- **判定口径只有一份**：健康度、合规进度与流向汇总在 `services/cockpit_service.py`，流向分类仍走
  `services/egress_regions.direction_of`，大屏 / 驾驶舱 / 合规板不会各说一套。
- **浅色控制台**：控制台改为**默认浅色**（只有 `dst-theme === 'dark'` 才深色）；主题状态提到
  `frontend/src/utils/theme.ts`（`themeMode` ref + `applyTheme` + `chartColors`），`App.vue` 只保留切换按钮。
  ECharts 的 option 在构建时就把颜色写死，因此 `components/charts/{Bar,Donut,Gauge,Trend}Chart.vue` 会监听
  `themeMode` 重建 option——否则切到浅色后画布仍留着深色网格与轴色。壁挂大屏不受主题影响（固定深色）。
- **菜单**：`数据大屏`（`/`）与 `数据安全驾驶舱`（`/cockpit`）是仅有的两个无分组标题条目，位于侧边栏顶部。

## 2026-09-22 — 控制台首页重做为「数据安全态势大屏」（平台 2.14.0，未升版本号）

面向客户演示 / 会议 / 大屏的首页：固定 1920×1080 深色大屏，整页等比缩放（1920×1080、1366×768、
2560×1440 实测满屏无裁切），`meta.layout='screen'` 下不渲染侧边栏与顶栏。顶部为品牌、标题
「数据安全态势大屏」、副标题、API 状态、集成组件 x/y、在线探针与时钟；下方是 6 张 KPI 卡、
数据流动势态拓扑（中心为流量最大的内网节点、内环内网节点、外环外部端点，点节点出资产/流量/风险抽屉）、
两条 7 天趋势与两个分布环形图，底部为检测引擎运行状态、探针健康、事件闭环与自动滚动的实时安全事件。
旧的统计型 `Dashboard.vue` 与其 composable 已删除。

- **接口**：新增 `GET /dashboard/overview`、`GET /dashboard/traffic-flow`、`GET /dashboard/risk-distribution`、
  `GET /dashboard/detection-trend`，全部由 `app/models.py` 的行实时聚合，不落缓存、不写死；
  `GET /alerts` 增 `order=recent`（按 `last_seen` 倒序，默认 `risk` 顺序不变）；
  `api/integrations.py` 抽出 `integration_catalogue()`，`/integrations`、`/health` 与大屏共用同一份组件口径。
- **流向判定**：只报内部流量 / 外部流出 / 目的未识别三类。库里没有 zone 表，因此不做「跨域访问」这一档；
  `external` 仅在地表或黑名单命中时成立，未证实的目的地一律保持黄色「未识别」而不是当成出境告警。
- **实机走查修掉的缺陷**：① 顶栏 `height:100%` 使中部整行塌为 0，改固定 76px；② 拓扑在隐藏状态下被
  echarts 以 100×100 初始化、整图缩进一个角，改 `ResizeObserver` 跟随容器；③ 底部引擎卡装不下 8 个适配器
  （后两个被切掉），收紧行距并加高底栏；④ 检测趋势横轴改 `MM-DD`，末位刻度不再被裁。
  另把节点风险扫描压到两列，`/dashboard/traffic-flow` 由 1.6s 降到约 1.06s。
- **回归**：`vue-tsc` 干净、`vitest` 16 文件 / 72 项（新增 `dashboard-screen-state` 11 项、
  `dashboard-screen` 2 项整页挂载）；后端 `test_dashboard_screen_api.py` 5 项、
  `test_dashboard_boundaries.py` 8 项及相邻域 66 项通过。

## 2026-09-22 — CVE 规则库恢复、网络资产页与出境报告明细（平台 2.14.0，未升版本号）

修复「网络扫描按指纹匹配漏洞库」这一断掉的链路，并补齐三处界面。

- **漏洞库（采集与规则）**：`local_cves` 之前为空——导入器把 NVD 记录拍平成文本，受影响版本区间丢失。
  现在保留 `product` 与 `affected_versions`（`cpeMatch` 的 `versionStartIncluding`/`versionEndExcluding` 等），
  CVSS v3.1/v3.0/v2 三代都读，严重度按 CVSS 分档。新增按扫描指纹的在线更新
  （`GET /api/v1/offline/cves/fingerprints`、`POST /api/v1/offline/cves/sync`，逐个关键字隔离失败）
  与手动导入/手动添加/Grype DB 管理。
- **网络资产（资产中心）**：新增 `GET /api/v1/network/assets`、`/network/assets/summary`，把
  `platform_scan`/`nmap_scan`/`probe_scan` 的端口清单与已落库的 `CVE_*` findings 按 (ip, port) 合到一张表；
  同一规则跨多次扫描去重，候选线索行带上自己的 CVE 号。
- **菜单**：`数据大屏` 分组不再渲染标题（总览），`资产中心` 下为 `数据资产` + `网络资产`，
  `采集与规则` 增 `漏洞库`。
- **数据出境报告**：传输对象新增 `src_ip:port → dst_ip:port`、`sha256`、`complete`、`content_type`、
  `binary_available`、`sensitive`、`matches`（含命中值样本）、`rule_ids`、`files`/`file_bound`；
  详情抽屉可看具体流量、是否含敏感信息、命中的规则与原文、对应文件，以及该会话的报文列表与单包解析。
- **判定修正（重要）**：① NVD 同一 CVE 下**其他产品**的版本区间不再拍平进主产品，
  避免 `nginx 1.27.5` 命中 android 的 `<13.0`；② 解析不了的版本约束不再被静默跳过（此前会让整条
  规则空真通过，`OpenSSH 8.2p1` 命中只列 `3.7.1` 的 CVE）。修后同一资产从「4 条虚假已确认」变为 0 条。
- **离线部署**：`scripts/offline_bundle.py` 改为读 `docker compose config --images` 取镜像清单并做
  **架构校验**（`aarch64`/`x86_64` 不可混用，不一致直接报错），README 给出真实镜像清单与
  `--no-build --pull never` 的离线启动命令；`docs/offline-deployment.md` 重写。
  arm64 实测：6 个镜像均为 `arm64/linux`，`docker save` 3.2 GB 包可 `docker load` 回灌，
  `--pull never` 离线重建容器成功。

## v2.14.0 交付更新（探针 3.7.0，2026-09-21）— 探针自带运行时

探针升到 **3.7.0**：分发包自带 CPython 3.11、全部 Python 依赖、`dumpcap`/`tcpdump` 及其 ELF 库闭包、
私有动态加载器与 CA 证书，目标机不再需要主机 Python、pip、apt、wheel 或抓包工具。平台侧预检改为用这同一个
运行时探测目标机（`app/deployment/{preflight,runtime}.py`），不再要求目标机 `python3 >= 3.11` 或预装
dumpcap；服务单元仍是 `dstprobe` + `NET_RAW`/`NET_ADMIN`/`DAC_READ_SEARCH`，不提权到 root，读不到的目录
按覆盖缺口上报。

- **安装/升级/回退**：`install.sh` 先用自带解释器跑 `runtime_check.py`（架构、解释器版本、依赖、抓包工具、
  可选平台连通性、archive sha256），通过后才停服务、原子替换 `/opt/data-security-toolbox/runtime`；
  `probe.toml`、`probe.token` 与 spool/rules/cache 全部保留，所以换新包目录重跑即升级、换旧包目录重跑即回退。
  不再使用 pip/apt/venv，也不再往 `/usr/local/bin` 写文件（`--skip-deps` 已移除）。
- **不依赖目标环境**：`ExecStart` 固定指向 `run-probe.sh`，该脚本只用 shell 内建命令定位自身目录（不用
  `dirname`）、自设 `PATH` 并固定 `PYTHONUTF8=1`/`PYTHONIOENCODING=utf-8`——systemd 启动时 `LANG` 未设置，
  CPython 会退回 C/POSIX 语言环境并按 ASCII 处理 stdio，中文日志（中文文件名、规则包消息）会被转义甚至
  抛 `UnicodeEncodeError`；随包单元模板与 `install.sh` 生成的单元都写入这两个环境变量。`install.sh` 另加
  主机工具前置检查（`tar`/`systemctl`/`useradd`/`id`/`chown`/`find`/`dirname`/`mktemp`，缺一个就一次性列出
  全部后退出），`runtime_check.py` 校验运行时布局完整性并断言解释器来自包内 `python/`。冒烟覆盖「空环境 +
  C 语言环境启动」「UTF-8 中文落盘」「76 个自带扩展模块全部可导入」「`/proc/self/maps` 无 runtime 外 .so」，
  arm64 在 qemu 下显式 SKIP 真实抓包（模拟器不能翻译 libpcap 的 socket ioctl）而不是误报失败。
- **平台口径**：平台自报版本仍是 2.14.0（本次是同一发布版本的交付更新），`PROBE_AGENT_VERSION` 与
  `.env.example`、compose 默认值同步为 3.7.0；镜像另打 `2.14.0-probe3.7.0` 标签，供已部署实例就地升级。
- **交付包**：`deploy_rev` 由 r2 升到 **r5**（`deploy.sh` 启动即打印平台/探针/脚本修订号；r3 是这批自带运行时
  改动，r4 是按文档口径改正平台 `README.md` 与包内交付 README，r5 是探针启动链路加固（启动器自设 `PATH`
  并固定 UTF-8、安装前一次性检查主机工具、`runtime_check.py` 校验运行时布局与解释器来源）后重出——靠修订号
  与整包指纹区分版本）；`VERSION` 写明
  `probe_python = 随包独立 Python 3.11，目标机无需 Python/pip/抓包工具`；`probe-offline/` 只做架构分发，
  不再探测主机解释器，也不接受 `--python`/`--wheels`。
- **Git**：平台 2.14.0 / 探针 3.7.0 已提交到 `develop`（`c903768`）并推送，创建注释标签 **v2.14.0**。
- **验证**：交付包内的探针包在一次性、无网络、无 Python 的 Ubuntu 22.04 容器里跑通离线安装冒烟
  （私有库不外泄、真实 `dumpcap` 抓包、重装保留 token 与 spool、`--keep-data` 卸载）；后端全量 6 项失败与
  基线逐项一致；平台镜像重建并切换后 `/api/v1/health` 全绿、`openapi.json` 2.14.0、
  `alembic current` = `0017_file_sources (head)`，容器内 `app/deployment/*` 与工作树 SHA256 逐字节一致。
  详见 [离线交付包](docs/offline-package.md) 与 [探针说明](probe/README.md)。

## v2.14.0（2026-09-20）— 共享文件来源、数据库直连盘点与统一规则源

平台版本升至 2.14.0（`backend/app/main.py`、`frontend/package.json` 与 lock），探针升至 3.6.0
（本版改了探针源码 `probe/data_assets.py`、`shared/sensitive_detection/*`、`shared/scanning/*`，
已重建分发包）。迁移新增 `0016_database_connections` 与 `0017_file_sources`，head 为 `0017_file_sources`。

- **统一规则源**：控制台手写规则与探针内置规则改走同一个敏感引擎 `services/sensitive_engine.py`
  （`analyst_rules()` 读规则库、`scan_engine()` 按 mtime+size 签名重建、`scan_all()` 一次扫描），
  文件扫描、数据库扫描、DataEngine 与网络防泄密四个消费方全部改走它。一条规则在
  「敏感发现 / 实时流量告警 / 网络防泄密」三处命中口径一致，三处都带命中原文。
- **命中原文回传（契约变更）**：`DetectionHit.matches` 携带 `value`（命中原文）与 `context`（所在行），
  落库在 `DetectionEvidence.extra['matches']`。上限两侧各自强制：每条命中 ≤3 条、`value` ≤120、
  `context` ≤240 字符；`report_guard` 把 `matches` 列为 `RAW_TEXT_KEYS`，其余字段仍不含任何值。
  旧证据行没有该字段，前端显示「没有回传原文」，不伪造也不报错。
- **共享文件来源**：平台可只读采集 FTP/FTPS/SFTP 共享目录，来源可新增/修改/删除，共享目录不再与协议、
  地址、端口一起锁死；采集中的来源不可删，删来源只删配置、保留已采集资产与证据。真实目标 vsFTPd 3.0.5
  不支持 `MLSD`，适配层已补 `LIST` 回退。
- **数据库直连盘点**：只读会话直连 MySQL/MariaDB（PyMySQL）与 PostgreSQL（psycopg2），枚举库/表、
  按列复用同一份敏感引擎做规则匹配，登记为 `source_kind=database` 的资产与检测证据；支持库表选择、
  按预算采样、可停止任务与按表明细；口令 AES-GCM 加密落库、只写不读。
- **采集语义**：`shared/scanning/budget.py` 把「目录枚举终止」与「内容采样截断」分开记账
  （`enumeration_complete` / `content_complete`），长文件不再终止整棵目录遍历；探针区分目录
  不存在/非目录/符号链接/无权限/其他错误；`collection_outcome` 统一采集终态文字。
- **止增**：DataEngine 按 `context.target_type` + `context.path` 识别原始抓包容器，只阻止登记为文档资产，
  保留 YARA 与提取文件路径。历史错误投影只做只读审计（`scripts/audit_capture_assets.py`），未删除任何数据。
- **离线交付**：新增 x86_64 Linux（银河麒麟桌面操作系统 V10 SP1 / Ubuntu 22.04 LTS）离线一键部署包，含 8 个镜像、探针 3.6.0
  分发包与离线 wheel、Compose v2 插件；`deploy.sh` 全程不构建、不拉取。见
  [x86_64 Linux 离线交付包](docs/offline-package.md)。
- **验证**：后端 829 passed / 6 failed（6 项失败与基线逐项一致）；前端 `vue-tsc` 通过、vitest 31 文件
  267 项通过、生产构建未启用 `VITE_DEMO_MODE`；本机重建 5 个应用镜像并切换容器，`/api/v1/health`
  全绿、迁移 `0017_file_sources (head)`、运行栈自报 2.14.0。真机证据见
  [发布记录](docs/releases/v2.14.0.md)。

## v2.13.0（2026-09-20）— 结构与状态解耦

本次发布把采集、编排、路由与页面状态按边界拆开，是纯结构调整：接口集合、数据表与索引、迁移基线与
运行行为都不变。平台版本升至 2.13.0（`backend/app/main.py`、`frontend/package.json` 与 lock），
探针声明保持 3.5.0（本版未改探针与分发包），迁移仍为 `0015_alert_hits (head)`。

- **分析编排与 Celery 入口分离**：跨域编排移到 `app/application/analysis.py`，`workers/*_tasks` 只做入口；
  路由与领域服务不再导入 `app.workers`，派发统一经 `services.task_dispatch`。
- **数据资产边界**：采集接口拆到 `app/api/data_collection.py` 与 `data_collection_schemas.py`；探针鉴权移到
  `app/api/dependencies.py`；任务创建集中到 `services/probe_task_service.py`；数据对象服务拆成
  `app/services/data_objects/`（身份、覆盖度、证据、入库、投影、查询），`data_object_service.py` 保留兼容导出。
- **v1 大路由按域拆出**：PCAP、文件证据、平台资产、事件/情报、告警、任务/审计/报表、检测/引擎、看板/流量、
  探针、集成与离线导入、规则以及 v1 剩余零散入口各自成模块；`app/api/v1.py` 只做聚合，自身不声明路径。
- **前端页面状态解耦**：15 批把约 25 个页面的状态抽到 `modules/*/composables/*.ts`，视图只保留模板、静态
  展示配置与格式化函数；轮询与长连接（`EventSource`、定时器）随状态进 composable 并在卸载时清除。
- **回归测试**：新增 17 个后端边界测试文件与 15 个前端状态测试文件；后端测试项由 596 增至 726。
- **验证**：隔离容器同环境对照——`develop` 基线 596 项 / 12 项失败，本版 726 项 / 同样 12 项失败，失败用例
  集合逐项一致、新增失败 0 项；前端 `vue-tsc` 通过、vitest 231 项通过、生产构建通过；OpenAPI（144 路径 /
  158 操作）、38 张表与 104 个索引与拆分前逐项一致。详见 [发布记录](docs/releases/v2.13.0.md)。

## v2.12.0（2026-09-19，Git 标签发布）— 业务逻辑与数据真实性整改

本次按“不修改代码”要求发布现有整改快照，源码内平台版本仍为 2.11.0、探针声明版本仍为 3.5.0；
以 Git 注释标签 v2.12.0 标识本次发布，不代表已生成同版本镜像或新探针分发包。
迁移基线为 0015_alert_hits；部署与验证限制见 `docs/releases/v2.12.0.md`。

按工作区 `业务逻辑与数据真实性整改清单.md` 的 29 项修正判定逻辑与展示口径。镜像已重建部署并通过真实探针采集核对，
历史数据重算/修复尚未执行。

- **判定与漏检**：DNS 隧道要求同一源主机、同一注册域下至少 3 个编码左标签且至少 20 次查询；CVE 关键字命中先记为候选
  `CVE_CANDIDATE_001`，只有版本落在本地库声明的受影响范围内才生成确认的 `CVE_<id>`；端口扫描按最忙窗口统计不同目的端口数；
  脚本上传要求 multipart/octet-stream 与脚本扩展名；C2 心跳要求明确源/目的、至少 10 个报文、观察时长 ≥60 秒、平均间隔 ≥1 秒且间隔变异系数 <0.2；
  数据引擎只产出确认类发现，API Key 仅按 `AKIA`/`ASIA` 精确 16 位识别，字段名判定先做 token 化再做值级确认。
- **扫描与解析真实性**：文档解析返回 SCAN_COMPLETE / PARTIAL / UNSUPPORTED / FAILED，采样合并重叠区间、保留末行无换行并取覆盖率并集；
  文件当前风险汇总元数据线索与数据敏感分级，进行中/失败/未支持不再默认 Low。
- **状态与关联**：事件阶段只按规则 id 归类，未识别的规则保持 `unknown`；告警抑制签名改为
  `fingerprint(rule, source, asset, ioc, probe)`，新增 `alert_hits` 记录被抑制告警的每次命中（首次/最近/最高风险）；
  PCAP 暴露面按内网 2.0、外网 3.0 计分并给出 `exposure_basis`；完成扫描替换实例类别、部分扫描只叠加；
  迟到报告不得让在位实例退役；对象与实例计数按受影响对象集合重算；数据资产与文件改用 `file_id` 关联；
  重新分析先把上一轮文件派生结果标记 `superseded` 并删除旧的按文件 `DataAsset`；投影重建从扫描快照恢复字段与证据。
- **展示与交付真实性**：`POST /api/v1/test/import` 由 `TEST_DATA_IMPORT_ENABLED` 控制，生产环境启用会直接启动失败，
  非授权环境返回 403；`/health.features.test_data_import` 暴露开关状态，前端据此隐藏入口；
  `GET /sensitive/findings` 改为全表聚合 + 分页 + 来源分列，并区分在位与历史未观测资产；
  数据类型中心顶部卡片改用服务端跨类型去重的 `totals`，单实例的部分指纹对象显示“待确认身份”而非“疑似副本”；
  文件类型筛选兼容扩展名与 MIME；数据资产详情返回字段级 PII 汇总；Partial/取消扫描显示明确原因；
  数据库端口发现标为“疑似数据库服务（端口推断）”；敏感分级覆盖统一作用于类型中心、对象与实例视图并返回 `level_source`。
- **数据库**：新增迁移 `0015_alert_hits`（`alert_hits` 表与 `detections.sample_limit`），head 由 `0014_probe_removal` 变为 `0015_alert_hits`。
- **历史数据 dry-run 工具**：新增只读脚本 `scripts/remediation_dry_run.py`，按整改清单第四节的顺序输出受影响记录清单与
  “将要执行的动作”差异（告警命中回填、对象计数/类别、样本口径、API Key 待复核、重复分析、投影结构、展示口径、测试数据），
  不写库、不把规则命中判为误报、不补造缺失的时间/哈希/样本/版本；投影重建还会把“列名被写成敏感类别”的不可恢复历史行
  标为 `extra.rebuild.fabricated_columns=true`。
  2026-09-19 复跑时补充：目录与端口推断数据库服务的汇总标签按设计没有检测，不再计入“类别无当前检测支撑”的漂移清单。
- **目录汇总不再当成独立发现**（真实探针验证中发现）：目录条目只上报子项类目并集、`counts` 为空，服务端原先仍为每个类目
  建了一条 `hit_count=0` / 无证据的“检测”，既不是发现，也让类型中心多算了目录。现在 `ingest_report` 只对上报了计数的
  类目（`category in counts`）建检测，`probe/data_assets.py::_directory_asset` 在证据里显式标注 `aggregate: true`
  （该标记需重建/升级探针包后生效，服务端不依赖它）。修复后 `/etc` 这类目录节点的检测数为 0，类目仅作为汇总标签保留。
- **部分采集的目录节点不再显示“已完整扫描”**：目录与端口推断条目没有解析覆盖度，原先默认 `coverage="complete"`，
  Partial 报告里的目录也读作扫描完整。现在回退到本次报告自身的覆盖率与终止原因，实测目录节点显示 `partial / row_budget`；
  该回退只影响没有自带覆盖度的条目，文件仍以自己的解析结果为权威。
- **旧投影的分级不再弱于平台口径**：探针本地严重度映射可能滞后于它刚下载的规则集（实测 agent 3.4.1 把
  `se_organisationsnummer` 上报为 `Low`，而同一文件的检测结果是 `Medium`），`data_assets.sensitivity` 原先原样照抄上报值，
  于是资产列表 Low、对象详情 Medium。现在投影取“平台映射与上报值中更严格者”，`Unknown` 等非严重度值保持原样，
  与 `rebuild_projection` 的取数路径一致（实测重扫后列表与详情同为 Medium）。
- **验证**：已按 `AGENTS.md` 用 legacy builder 重建 `source-backend` / `source-worker`（另打 `source-beat`、
  `source-deployment-worker` 标签）并重建容器，backend 启动时执行 `0014_probe_removal -> 0015_alert_hits`；
  `/health` 全绿，容器内 tshark 4.4.18 / zeek 9.0.0 / suricata 7.0.10（52,270 签名）可用、`features.test_data_import=false`。
  探针 #2（agent 3.4.1）真实采集核对通过；历史数据修复（告警命中回填、对象计数重算等）仍未执行。

## v2.11.0（探针 3.5.0）

- **规则库不再是空壳**：此前控制台里多数引擎的规则列显示为空，因为阈值以字面量写在引擎代码里，磁盘上没有对应规则文件。
  现在每个引擎都有自己的规则目录，并真正从规则文件读取参数（`app/rules/library.py`、`app/rules/catalog.py`）：
  引擎按目录枚举规则文件，新增规则无需改代码；文件缺失、被禁用或格式损坏时回退到代码里的原值，
  一次错误编辑不会让检测停下来。规则值带 mtime 缓存，按分析任务读取。
- **「代码即规则」也进清单**：`app/rules/code_catalog.py` 用 AST 读取适配器源码，把实现检查逻辑的代码项列进规则清单；
  `app/rules/builtin.py` 为引擎内置规则声明 id、引擎、严重度、条件与建议，并标出实现它的 `.py`。
  实测 15 个引擎规则数全部非 0，清单共 3,512 项资源（含规则文件、代码检查与敏感检测定义，不等于单条签名数）。
- **在线更新上游规则集**：新增 `app/rules/sync.py` 与 `POST /api/v1/rules/sync`，从上游拉取 Sigma、
  Suricata ET Open、Zeek、osquery、Wazuh、OpenSCAP、Presidio 的规则；下载先按引擎自身格式校验，
  通过后才原子替换，失败保留旧规则集并回报失败，而不是静默沿用陈旧规则。文件数与字节数有上限，
  离线或出网被拦时不会破坏现有规则。实测 Suricata ET Open 52 份文件、本机实际加载 52,270 条签名。
- **命中可追溯到规则原文**：分析时把命中的规则原文与 SHA256 存入 `rule_snapshot`；告警详情新增 `rule` 字段，
  按「规则库文件 → 代码内置规则 → 数据驱动规则（DLP 策略、本地 CVE 库）」三层解析，
  `resolution` 标明是 `matched_snapshot`（当时命中的版本）还是 `current_definition`（无快照时的当前定义）。
  「代码实现的规则没有规则文件」不再导致规则列空白；规则中心支持按引擎筛选、搜索、分页与原文懒加载
  （新增 `GET /api/v1/rules/content`，`GET /api/v1/rules` 增加 `engine` 参数与 `include_content`）。
- **引擎归属与规则数口径统一**：`interpret_rules()` 不再硬编码注册表里不存在的幽灵引擎 `rules`，引擎名由调用方传入；
  `GET /api/v1/engine/registry` 每项追加 `slug` / `label` / `rule_count` / `detection_engine` / `detection_count`，
  前端的引擎下拉与过滤全部改读注册表，不再各自硬编码名单。规则数与 `/rules` 清单共用同一个枚举点。
- **引擎总览页**：安全引擎菜单由 12 个逐引擎入口收敛为单一「引擎总览」（前端路由 `/engines`），
  一张表列出全部引擎的名称、类型、版本、状态、规则文件数、检测数与来源；`/engines/:name` 详情页保留。
  导航按「谁在用」收敛，引擎差异化信息放进总览与详情，不再随引擎数量膨胀。
- **资产与事件归属修复**：事件的 `evidence.assets` 记录该事件覆盖的全部主机（`evidence.asset` 仍是展示标签）；
  资产详情的「关联检测」从只匹配 `evidence.asset.ip` / `evidence.ip` 扩大到所有主机拼写，并补读情报引擎的
  `matched_iocs`；finding 去重签名复用同一套身份解析，不再把不同主机的结果误合并。
  新增 `POST /api/v1/incidents/rebuild-attribution`，只按原始数据重算既有事件的 `asset` / `assets` / `stages` / `title`，
  不增删事件、不改 `fingerprint`，并写审计。实测资产 192.168.191.130 关联检测 0 → 99、关联事件 0 → 20，
  库内 `engine='rules'` 归零。
- **PCAP 工作台**：
  - 手动上传返回并直接打开 `id` 与 `duplicate`，上传有进度与独立 30 分钟超时，网关对上传关闭请求缓冲；
    重复文件先确认再走队列背压检查。原先页面忽略返回 ID、只刷新按新旧排序的当前页，造成「上传没有成功」的观感。
  - 包列表改为上方全宽表、下方协议树/字节视图，支持分页与搜索，概览显示真实总数并标明已索引数；
    补齐 IPv6 / 非 IP 帧地址，时间保留微秒，Hex 列固定字符宽度防止错位。
  - 新增 `app/services/pcap_files.py`：抓包内传输文件（HTTP / FTP-data / SMB / TFTP / IMF）独立于 DLP 告警落盘，
    标明缺包、配额限制与加密流，并保留 TShark 原生对象导出；新增
    `GET /api/v1/pcaps/{id}/files/{file_id}` 分页文本/Hex 预览与下载端点。
    下载与预览按本抓包的文件清单校验文件 ID 归属，不再信任事件里的任意存储路径。
    文件预览是字节解码，不承诺 PDF / Office 等格式的正文渲染。
- **集成与解析修复**：Zeek JSON 开关与 JSON `.log` 解析、Suricata 误用 `-q`、Linux cooked-v2（`LINUX_SLL2`）
  抓包兼容，原生命令错误不再被吞成空结果。
- **部署阶段标签与演示文档**：探针下发/回收各阶段显示中文标签，新增 `docs/领导演示方案.md`。
- **版本**：平台升至 2.11.0，探针保持 3.5.0（本版未改动探针代码）；
  数据库迁移仍为 `0014_probe_removal (head)`，升级无需执行迁移。
- **验证**：前端 `vitest` 34 passed、`vue-tsc --noEmit` 通过；后端定向回归（规则执行、告警、PCAP 工作台）通过，
  全量后端仍有既有 16 项失败（探针包缺失、Windows/Linux 行尾、容器内 Suricata 能力等环境相关），与上一版基线一致。

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
