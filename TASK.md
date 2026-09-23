# 当前任务：资产与数据安全增强

## 第四十九批：漏洞库「任务不存在」、抓包刷屏任务监控、大屏两张图分开切换（2026-09-24）

用户要求：① 大屏的「地理位置态势」和「数据流动」做成两个可切换的页面、不要并列、并在地图上
把数据流动链路划清楚；② pcap 抓包不要刷屏任务监控；③ 漏洞库显示 `Error: 任务不存在` 要查出原因并修复；
④ 修复后重新打包发布、推 git。

### 缺陷一：漏洞库页永久停在「Error: 任务不存在」

**根因（客户端与服务端各自都对，是生命周期错配）**：`useVulnerabilityLibrary` 把 Grype 任务的 id 存在
`localStorage['grype-library-job']`，而任务的状态文件存在服务端 `settings.storage_dir/library_jobs/`。
重新部署会换掉 `storage_dir`（bind mount 换新），于是页面拿着**新容器从没听说过的 id** 去轮询
`GET /offline/grype/jobs/{id}`，`integrations.py::job_path` 找不到文件就 `404 任务不存在`；
`poll()` 把 404 当成普通错误写进 `error`，然后**每 2 秒重排一次**——页面既有一个永远清不掉的红色报错，
又永远停不下来。本机 `deploy-data` 被换过多次，这个 id 因此长期存活。

- `api/client.ts`：响应拦截器把 HTTP 状态码挂到 Error 上（`failure.status`）。此前只有一句话，
  调用方无法区分「这条记录没有了」（404）和「服务端不健康」（5xx），而这两者的处置完全相反。
- `useVulnerabilityLibrary.ts`：`poll()` 认 404 为「任务已不存在」——清 `localStorage`、把 `busy` 复位、
  把 `job` 置空、用 `hint` 与一次 warning 说明「已清除本地记录」，然后**return（不再排下一次轮询）**。
  非 404 的失败仍旧重试，仍旧记进 `error`（瞬时故障不该终止展示）。
- 测试：`__tests__/cve-network-state.test.ts` 新增 2 项（404 清记录并停表、502 保持等待且保留 id）。

### 缺陷二：抓包段刷屏任务监控

**根因（过滤条件依赖了一个可能不存在的字段）**：`default_task_filter()` 只按
`payload['monitor_task_id'] IS NULL` 隐藏抓包段——它假定**每个段都被挂到了监控任务上**。
段的挂链发生在**上传那一刻**（`api/pcaps.py` 的 `ensure_monitor_task` + `attach_segment`），所以
「上传时没有 Running 监控任务」和「挂链存在之前建的行」都会留下**没有链接的段**，它们满足过滤条件，
于是以一条条裸 `pcap` 行出现在任务中心。本机实测：`GET /tasks` 共 94 行，最新的 8 行全是 `pcap`；
库里 76 行段没有链接（`pcap` 共 1685 行）。

- `services/probe_task_service.py::default_task_filter`：默认列表**直接排除 `kind='pcap'`**
  （用 `monitoring.SEGMENT_KIND`，不写字符串字面量），再叠加原来的链接条件。段的可达性不变：
  `kind=pcap`（任务中心的类型下拉里本来就有）仍旧能翻到全部段。
- 实测（本机重启后端容器后）：`GET /tasks` 总数 **94 → 18**，无 `pcap` 行；`kind=pcap` 仍返回
  1261 段；驾驶舱「最近任务」（同一个过滤器）只显示 monitoring/scan/file_source_scan。
- 没有改数据：过滤即修复，76 行历史段原地保留、仍可按类型检索。
- 测试：`tests/test_monitoring_stop.py` 新增 1 项（没有链接的段不出现在默认列表、仍能按 `kind=pcap` 找到）。

### 缺陷三：大屏两张图并列，且看不出数据流向

- `DashboardScreen.vue` 中心列原先**上下堆叠** `TrafficMap` + `GeoMap`，各占一半高度（原注释就写着
  「两张图各占一半，谁也不藏起来」）。现在改成**两个可切换的视图**（`数据流动` / `地理位置态势`），
  默认 `数据流动`，同一时刻只渲染一张图，当前图拿满整列高度。切换状态 `centerView` 与 `metric` 一样
  放在 `composables/useDashboardScreen.ts`，视图不再自己持有状态。
- `components/GeoMap.vue` **在地图上画出数据流动链路**：从内网 hub 到每个目的国家/地区一条曲线，
  **粗细=数据量、颜色=该组敏感等级**，虚线沿 hub→目的地流动（静态线说不出的就是方向），
  悬停给出「内网 → 美国 · 2 主机 · 4.0 KB · L3 高敏感个人信息」。链路按**目的地区分组**画，
  不画主机到主机——服务端 `GET /dashboard/geo-map` 只把目的地址判定到国家，没有主机级坐标，
  画主机连线等于声称一个没人测量过的几何。
- **地球改为朝向数据量最大的境外目的地**：地球只能朝一面，原先固定 105°E，于是 `-98.6°` 的美国
  落在背面被静默丢掉（原代码只 `filter(visible)`，什么都不说）。现在按最大流量目的地定朝向，
  背面剩下的组在脚注里计数（「地球背面 N 组未绘制」），不再无声消失。
- 测试：`dashboard-screen.test.ts` 新增「切换中心列」1 项（两个 tab、一次只渲染一张图、切回、链路数量与
  标题、背面无遗漏）；`dashboard-screen-state.test.ts` 新增 1 项（`centerView` 默认值）；geo/投影用例未改。
  前端 22 文件 / **124 项通过**（原 120），`vue-tsc --noEmit` 无输出。

### 交付与验证

平台版本 3.1.0 → **3.2.0**（`backend/app/main.py`、`frontend/package.json`、`frontend/package-lock.json`），
探针保持 3.7.0，**无新增 Alembic 迁移**。后端全量（容器内）
`pytest --ignore=tests/test_rule_libraries.py`：**29 failed / 980 passed / 5 skipped**
（998 项，本轮新增 2 项）。为了不靠「和上次的数字比」，缺陷五的改动做了一次**同容器 A/B**：
把两个被改文件换回 HEAD 版本跑一次、再换回改动版本跑一次，两次的失败集合 **diff 为空**，
通过数 978 → **980**（正好等于新增的 2 项）——**零新增失败**。ruff 对改动文件无新增违规
（`protocol_service.py` / `protocol_engine/engine.py` 的告警集合与 HEAD 完全相同：
19 E501 + 2 I001 + 1 B905 + 1 F401 + 1 F841）。

**已知遗留（非本轮引入）**：`backend/tests/test_rule_libraries.py` 仍 `from app.api.rules import ...`，
而 `app/api/rules.py` 已在 `8080857` 被删除（该 commit 忘了删这个测试）。它会让 `pytest` 在收集阶段
直接中断，所以全量跑必须带 `--ignore=tests/test_rule_libraries.py`；删除或改写该测试属于另一件事，
本轮只在文档记录，不动它。

### 部署验证中新发现的缺陷四：探针分发包比源码旧

**现象**：`.50` 上把 `filter = "not (host 192.168.110.50 and port 8000)"` 正确写进了探针配置，
`.168` 上真正跑起来的 dumpcap 命令行却**没有 `-f`** —— 探针在录自己的上传，一个 64 MB 段里
`282 192.168.110.168 → 192.168.110.50:8000` 能占满整个段。wlan0 发送 ≈ 21 MB/s，段 30 秒一段、
分析 20 秒一段，**抓包速率永远大于分析速率**，探针 spool 涨到 1.9 GB / 2 GB 上限并进入 degraded。

**根因（构建产物没跟着源码走）**：`probe/probe.py` 的 BPF 支持是 `3d03b18`（09-23 16:36）才加进去的，
而 `probe_packages/probe-3.7.0/arm64/probe.py` 的构建时间是**同一天 08:21** —— 包比源码旧 8 小时。
`probe_packages/` 在 `.gitignore` 里，没有任何东西会在 `probe/` 改动后重建它，于是**源码已经修好、
发出去的包还是旧行为**。这不是探针逻辑错，是发布流程缺一道闸。

**修复**：

- 按 `scripts/build_probe_packages.py --arch=arm64` 重建分发包，确认包内 `probe.py` 带
  `capture_filter_args` 与 `-f`（`sha256 12f6bd79…`，原 `e39afa56…`）。
- `scripts/make_offline_release.py` 新增 `verify_probe_package()` 闸门：把包内 `probe/` 成员与
  `shared/**/*.py` 逐字节（按 LF 归一）与源码比对，不一致就**拒绝出包**并列出是哪些文件。
  闸门放在打 tar 之前——「静默漂移」这类问题只能用类级防御挡。
- 真机复核：重装后 dumpcap 命令行变成
  `-i wlan0 -f not (host 192.168.110.50 and port 8000) -a duration:30 -a filesize:65536`，
  wlan0 立刻回到 ~0.006 MB/s（把自身上传摘掉后，这条链路本来就是闲的）。

### 部署验证中新发现的缺陷五：tshark 的 TCP 重组让分析永远追不上抓包

**现象**：在把自录环断掉之前，`.50` 的 pcap worker 报
`AnalysisTimeout: tshark exceeded 300s timeout`；一个 64 MB 段**光把帧号列一遍就要 200 秒以上**，
149 个段排队等分析。

**根因（一次实测定位）**：段里只有 44 131 个包 / 64 MB，格式完全正常（1 个 SHB + 1 个 IDB +
44 131 个 EPB），所以既不是坏文件也不是磁盘慢 —— 是 **Wireshark 的 TCP 流重组**。同一条命令加上
`-o tcp.desegment_tcp_streams:FALSE`：

| 同一条 10 000 包的段 | 耗时 | `frame.protocols` 里带 http 的帧 |
| --- | --- | --- |
| 重组开（默认） | 48.4 s | 8 |
| 重组关 | **0.8 s** | **9 353** |

原因很直白：这些段里有一条 2 GB 的 HTTP 上传流，重组器**必须把整条流缓冲下来才肯报告任何东西**，
单段成本随流长平方增长；而且它在缓冲期间**不把中间段认成 http**，覆盖率反而更差。
关掉之后逐帧独立判定，HTTP 从 8 帧变成 9 353 帧 —— **性能与覆盖率同向，不是取舍**。

**修复**：只对**不需要重组**的三条元数据通道关掉它（地址、端口、长度、`frame.protocols` 都是逐帧事实）：

- `services/protocol_service.py`：新增常量 `NO_TCP_DESEGMENT`，用于 `parse_pcap`（每段分析的入口，
  就是超时的那一条）与 `protocol_distribution`；
- `engine/protocol_engine/engine.py`：`tcp_streams`（只读 `tcp.len` / `tcp.payload` 的长度）；
- **刻意不动** `app_analysis`（要 `http.request.uri`、`tls.handshake.extensions_server_name`）与
  `pcap_files`（要重组出完整对象）——它们按语义就需要重组，且 `pcap_files` 本来就有
  120 秒 + 文件数/字节数上限。
- 测试：`tests/test_protocol_service.py` 新增 2 项，断言这三条通道的 argv 里带
  `tcp.desegment_tcp_streams:FALSE`。丢掉它是**静默**的：照样返回看起来合理的数据，只是慢到追不上抓包。

## 第四十八批：修复探针抓包「抓空网卡」与「空段拖垮分析队列」（2026-09-23）

用户要求：先修复 → 复核密码评估在检查任务里的位置与展示 → 起新版本 → 推 git →
给本机下发一个持久监控任务（**不能让抓包速率大于分析速率而卡死**）→ 打包发布 release。
本轮把「卡死」的两个真根因都抓出来了，都不是配置问题。

### 根因一：探针抓在了一块没插网线的网卡上

preflight 用 `ls /sys/class/net` 列出所有非 lo 名字，`capture_interface_for` 取**第一个非虚拟**的。
真机 `enp1s0`（网线未插，`operstate=down`、无地址）排在 `wlan0`（`UP`，192.168.110.168/24）前面，
于是探针被派去抓一块**永远没有流量**的网卡：部署记录是 `ONLINE`、心跳正常、段也在上传，
表面上一切正常，只有「永远没有内容」这一个症状。

- `deployment/preflight.py`：新增 `operstate` 探测，`interfaces` 只给**内核报告为 up** 的非 lo 网卡；
  完整清单另存 `all_interfaces` 供控制台展示（死网卡仍然看得见，只是不会被选）。驱动把 operstate
  报成 `unknown` 的主机（部分虚拟/无线栈）回退到全部非 lo 名字，不会因此 preflight 失败。
- `deployment/service.py`：`capture_interface_for` 文档补上「候选已按 up 过滤」的契约。
- 测试：`tests/deployment/test_runtime_preflight.py` 新增 2 项（死网卡不被选中 + 运维显式选择优先、
  虚拟网卡跳过、无候选回落 `any`）。

### 根因二：一个空抓包段会占用 60 秒分析时间，而且永远清不掉

段里**零个数据包**时仍然跑全部引擎。Suricata 对读不出包的 pcap **不是快速失败**：它耗尽自身 ~60 秒
启动预算，然后抛 `failed to get first packet timestamp`。两件事同时发生：

1. 这个异常从 `EngineRegistry.run` 冒出去，**中止整段分析**，段记录停在 `pending` 永不落地，
   而 pcap worker 的槽位被占满 60 秒 —— 抓包 30 秒一段、分析 60 秒一段，**积压必然无界增长**；
2. 安静窗口（或抓空的网卡）每 30 秒产出一个这样的段，于是「越积越多直到卡死」。

真机实测坐实：探针 8 四十分钟内 `pending` 段从 7 涨到 **75**，`tasks.kind='pcap'` 里 583 条 Failed，
6 条卡在 Running。

- `workers/analysis_tasks.py`：`analyze_pcap_task` 在跑引擎前判断 `parsed["packets"]` 为空 ——
  零包不可能是证据，写一条 `capture` 模块的 AnalysisResult（中文说明「空抓包：该时间窗口内未捕获到
  任何数据包」）后直接收尾，不再付引擎的钱。
- `engine/core/registry.py`：**引擎隔离** —— 单个引擎抛异常只记 warning、把失败挂到
  `context.data["engine_errors"]`，其余引擎照常产出；pcap 任务把 `engine_errors` 落成
  `engine_error` 模块的 AnalysisResult（**盲区要看得见，不能读成「干净抓包」**）。
- 测试：`tests/test_empty_capture_analysis.py`（上传真实 dumpcap 空段字节 → `analyzed` + `capture`
  结果 + 无 `engine_error` + 任务 Success）、`tests/engine/test_core.py` 新增引擎隔离用例。
  空段字节取自真机产物，存为 `tests/fixtures/generate_empty_capture.py`（272 字节，注释写明来源）。

### 根因三：死掉的分析任务与「已被回收却仍显示 pending」的行

worker 在分析中途被杀（重启/OOM/第三方二进制不返回）时没人写终态：任务行永远 `Running`、
段记录永远 `pending`，控制台于是显示一个「永远排不完的队列」。另外存储护栏删**文件**保留行
（`pcap_storage.release`），却没动 `analysis_status`，被回收的段也读成「等分析」——本轮实测
**208 行** 这样的幻影积压（65 MiB/段、`retention_status=retained_analysis`、文件已不在）。

- `services/pcap_storage.py::release`：删文件同时把仍是 `pending` 的段标成 `evicted`
  （已 `analyzed` 的不动，保留它的结论）。
- 新增 beat 任务 `security_toolbox.sweep_stale_analyses`（60 秒，
  `workers/maintenance_tasks.py::sweep_stale_analyses_task`）：`Running` 超过 900 秒的任务判为
  `Failed`（写明「分析未在预期时间内完成，已判定为中断」），其段记录 `pending → failed`；
  同时把历史上「已回收仍 pending」的行收成 `evicted`。
- 测试：`tests/test_stale_analysis_sweep.py` 3 项、`tests/test_storage_guard.py` 新增 1 项。

### 根因四：两条流量规则几乎在**每一段**上都报，且是同一类错误

把空段问题修掉、探针 9 真正抓到内容之后，新的段立刻开始产出成片的「端口扫描 / 高包速率」——
这一批才是「误报严重」的主因。两条规则各错在一次**度量口径**上，且都在两个产出者里各写了一遍：

- **`NETWORK_PORT_SCAN`（滚动状态，High，27 条）**：`RollingTrafficState` 只按**源地址**建键、
  直接数 `dst_port`。抓包流是**单向**的，DNS 服务器的应答是
  `114.114.114.114:53 → 客户端:临时端口`，一个客户端一条流、目的端口各不相同——
  于是**每台繁忙服务器在每一段里都被判成在扫描它自己服务的网**。改为按
  `(probe, src, dst)` 建键、用 `traffic_scope.service_port()` 取**服务侧**端口，引擎按 `(src, dst)` 对遍历；
  `dedup_key` / `seen()` 一并带上 `dst`。
- **`NET_RATE_001` 与遗留 `high_packet_rate`（Medium，各 38 条）**：都是
  `packets / max(span, 0.001)`，**只有一个包的会话**（span=0）算出 **1000 pps**，
  直接越过 `packet_rate > 500`。凡是段里出现一个单包会话就报一次 = 几乎每段都报。
  改为共用 `traffic_scope.conversation_rate()`，跨度下限 **0.05 秒**：单包读 20 pps，
  1000 包/10 ms 仍是 20000 pps。两条产出者从此不可能对不上口径——它们本来就是同一个异常的两次上报。

### 存量清理：只清「指标口径已被改掉」的三条规则

`POST /admin/findings/purge-false-positives` 的 `rules` 参数语义是「运维已确认该规则把指标描述错了」，
所以只清本轮**改过口径**的三条：`NETWORK_PORT_SCAN` + `NET_RATE_001` + `high_packet_rate`。
先 `dry_run=true` 对齐（119 finding / 0 alert / 0 detection），再实删：**删除 119 条 finding + 6 条级联告警**。
**刻意不清 `NET_SCAN_001`**（5 条）：它的 `port_count` 走 `_busiest_port_window`，本来就是
「按 `(源,目的)` 对 + 服务侧端口」的口径，本轮没动它——按行证据判定它仍然成立，清了才是误删。

### 仍未解决的误报（本轮只记录，未改码）

清理后仍在产出的是**探针主机自己的流量**：`192.168.110.168` 既跑平台、又跑平台发起的 nmap/nuclei
扫描（nuclei 命中的 `host` 就是 `192.168.110.168`），探针又恰好在自己的 wlan0 上抓包，
所以「本机扫本机 / 本机对外开连接」会变成本机被扫描的 finding
（例：`192.168.110.168 → 43.199.29.225` 60 秒内 38 个服务端口）。这不是度量算错，是**范围**问题；
平台已有的正解是 `DLP_SELF_ENDPOINTS`（`services/dlp/self_traffic.py`，`filter_flows` 会在任何指标之前丢弃
命中行）。把它配上会同时屏蔽该主机的其余流量，属于**运维取舍**，因此没有替用户默认打开。
另有一条**待决策项**：同一异常有 YAML 与遗留两套产出者（`NET_SCAN_001` 与内置 `NETWORK_PORT_SCAN`，
标题都是「端口扫描」），同一台主机各报一遍。

**测试与证据**：全量后端 **34 FAILED 与 HEAD 基线逐条一致**（另 2 个既有 collection ERROR 同样复现），
passed 897（本轮流量修复新增 5 项用例：`test_traffic_state` +2、`test_traffic_scope` +3）；
新代码 ruff 0 违规（改动文件只剩原有存量 E501，逐个与 `git show HEAD:` 的 HEAD 版本比对、
未新增任何违规）。无 Alembic 迁移。

### 密码评估复核（不改码）

「密码评估」只在**检查任务（单次）**向导里出现（`wizard.cryptoAssess`，`taskType==='inspection'`，
顶层 `TaskCenter.vue` 第 502 行），下游一路通到 `workers/analysis_tasks.py` 写
`summary["crypto_profiles"]` / `["crypto_profile_hosts"]`；**展示位置在任务中心详情抽屉**
（`TaskCenter.vue` 第 342 行 `<CryptoAssessmentPanel>`），不是独立页面。真机复核任务 1355
（`POST /scan` target=192.168.110.168 + `crypto_assess=true`）：`Success`，
`crypto_profile_hosts=1`，`crypto_profiles` 正常返回。**结论**：流程内有、界面上有，
按用户「如果没有展示才在资产中心新建页面」的条件，本轮不新建页面。

## 第四十七批：执行误报治理 1–5、清掉存量误报并复核（2026-09-23）

第四十六批把误报的**根因**堵住了，但清理计划（五层）只写了方案、一条没执行；用户要求“执行 1-5”，
并在执行后**分析全部检查记录、给出误报的解决方案**。本轮把五层全部落到代码上，并真正清掉存量。

### 五层（全部落码）

1. **清存量**：扩展 `services/finding_hygiene.py` 的清理判定，`POST /admin/findings/purge-false-positives`
   新增两个**运维显式声明**的入口，语义与既有的 `addresses` 一致（空列表不匹配任何行、不做任何推断）：
   - `roots`：平台自己的存储树（`/app/data/storage` 下的 pcap 与上传池）。命中这些路径的文件证据
     描述的是**检查器自己**，不是甲方数据——`DATA_YARA_001` 382 条全部命中的是平台自己 65 MiB 的 pcapng。
   - `rules`：运维已确认“指标写错了”的规则 id（见第 4 层）。**判定不变**：只有当现行规则集**不会再产出**它时才删；
    仅是严重度错配（如 Zeek weird 降级）**不算**，因为现行规则仍会产出它。
2. **入库闸门**（`services/detection_gate.py`，新）：不再相信探针自报的置信度，入库时按**平台当前规则**重算。
   `regex`/`validator` 两类证据取规则自身精度；其余（`keyword`/`field_name`/上下文词）**封顶 0.5**，
   低于 0.6 告警线、只作证据。接不进类别/无证据的**不做裁剪**（规则被删 ≠ 值有错）。
   接入 `services/data_objects/evidence.py`（`_merge_detection` 改返回 `Detection | None`）、
   `data_objects/ingestion.py`、`database_scan/ingest.py`：判不下来的类别进 `candidate_categories`，
   **仍然可见、只是不再单独定案**。
3. **规则包收敛**（`services/rule_library.py`）：Presidio 导入时记录 `rule_confidence`（纯数字规则封顶），
   `enabled` = `confidence >= MIN_ALERT_CONFIDENCE` 且是敏感实体；新增 `enabled_by_analyst` 标记——
   运维手工开关过的规则**保留其选择并重新打标**，不会被下一次导入覆盖。
4. **回放与噪声报告**（`services/rule_noise.py`，新）：`GET /dlp/rules/noise` 按规则给出
   `detections`/`evidence_rows`/`unconfirmable_rows`/`findings`/`alerts`/`noise_ratio` 与
   `known_rule`/`alertable`/`platform_confidence`，全部是既有行的聚合、只读；`POST /dlp/rules/{id}/replay`
   对某条规则**已存的原文**做只读重放（现行规则+validator），未知 id 返回 404。
5. **扫描范围护栏**（`services/scan_scope.py`，新）：探针安装树（`/opt|/etc|/var/lib/data-security-toolbox`）
   永久排除——`queue_probe_data_asset_job` 下发前把它并进 `exclude_paths`；显式 include 落进这棵树**直接 400**
   （`api/error_handlers.py` 接 `ScanScopeError`），不返回“已完成”的空扫描。排除随任务 payload 下发，一处可见。

### 根因修复（本轮新增两处）

- **YARA 口令规则过匹配**（`app/rules/data/sensitive.yar`）：`$password = /password\s*[=:]\s*[^\s]+/`
  的 `[^\s]+` 会在**任意捕获字节**里匹配——平台自己的 pcapng 上传被读进来，`DATA_YARA_001` 因此产出
  **382 条全部误报**。改为要求行内形态（`\b(password|passwd|pwd)\b[ \t]*[=:][ \t]*[!-~]{8,120}` 且**行尾**）、
  ASCII、`filesize < 20MB`；`$secret` 扩充 `api_key`/`access_key`/`private_key`，provider token 前缀独立成 `$provider`。
  **YARA 4.5.4 不支持非捕获组 `(?:…)`，只能用捕获组**（本轮踩过）。二进制噪声样本现不再命中，真实配置行仍命中。
- **Zeek weird 一律 High**（`integrations/zeek/adapter.py`）：`bad_HTTP_request` 是**解析器自身的限制**
  （客户端连到代理/非 HTTP 端口），却被判 High/0.8 越过告警线——单台被监控主机产出 **102 条 High + 82 条告警**。
  改为按名字定级：`bad_http_request`/`http_unknown_method`/`dns_question_too_long` → Low（只留证、不告警），
  `ssl_invalid`/`ssl_self_signed` → Medium。

### 真机执行（真实删除，全部带审计）

先 dry-run 对齐再执行，三条命令合计 **删除 2497 条 finding、54 条告警**，`detection_findings` 3013 → **516**：

| 命令入参 | dry-run | 实删 findings | 实删 alerts |
| --- | --- | --- | --- |
| `{"roots":["/app/data/storage"]}` | 382 | 382（`DATA_YARA_001`） | 4 |
| `{"rules":["NET_RATE_001","NET_BROAD_001","NET_SCAN_001","NETWORK_PORT_SCAN"]}` | 1275 | 1275 | 50 |
| `{"rules":["high_packet_rate","broad_communication"]}` | 840 | 840 | 0 |

**第 4 层暴露的一处事实**：同一类网络异常有**两套并行的产出者**——YAML 规则（`NET_SCAN_001`/`NET_BROAD_001`/
`NET_RATE_001`）与遗留的 `services/traffic_service.py`（`NETWORK_PORT_SCAN`/`broad_communication`/
`high_packet_rate`），rule id 不同、同一台主机各报一遍（`192.168.110.168` 同时出现在两族里）。三条删除命令
因此必须覆盖两族，否则只清一半（本轮第一遍就只清了第一族，第二遍才发现剩余 840 条）。

**清理后**剩余 top：`ZEK_WEIRD_001` 102 / `NUCLEI_http-missing-security-headers` 80(Low) /
`SURICATA_DNS_ERROR_001` 54(Low) / `ZEK_HTTP_UA_001` 48(Medium) / `DLP_TRANSFER_001` 38，
均为单条个位数量级的真实低危项；`SD_*`（DLP 数据规则）`noise_ratio` 已降到 0–0.4，`SD_EMAIL_001` 278 条检测
只剩 1 条不可确认。

### 误报的解决方案（回答用户“给出解决误报严重的解决方案”）

**先分类，再分别用不同手段**——把“误报”当成一件事修，只会把漏报换进来：

| 误报类型 | 本轮实例 | 手段 |
| --- | --- | --- |
| 规则**按错误指标**判定（方向、整段聚合） | 端口扫描/大范围通信/包速率 | 修指标本身（第四十六批 `traffic_scope`），存量按 `rules` 清 |
| 规则**过匹配**（字符类落在任意字节上） | `DATA_YARA_001` 382 条 | 收紧模式 + 限定文件形态，存量按 `roots` 清 |
| **严重度错配**（解析器限制当成攻击） | `ZEK_WEIRD_001` 102 条 | 按证据名定级，**不删**（事件真实发生，现行规则仍会产出它） |
| **第三方代码**里的敏感形态 | 954 条检测中的 403 条 | 采集范围默认排除依赖/VCS 目录，存量按 `path_excluded_by_scope` 清 |
| 探针**自报置信度**不可信 | 331 条瑞典组织号 | 入库闸门按平台规则重算，低于线只留证 |
| **扫自己** | 安装树里的 `password = …` | 下发前并入 `exclude_paths`，显式 include 直接 400 |

**三道防回流的机制**：① 入库闸门（第 2 层）——以后探针再报过匹配也不进 Finding；② 噪声报告 + 回放（第 4 层）
——运维可随时看“哪条规则最吵”，并对已存原文重放验证；③ 精度回归基线（`tests/test_false_positive_baseline.py`）
——把“这些样本不应产出 finding”固化进测试，改规则时回归。

### 验证与测试

- 新增 `tests/test_detection_gate.py`(6)、`test_rule_pack_curation.py`(5)、`test_rule_noise.py`(6)、
  `test_false_positive_baseline.py`(8)、`test_credential_yara_precision.py`(3)；`test_finding_hygiene.py` 4 → 6
  （`roots`、`rules` 各一），`tests/integrations/test_zeek.py` 新增 weird 定级用例；
  `test_data_objects.py`/`test_data_asset_probe_api.py` 随闸门与范围护栏更新。
- 全量后端 **34 FAILED，与 HEAD 基线逐条一致**（另 2 个既有 collection ERROR 同样复现），
  passed 878（较基线 +2）；`ruff` 对新增/改动行负责，新代码 0 违规（`rule_library.py` 存量 E501 反而少一条）。
- **无 Alembic 迁移**：本轮不新增表/列，`enabled_by_analyst` 存在既有 `file_sources.limits` JSON 里。

### 待办

- incident 由 `POST /incidents/rebuild-attribution` 重算——**本构建没有该路由**（`api/incidents.py` 已在
  `8080857` 随页面删除），`1275+840` 条 finding 删除后留下 **116 条挂在 incident 上的告警**（`finding_id` 为空）
  指向已重算的旧事件链，待恢复该路由或补一条维护端点后重算，**不凭空造数**。
- `ZEK_WEIRD_001` 存量 102 条仍是 High（现行规则会产出，只是 Low），重跑分析才会按新定级落库；
  本构建没有“重算严重度”的路径，暂不处理。

## 第四十六批：存储护栏 + 抓包平衡点 + 历史误报清理（2026-09-23）

用户要求三件事：① **解决存储问题防止卡死**；② 找一个**抓包分析的平衡点**，兼顾性能、存储与覆盖率；
③ **分析全部检查记录**，解决目前严重的误报。第①③两项本轮都落到了代码上（第四十五批只做了诊断）。

### ① 存储护栏：能不能写，先看数据分区还剩多少

新增 `services/storage_guard.py`（水位）与 `services/pcap_storage.py`（腾空间 + 保留策略），两套判断都
**以 `STORAGE_DIR` 真实所在分区为准**（平台数据是 bind mount，通常不在 `/` 上——第四十五批就是只盯 `/` 才漏掉）。

- **发布前先看得到**：`/api/v1/health` 新增 `storage` 块（分区路径/总量/已用/可用/百分比、`floor_bytes`、
  `state`、`ingest_blocked`）。实测容器里 `/app/data/storage` → 宿主 `/home`（`/dev/sdd5` 296 G）。
- **两道界**：`PCAP_STORAGE_MAX_GB`（硬上限，此前只在 `/health` 展示、无处执行）+ **保留下限**
  `max(PCAP_STORAGE_MIN_FREE_GB=5 GiB, PCAP_STORAGE_MIN_FREE_PERCENT=10%)`。
  取两者较大值：小盘靠绝对数兜底，大盘靠百分比。
- **低于下限就拒收**，返回 `429` + `Retry-After: 60` + 中文原因（`数据分区 … 剩余 … MB，低于保留下限 …`）。
  `pcaps/upload` 与 `files/upload` 两条采集入口走同一个 `api/dependencies.py::enforce_queue_backpressure`
  （不复制守卫）；该磁盘检查**刻意放在 `app_env == "development"` 短路之前**——只会在生产生效的护栏，
  第一次真正生效就是出事那天。文件上传此前完全不设防，本轮一并纳入（它同样写数据分区、同样建分析任务）。
- **腾空间只删文件、保留行**：按 id 最旧优先，删完把行置 `retained_analysis`（`/health`、发现与告警仍能
  指着这条记录说“载荷已删除”）。**有未关闭告警/事件的分段排最后**，只有越过保留下限（`critical`）时才动它们。
- **60 秒 beat** 新增 `enforce-pcap-storage-cap`（`cleanup_pcap_retention` 是小时级，太慢，挡不住
  探针每 30 秒一段的写入）。
- **真机结果（本轮实测）**：起效前 `state=critical`（可用 18.09 GiB < 下限 29.58 GiB），上传被拒；
  一次 sweep 后 `/home` 从 19 G 可用回到 **31 G 可用**（平台数据 37.97 → 25.51 GiB，释放 **12.46 GiB**），
  `state=warning`、`ingest_blocked=false`、上传恢复 `200`；**102 段持有未关闭事件的分段 102/102 全部保留**，
  删掉的 502 行全部是无未关闭事件的最旧分段，行一条未删（750 行不变）。

### ② 抓包平衡点：30 秒 / 64 MiB + 不抓自己

- **不再写死 `interface = "any"`**：`deployment/service.py::capture_interface_for()` 按 preflight 拿到的
  真实网卡选第一个**非虚拟**网卡（排除 `docker*`/`br-*`/`veth`/`virbr`/`tun`/`tap`/`lo`），
  同机部署的“自己抓自己上传、真实流量为零也停不下来”回路从源头拆掉；运维显式指定则尊重运维。
- **新增采集期 BPF**：`capture_self_filter()` 生成 `not (host <平台地址> and port <平台端口>)`，
  探针 `probe.py` 新增 `capture.filter` 配置项并加到 `dumpcap -f`（`tcpdump` 走尾部参数），
  **用 `shlex.split` 传 argv、不过 shell**。过滤器在写盘前生效——没写进文件的段不占磁盘、不上传、不分析，
  这才是真正省资源的排除。渲染实测：`interface = "eth0"` / `segment_seconds = 30` /
  `segment_max_mb = 64` / `filter = "not (host 192.168.110.168 and port 8000)"`。
- **为什么是这个平衡点**：一段 64 MiB ≈ 30 秒；分析侧 `pcap-worker` 2 并发实测约 5.8 s/段。段切得太小，
  段数与上传/元数据/任务开销按比例涨；切得太大，单段分析延迟与失败重跑代价都变大，还更容易撞上
  文件大小上限而**按大小而不是按时间切段**（第四十五批 321 段全是这样，30 秒窗口名存实亡）。
  保留 30 s / 64 MiB，另加“不抓自己”把无效流量直接去掉，覆盖率不降、写入量大幅降。
- 运维可覆盖：`POST /probe-deployments/preflight` 新增 `capture_interface` /
  `capture_segment_seconds`(5–3600) / `capture_segment_max_mb`(1–4096)，网卡名做了引号/换行/NUL 校验。

### ③ 严重误报：先堵根因，再清存量

**根因（新增 `services/traffic_scope.py`，被 `rules/interpreter.py`、`services/traffic_service.py`、
`engine/traffic_engine/engine.py` 共用）**

- **方向**：抓包流是**单向**的，DNS 服务器的应答长这样 `114.114.114.114:53 -> 客户端:33209`，每个客户端一条流。
  按“源地址的不同目的端口数”统计，等于把**每台繁忙服务器都判成端口扫描器**——179 条 `NETWORK_PORT_SCAN`
  就是这么来的。现在按 `(源, 目的)` 对计数，并只在**服务侧端口**上计数（`service_port()` 取 ≤32767 的一端），
  证据里补上 `dst`。127.0.0.1 / 172.23.0.2（docker 网桥）被报成扫描也是同一原因。
- **范围**：特殊用途网段（`127/8`、`169.254/16`、`224/4`、`0.0.0.0`、`::1`、`fe80::/10`、`ff00::/8`）
  与平台自身管理端点（复用 DLP 的 self-endpoint 解析）在**算任何指标之前**就丢掉。
  注意：`172.16/12` 是合法私网，**不能**默认丢，要运维显式配（有测试钉住这一条）。
- **纯数字规则**（`services/rule_library.py`）：非人工规则且 pattern 只能匹配数字与分隔符 → 精度上限
  `0.5`（低于 0.6 告警线）。`\b\d{6}[-]?\d{4}\b`（瑞典组织机构号）在 `.bash_history` 里命中时间戳
  `1376524890`、在 `xlsx` 里命中学号，一条规则就产出 331 条检测 / 3194 次命中。规则保留作证据、不再单独定案；
  **运维手写的规则不受限**；带 validator 的规则不受影响（内置手机号/银行卡仍确认，有测试）。
- **口令赋值**（`shared/sensitive_detection/validators.py::validate_secret_value`）：`password: bytes,`、
  `password = str(password)`、`password[:127]` 这类**源码**形态直接拒绝；纯数字给 0.5、
  无数字的裸词给 0.4/0.55（只留作证据）。这些此前全部按 **L4/Critical** 上报。
  **顺带修掉一个真 bug**：引擎交给 validator 的是**整段匹配**（不是捕获组），
  所以必须先把“关键字 + 分隔符”剥掉再判取值——否则 `password: _PasswordType` 仍会以 0.9 确认。
- **采集范围**（`services/file_scan/`）：新增默认排除 `node_modules`/`site-packages`/`.git`/`__pycache__`/
  各类依赖缓存（954 条检测里 **403 条**来自第三方代码）；**刻意不排除** `dist`/`build`/`bin`/`target`/`obj`
  ——这些名字在甲方自己的目录里很常见且可能放真配置，静默跳过等于把误报换成漏报，由运维按源自行添加。
  排除表存在 `file_sources.limits` 这列 JSON 里（**不动已发布迁移、不加新列**），下发时冻结进任务快照；
  被排除的目录单独记 `excluded_paths`/`excluded_count`，不把“范围决定不看”混进“覆盖率缺口”。
- `app/rules/network/broad.yaml`：条件由 `total_bytes > 10000000` 改为 `dst_bytes > 10000000`
  ——前者在 64 MiB 的分段上**恒真**（485 条 `NET_BROAD_001`）。

**存量清理**：新增 `services/finding_hygiene.py` + `POST /api/v1/admin/findings/purge-false-positives`
（`dry_run` 默认 `true`，写入审计）。判定只用**行自己记录的**东西（规则 id、命中值、采集路径、证据里的地址）：
哪些按现行规则/范围**不再成立**。规则被运维删掉、主机不见了**都不算证据**，不做任何推断。

**真机 dry-run（地址 `172.23.0.0/16` + `127.0.0.0/8`）**

| 桶 | 条数 | 样本 |
| --- | --- | --- |
| `validator_rejects_stored_value` | 6 | `password:{type:"String"},disabled:{...}`（压缩 JS）、`password={{r2}}`（xray yml）、`apikey: apiKeyGen(doc` |
| `rule_below_alert_confidence` | 218 | `se_organisationsnummer` 命中 `.bash_history` 的 `1376524890`、`.claude.json`、学号 `2023312349` |
| `path_excluded_by_scope` | 411 | `xray-plugins/.git/config` 的 `git@github.com`、`.git/logs/HEAD` 的时间戳 |
| `detection_findings`（地址在 `172.23/16`、`127/8`） | 866 | `NETWORK_PORT_SCAN`/`NET_BROAD_001` 等，命中 docker 网桥与回环 |

合计**待清 635 条检测 + 866 条 finding**（顺带删掉指向这些 finding 的告警；`alerts.finding_id` 没有级联删除，
模块里显式删）。**本轮只跑了 dry-run，没有执行删除**——这是不可逆的生产数据操作，等确认。
另外修掉一处归因缺陷：原先 validator 拒绝的条目也记进“低于告警线”桶，现在按真实原因分桶。

### 验证与测试

- 新增 `tests/test_traffic_scope.py`(7)、`test_storage_guard.py`(6)、`test_rule_confidence.py`(4)、
  `test_file_scan_exclusions.py`(6)、`test_finding_hygiene.py`(4) 与 2 个 shared 用例，共 **29 项全过**；
  `tests/conftest.py` 把 `PCAP_STORAGE_MIN_FREE_GB/PERCENT` 固定为 `0`——磁盘水位是**机器的属性、不是代码的属性**，
  否则宿主机盘满时 ingest 测试会因磁盘状态而红，而不是在测它该测的路径（本轮就是这样暴露出来的）。
- 全量后端测试 **34 FAILED，与 HEAD 基线逐条一致**（另有 2 个既有的 `app/` 模块被误收集的 ERROR，
  在 HEAD 树上同样复现），未新增回归。`ruff` 只对新增/改动行负责，本轮新代码 0 违规
  （`interpreter.py`/`traffic_service.py` 的存量 E501 反而各少一条）。
- **顺带修掉一个性能坑**：sweep 原先对**每条分段**全表扫一次 incident 表，452 段要跑 ~5 分钟，
  而 beat 是 60 秒一次。改为一次性取 `open_case_pcap_ids()` + 用 `freed` 累计替代每删一个文件就重走一遍
  整个存储树，实测 **~1.0 秒**（`open_case_pcap_ids` 0.06 s + `_ordered_candidates` 0.04 s + `stored_bytes` 0.93 s）。

### 待办

- **误报清理尚未执行**（见上表），确认后执行：`POST /api/v1/admin/findings/purge-false-positives`
  `{"dry_run": false, "addresses": ["172.23.0.0/16", "127.0.0.0/8"]}`；incident 由
  `POST /api/v1/incidents/rebuild-attribution` 重算，不凭空造数据。
- 本轮改动**尚未提交**。本机现在没有探针（第四十五批已回收），复测前需重新下发一个；
  下发后应复核 `probe.toml` 里确实是 `interface = "eth0"` + `filter = "not (host … and port …)"`。

## 第四十五批：本机装探针做全链路实测（2026-09-23）

用户要求：提交后在本地用最新版跑起来、在本机注册一个探针、看功能是否正常，以及**会不会抓包速度大于
分析把系统卡死**。结论：功能链路全通；**抓包确实远快于分析**，而且本机上探针抓的是自己的上传流量，
形成自持回路，实测把 `/home` 写到 0 字节可用——已处置。**探针已按平台自身流程回收，本机现在没有探针。**

**本地最新版**：用 legacy builder 重建 `source-backend` / `source-worker`（api 与 analysis-worker）/
`source-frontend` 三个镜像后 `--force-recreate` 起栈，并补上 **`pcap-worker`**（`docker-compose.yml` 里
的服务，之前仍是 5 小时前的旧镜像）。`alembic current` = `0019_policy_group_fingerprints`（head），
新增的 `/dashboard/geo-map`、`/asset-instances/{id}/risk-points`、`/asset-instances/{id}/download` 都已注册。

**三处新功能真机复核（都是真实数据）**

- 风险点：`GET /asset-instances/2988/risk-points` 直接给出规则 `SD_ID_CARD_001`、等级 `L3`、
  命中值 `370923193604180032` 与上下文——「能直接看到风险点」成立。
- 掩码浏览：`/content` 默认返回 `masked=true / masked_values=2`，实测把 `1510101003` 换成 `15***03`；
  `?mask=false` 才给原文。
- 下载：`/download` 回来的文件与源文件 **sha256 一致**（`41623db6…`，6636 字节），走的是部署里配置的
  SFTP 通道取回，不是容器本地路径。
- 大屏：`/dashboard/geo-map` 返回真实分组（内网 22 主机 / 国内 324 / 境外 323 / 未识别 12）。

**探针下发（走的平台自己的流程，凭据不出容器）**

`POST /probe-deployments/preflight` → `POST /probe-deployments`（host `192.168.110.168`、root、
profile `standard`、回连 `http://192.168.110.168:8000`）。preflight 四项全过（root、bundled python 3.11.16、
`dumpcap`、回连连通）。10 秒内 `ONLINE`，systemd 单元 `data-security-toolbox-probe` 跑起来，
进程为 `/opt/data-security-toolbox/runtime/... python3.11 probe.py` + 自带的 `dumpcap.elf -i any
-a duration:30 -a filesize:65536`，`/probes` 出现 `本机功能验证探针`。第一段 pcap 上传后
**7.55 秒**就分析完并产出告警（`deliver_alert` 连着跑），链路（采集→上传→分析→发现→告警）全通。

**「会不会抓包大于分析卡死系统」：会，而且本机是特例中的特例**

- 15 分钟内上传 **321 段、20 GB**（1 段 / 2.8 秒，全部顶到 64 MiB 的文件大小上限，说明不是 30 秒切一段
  而是被大小切段）→ 采集约 **22 MB/s**。
- 这 22 MB/s 里 **96% 是探针自己的上传**：`flows` 里 `192.168.110.168 → 172.23.0.7`（`172.23.0.7`
  就是 backend 容器）占 7376 MB 中的 7079 MB；真实外网只有 5 MB 量级（221.204.163.76 等）。
  根因是部署写死的 `interface = "any"`（`deployment/service.py::build_probe_toml`，
  且 `capture_interfaces()` 在 Linux 上把 any 直接翻成 `['any']`），而探针与平台同机、上传走 docker 网桥，
  于是**每一段 pcap 都被抓进下一段**，形成自持回路，真实流量为零也停不下来。
- 分析侧：`pcap-worker` 并发 2，本次平均 5.8 秒/段 ≈ 21 MB/s，与采集速度基本持平但方差大，
  实测待分析积压一路涨到平台阈值 **200**（`QUEUE_PENDING_MAX`，`api/dependencies.py::enqueue` 的
  `enforce_queue_backpressure`），到 200 后**上传被拒、积压开始回落**——这层保护是有效的。
- **磁盘才是真正的卡死点**：`PCAP_STORAGE_MAX_GB=100` 只在 `/health` 里**显示**（`api/health.py:134`），
  没有任何地方执行；真正删文件的只有 `cleanup_pcap_retention`（7 天保留，且**有未关闭告警/事件的行标
  `extended` 永不删除**）。实测 15 分钟平台存储 38 GB → 46.5 GB，而平台数据在 **`/home`（`/dev/sdd5`，
  296 G，已用 280 G）**，不是根分区——`df /` 当时显示 69% 很健康，`/home` 却被写到了 **0 字节可用**。
  发现后立即回收探针（`POST /probe-deployments/removal`，`delete_record=true`），并清掉本批自己产生的
  321 段 pcap 文件（行保留、置 `retained_analysis`，其中有未关闭告警的 23 段按平台语义标 `extended` 保留），
  **释放 18.2 GB，`/home` 回到 19 GB 可用**；平台 `/health` 恢复正常，探针卸载干净
  （`/opt`、`/etc`、`/var/lib` 与 systemd 单元都不在，只留下安装前就存在的 `dstprobe` 账号）。

**结论与建议（未改代码）**

1. **平台主机上不要用 `any` 跑抓包探针**（尤其是同机部署）：要么只抓物理网卡，要么给采集加一条排除平台
   自身端点的 BPF（探针目前没有 BPF 配置项），要么这台机器用 `profile = lite`（关采集）。
2. `PCAP_STORAGE_MAX_GB` 要么真正执行（超限按最旧优先删），要么在文档里明确它只是展示值；
   7 天保留 × 22 MB/s ≈ 13 TB，与 296 GB 的 `/home` 差两个数量级，容量必须先算。
3. 监控要看**存放真实数据的分区**（这里是 `/home`），只看 `/` 会漏掉这类事故。

## 第四十四批：风险文件直读 + 大屏地理态势 + 密码评估回到扫描流程（2026-09-23）

用户要求三件事：① 风险文件要能直接看到风险点，`浏览原始文件` 改为 `下载原始文件`，浏览默认走掩码、
需要时才手动看全部；② 数据大屏用地图展示内网/国内/境外，中国地图 + 地球，颜色区分数据敏感等级；
③ 把历史版本里的密码评估找回来，并放进扫描流程。三件都已落地，未提交。

**① 风险文件（`api/data_catalog.py`）**

- 新增 `GET /asset-instances/{id}/risk-points`：按实例聚合命中的检测行，返回每条风险点的
  **命中字段/规则/等级/计数**，以及 `text`（命中的原文片段）——「能直接看到风险点」就是这一段，
  列表行同时补 `risk_point_count` / `risk_hit_count` 两列，不点开也能看出这个文件有几处风险。
- `GET /asset-instances/{id}/content` 默认 `mask=true`：命中值在服务端被替换成掩码（`services/masking.py`），
  响应带 `masked` / `masked_values` 说明「这份内容是打过码的」；`mask=false` 才是显式的「看全部」。
  掩码只作用于**规则真正命中过**的值，没命中过的内容不会被顺手抹掉（否则原文会失真）。
- `GET /asset-instances/{id}/download`：整份文件回给浏览器（临时目录 + `FileResponse` +
  `BackgroundTask(shutil.rmtree)` 兜底清理），前端 `浏览原始文件` 按钮随之改为 `下载原始文件`。
  非 `file-source:` 归属的实例（探针上报的文件）没有可回读的本机路径，返回 409 `not_retrievable`
  并说明原因，而不是给一个空文件。
- 回归：`backend/tests/test_risk_files.py`（4 例：风险点带命中原文 + 列表计数、非可回读来源给 409、
  浏览默认掩码直到显式要全部、下载回整份文件）；前端
  `frontend/src/__tests__/risk-files-state.test.ts`（5 例）。实现拆在
  `frontend/src/api/riskFiles.ts` + `modules/data-security/composables/useRiskFiles.ts`，
  `evidence/RiskFiles.vue` 只留模板。

**② 数据大屏地理态势（`GET /dashboard/geo-map`）**

- 后端新增 `services/region_geo.py`：离线**国家表**（238 个 ISO 国家码 → 中文名 + 近似标签点）。
  没有这张表就判定不出境外，响应里的 `country_table_present=false` 会如实说明，**不会**把未知说成境内。
- `api/dashboard.py` 新增 `GET /dashboard/geo-map?limit=24`：按**目的地址**聚合已完成分析的会话，
  经 `egress_regions.classify` 分成 `internal`（本企业私网）/ `domestic`（境内）/ `overseas`（境外）/
  `unknown`（未命中地区表，单列为「未评级」，**不计入境外**）。每组的颜色是组内**最严重**的敏感等级
  （`Detection.instance_id → AssetInstance.owner_key → Probe.ip_address` / `FileSource.host`），
  主机数/字节数/会话数都是 `models.py` 的行实时聚合，无缓存、无采样。
- 前端 `modules/dashboard/geoProjection.ts` 自带几何：中国轮廓（含海南、台湾）+ 点阵填充 +
  等距圆柱投影；地球用正交投影（**背面返回 `visible:false`**，不折到正面）+ 经纬线框。
  平台离线、拿不到 GeoJSON，所以形状是代码里的简化轮廓而不是下载的地图数据。
  `components/GeoMap.vue` 左侧中国地图（内网画成示意枢纽 + 国内落国家标签点）、右侧地球（境外），
  图例用 `chartTheme.sensitivityColors` 的 L1–L4 四色 + 未评级；组内没有任何已判定等级时标「未评级」。
- 回归：`backend/tests/test_dashboard_screen_api.py` 增 3 例（分组与着色、打击伪造的地区表后能点名「美国」、
  地区表缺失时如实降级）；`test_dashboard_boundaries.py` 的冻结路由表补
  `("GET", "/dashboard/geo-map")`；前端 `frontend/src/__tests__/geo-projection.test.ts`（5 例几何）+
  大屏两个用例更新。

**③ 密码评估回到扫描流程**

- `services/crypto_profile.py` 拆出 `profile_from_observations(services, handshakes)`：一次扫描里已经采到的
  服务 banner / TLS 握手观测就地汇总成画像，不必再回查库。
- `workers/analysis_tasks.py`：扫描过程为每台主机生成 `crypto_profiles[host]`（上限
  `CRYPTO_PROFILE_HOST_LIMIT = 50`），**只有非空时**才写进 summary 的 `crypto_profiles` /
  `crypto_profile_hosts`；新增 payload 开关 `crypto_assess`（默认 `True`），关掉时连这两个键都不出现，
  元数据不残留。`ScanRequest.crypto_assess` 与 `api/network_scan.py` 把开关透传到任务。
- 前端把 `api/crypto.ts`、`modules/tasks/assessment/cryptoAssessment.ts` 从历史版本取回，
  新增 `assessment/composables/useCryptoAssessment.ts` 与 `assessment/CryptoAssessmentPanel.vue`：
  任务详情里选「评估目标」→ 评该主机，另有合规/弱配置两个预置；**观测不足的主机会用内置默认值补齐**，
  不会因为少几项就评出一个假的满分。`TaskCenter.vue` 增加密码评估分区，并把
  `crypto_profiles` / `crypto_profile_hosts` 加进 `PRESENTED_KEYS`（不再在原始结果块里重复刷屏）；
  向导第 6 步加 `密码评估` 开关（`useTaskWizard.ts` 的 `cryptoAssess`，随 `/scan` 下发、`reset()` 归位）。
- 回归：`frontend/src/__tests__/crypto-assessment-state.test.ts`（8 例）+
  `task-center-wizard.test.ts` 增 3 例（共 9 例）；后端 `test_crypto_profile.py`、
  `test_network_scan_boundaries.py`、`test_task_boundaries.py`、`test_scan.py` 共 33 例通过。

**验证**

- 后端定向：`test_dashboard_screen_api.py` + `test_dashboard_boundaries.py` + `test_risk_files.py` 共 20 例通过；
  crypto/scan/边界共 33 例通过。
- 后端全量对照：与本批前的 `HEAD` 版本跑同一命令，失败集合**完全相同**（本容器环境固有的
  packaging/shared/probe 类失败），本批**零回归**，另外把 9 例新功能用例从失败变为通过。
- 前端：`vitest run` 21 文件 114 例全过；`vue-tsc --noEmit` 干净。
- `ruff check`：本批新增/修改行 0 告警（存量 E501 未动）。

## 第四十三批：扫描临时文件清理 + 旧版本探针回收（2026-09-23）

用户要求：每个文件整份下载 + 全量哈希，**分析完成后及时清理即可**；并**回收旧版本探针，确保没有
历史版本的内容影响**。

**扫描临时文件（已在，本轮补上崩溃路径）**

- 现状核对：`backend/app/services/file_scan/scan.py` 每个文件下载到
  `TemporaryDirectory(prefix='dst-file-scan-')` 下的 `content<后缀>`，`ingest.analyze` 与
  `_sha256_file`（分块，整份哈希）跑完后在 `finally: local.unlink(missing_ok=True)` 删除，一次扫描
  只占一个文件的空间。工作/运行容器 `/tmp` 复核为空，无遗留。
- 新增 `scan.sweep_stale_temp_dirs()`：`TemporaryDirectory` 与 `unlink` 都跑不到的场景只有
  `SIGKILL`／容器停止，此时整份拷贝会永久留在 `/tmp`（一份多 GB 的 dump 就够撑爆磁盘）。启动时清扫
  **超过 6 小时**的 `dst-file-scan-*`（年龄保护，不会碰别的 worker 正在写的目录），接在
  `workers/celery_app.py` 的 `worker_ready` 信号上（懒导入，beat/API 不触发）。
- 回归：`backend/tests/test_file_scan_containment.py` 增 2 例——① 每个文件都是整份拷贝、全量哈希、
  跑完 `/tmp` 里连目录都不剩；② 启动清扫只清陈旧目录，保留刚写入的。**反向验证**：把修复摘掉后第 1 例
  仍失败（`copied` 断言可捕获），确认不是空断言。
- 真机复验：在 `source-worker-1` 里放一个 7 小时前与一个刚写入的 `dst-file-scan-planted-*`，
  `docker restart source-worker-1` 后陈旧的消失、新的保留。

**旧版本探针回收**

- **发布目录里的旧包**：`probe_packages/probe-3.7.0/arm64/` 还是修复前的源码（`probe.py` 仍是
  `max_files` 50/10000 上限与 500 MiB 跳过、`install.sh` 仍是 `max_files = 50`、`shared/` 四个文件也不同）。
  用 `scripts/build_probe_packages.py --arch=arm64` 从当前树重建，产物 `probe-3.7.0-arm64.tar.gz`
  sha256 由 `dd020dd1a927d776bfb0dfb90cc16e638867cf46ee4284d462c58f65b7c457db` 变为
  `e39afa560ae322a58dca1529a4d31dd34da299516c1e18570b4dbad6faafae33`，重建后与工作树逐字节一致；
  旧目录备份在 `/tmp/probe-pkg-backup/probe-3.7.0.old`。**版本号仍是 3.7.0**，源码变了版本没变，
  以后只有 `package_digest` 能区分（如需可辨识需另起版本号，影响面较大，本批未动）。
- **根因修复**：`services/probe_service.py::delete_probe_record` 回收探针时把 `probe_deployments.probe_id`
  置空，却把 `status` 留在 `ONLINE`，于是历史里永远显示一台不存在的在线探针（`probes` 表已空、该行已无
  探针可指，没有任何事件能再推进它）。现在会把属于该探针的 `ONLINE` 安装行改为 `REMOVED` 并补一条
  `ProbeDeploymentEvent` 说明原因；回归用例
  `tests/deployment/test_removal.py::test_reclaiming_a_probe_takes_its_install_offline`
  （摘掉修复后确认失败）。
- **线上两条孤儿行**：`probe_deployments` 3/5（`install`，host `192.168.110.168`，`probe_id` NULL、
  `ONLINE`，`preflight arch=arm64`）按同语义改为 `REMOVED` + 事件 + 审计
  （`audit_logs.action='probe_deployment.reclaim'`），同时把两行的 `probe_enrollments.expires_at` 收到
  当下。处理的判据是「该主机已无任何探针记录」（`probes` 表空）。
- **真机事实**（只读核对，未登录任何探针主机）：本机 `192.168.110.168` **没有安装探针**
  （`/opt|/etc|/var/lib/data-security-toolbox`、`data-security-toolbox-probe.service` 均不存在），
  `probes` 表 0 行，`files/asset_instances/detections/assets/pcaps/alerts` 里 `probe_id` 非空的行全为 0——
  即**没有旧探针留下的数据**，`/home` 那次 15137 个文件是平台用 SFTP 直连采的。遗留的
  `dstprobe`(uid 995) 系统账号是远端卸载时 `keep_user` 保留的，非 root 无法清理，且不影响结果。
- **架构**：本机是 **aarch64**（`Linux gb-pc ... aarch64`，Kylin，装 exagear 跑 x86），所以只构建/保留 arm64 包
  是对的；amd64 包需在 amd64 构建机上出（`scripts/build_probe_runtime.py --arch amd64` 本机跑不通，
  `probe_packages/runtimes/amd64` 一直是空的，属既有状态）。

**一致性修补：源 1 的旧上限**

- `file_sources` 1（`192.168.110.168 直连采集` `/home`）仍留着老值
  `max_files=10000, max_depth=3, max_bytes=64 MiB, max_file_bytes=8 MiB, max_seconds=120`，
  `last_error=byte_budget`——这正是「目录只能看三层 / 被截断」的来源。经 `PUT /file-sources/1` 全部改为
  0，4 个来源现在都是 `{max_files:0,max_depth:0,max_bytes:0,max_file_bytes:0,max_seconds:0}`
  （审计 `file_source.update` id=26）。核对了资产分布：只有 `file-source:3`(15137，深度 3–17) 与
  `file-source:4`(6) 有实例，源 1/源 2 **0 条**，所以没有截断期的历史资产混在库里。

**发布与复验**

- 重建并切换：`source-backend:latest`（target api）与 `source-worker:latest`（target analysis-worker）
  用 legacy builder 重建，`--force-recreate` 了 backend/worker/beat/pcap-worker/deployment-worker；
  `/api/v1/health` = ok（3 worker、`analysis_worker: ready`、tshark/zeek/suricata 均可用）。
- 测试：`test_file_scan_containment`(3)、`test_file_scan_global_stop`(1)、`test_file_sources`(21)、
  `test_scan_profiles`(28)、`test_targets`(6)、`test_data_asset_boundaries`(3)、`test_probe_boundaries`(9)、
  `test_task_boundaries`(9)、`tests/shared/test_scanning_core`(42)、`tests/deployment`(arm64 全绿) 通过。
- 既有失败（与 `HEAD` 相同，非本轮引入，已用 `git archive HEAD` 建立干净树对照）：`test_api.py::test_health`、
  `test_bugfix_regressions.py`、`test_dlp_detection_quality.py`、`test_rule_execution.py`、`test_rule_libraries.py`
  （`app.api.rules` 已拆走）、`shared/test_distribution.py` 里需要 `offline/`、`backend/Dockerfile`、
  `docker-compose.yml` 的 3 条、`tests/deployment/test_api.py::test_create_deployment_persists_data_asset_config`；
  另有 `tests/test_gap_fixes.py::test_file_upload_persists_md5_from_probe_metadata` 在容器内无 broker 时挂起
  （HEAD 同样挂起，环境问题）。
- **未做**：没有登录或改动任何探针主机（无凭据也未获授权）；没有 `git commit`。

## 第四十二批：目标机接入远程 Git + 探针监控修复上线（2026-09-22）

用户目标：把目标机上那份项目接到 `git@github.com:1376524890/data-security-toolbox.git` 并纳入版本控制。

**目标机 Git 接入（真实执行）**

- 工作树 `/home/user/dst-toolbox-3.0.0-linux-arm64`（3.0.0 离线包解包目录）已建库：
  `origin = git@github.com:1376524890/data-security-toolbox.git`，分支 `develop` 跟踪 `origin/develop`，
  提交身份 `Codex <codex@example.com>`（与本地一致）。
- 免密走目标机自己的密钥 `~/.ssh/id_ed25519`（ED25519，`SHA256:fhthVPgD4RndCOuQORa3Ws0wnEle1TIHywAWBN2t4Fg`）；
  `ssh -T git@github.com` 回 `Hi 1376524890!`，`git fetch` / `git push --dry-run` 均通——目标机不是只读镜像，
  本身就是一处可提可拉的工作副本。
- 交付包根多出来的发布件（`README-离线部署.md`、`SHA256SUMS.txt`、`VERSION`、`deploy.conf`、`deploy.sh`、
  `undeploy.sh`）写进 `.git/info/exclude`（只在本机忽略，不动仓库共享的 `.gitignore`）；运行期数据
  `.env`、`deploy-data/`、`dist-offline/`、`frontend/dist|node_modules` 由仓库 `.gitignore` 覆盖。
  `git status` 干净，改动全在受控范围内。
- 一致性核对：本地与目标机 `HEAD^{tree}` 同为 `0627e286355001f81956c24df2eb59d1c1361ee1`。
- `.git` 只有 14M（包内自带历史），目标机无需再克隆一份即可开发。

**线上修复探针监控任务（真实执行）**

- `804b420` 提交说明里承诺的第二处根因**当时漏进了提交**：`probe_lifecycle.owner_deployment()` 仍按
  `status == "SUCCEEDED"` 找安装单，而全代码库没有一处写 `SUCCEEDED`（推送安装的终态是探针回调时的
  `REGISTERED`、首次心跳后的 `ONLINE`），所以任务专属探针从未被自动回收、抓过包的探针也删不掉。
  补提交 `653ada3`：改查 `REGISTERED`/`ONLINE`；`DELETE /probes/{id}` 允许不带口令、改用安装保留的凭据，
  没有可复用的凭据才 400；`ProbeDeleteRequest.auth_type` 因此改回可选，校验器只在显式给了类型时触发。
  `tests/test_probe_lifecycle.py` +5 项后 16 项全绿。
- 目标机离线拉不到 base image（`failed to resolve reference "docker.io/library/python:3.11-slim"`），
  三个应用镜像在本机（同为 aarch64）用 legacy builder 重建后运过去：`docker save backend worker frontend
  | gzip -1 | ssh`（883 673 359 字节，约 70 秒，~19MB/s），`docker load` 后**逐个验内容**——backend / worker
  镜像里有 `pcap_worker_queue`、frontend 的 `TaskCenter-*.js` 里有「回收探针」——再
  `compose up -d --no-build --force-recreate backend worker pcap-worker beat deployment-worker frontend`。
  注：load 后镜像 ID 与本地不同（containerd 重新生成 manifest 摘要），验内容比验 ID 可靠。
  旧镜像（`87cbabf4fbb5` / `6729dc2241a4` / `a97aa30cd0b1`）保留为 `<none>` 便于回滚，中转 tar 已删。
- **线上复验（目标机上真实请求）**：
  - `/api/v1/health` = ok，`celery.workers=3`（analysis / pcap / beat），`analysis_worker: ready`、
    `tshark.available=true`——修复前这里是 `analysis_worker: offline`。
  - `POST /api/v1/tasks/3/stop`（monitoring）→ 200 `Cancelled`，`current_stage` =
    「已停止监测，同时取消 186 段待分析流量」；`tasks` 表里 186 条 `pcap Pending` 全部转 `Cancelled`，
    再拉任务列表仍显示 `Cancelled`（此前列表刷新会把它重绘成「持续监测中」，是用户看到"卡死"的原因之一）。
  - 被堵住的 `scan` id=34 立刻转 `Running`（`Nuclei 扫描 http://192.168.110.168:8080`）；`file_source_scan`
    id=35 在 10:01 就被 `time_budget` 判过期（其配置里 `max_seconds: 1`），属旧 backlog 的连带结果。
  - 探针回收闭环：停监测后 `retire_after_task` 排队卸载，`source-deployment-worker-1` 日志显示 10:05:58
    收到 `run_probe_deployment`、`Authentication (password) successful!`、5 秒成功；随后 `probes` 与
    `probe_deployments` 都是 0 行——192.168.110.168 上那份探针已被远端卸载并清掉记录（一键回收实测通过）。
  - 控制台 `http://127.0.0.1:8080/` 200。
- **安全提醒（未彻底处理）**：远端仓库当前是 **public**。本条已把 `TASK.md` 里明文的管理员口令换成
  「取自目标机 `.env` 的 `ADMIN_PASSWORD`」，但 `43c2092` 这次提交的历史里仍有该口令，彻底消除需要
  把仓库改 private 或重写历史。

## 第四十一批：交付包实测离线部署到 192.168.110.50（2026-09-22）

用户目标：连到 `user@192.168.110.50`，把本项目**以离线方式**部署上去并测试能跑。目标机 aarch64 /
Ubuntu 26.04 / 64 核 123G，Docker 29.1.3，`/` 剩 70G；本机与目标机同为 aarch64，包可直接用。

**已完成（真实执行）**

- 用 `dist-release/dst-toolbox-3.0.0-linux-arm64.tar.gz`（sha256 `54b994…` 校验通过）在目标机部署：
  解包到 `/home/user/dst-toolbox-3.0.0-linux-arm64`，`sudo ./deploy.sh --non-interactive
  --http-port 80 --api-port 8000 --backend-url http://192.168.110.50:8000`。
- 目标机 `docker compose` v2 插件缺失（只有 `docker-trust`，`docker compose` 直接不认识）：从本机
  `~/.docker/cli-plugins/docker-compose`（v2.29.7，同为 linux/arm64 静态二进制）拷过去装到
  `/usr/libexec/docker/cli-plugins/`。注意装到用户级目录对 `sudo` 无效（HOME 变 /root），必须装系统级。
- **交付包实证缺陷（已修）**：`deploy.sh` 授权数据目录那段的入口条件是
  `if [[ "$(id -u)" -eq 0 ]] || chown … ; then :`，`id -u` 为 0 时短路直接进 `:`，**chown 永远不跑**。
  于是 README 的主路径 `sudo ./deploy.sh` 必然让 `deploy-data/backend` 停在 root:root，
  容器内 appuser(10001) 建不了 `/app/data/storage`，backend/worker/beat/deployment-worker 四个容器
  无限重启，deploy.sh 最后打印「backend 未在 180 秒内进入 healthy」。改为显式三分支
  （root → 直接 chown；非 root → chown 失败再退回容器 chown），`bash -n` 通过。
  首次部署靠手工 `chown -R 10001:10001 deploy-data/backend` + `compose restart` 救活；
  修复后用 **全新项目 dstfix / 全新数据目录 / 端口 18081+18001** 重跑一遍 `sudo ./deploy.sh` 验证：
  目录自动变 10001:10001、backend 自己 healthy、`/api/v1/health` = ok，验证栈已 `down` 并删除数据目录。
- 交付包里 `deploy.sh` 有**两份**（顶层一份 + `deploy/` 一份，打包脚本把 `deploy/` 拷到包根）：
  实际执行的是**顶层**那份，改包内脚本时别只改 `deploy/deploy.sh`。
- 验收（全部真实请求）：8 容器 Up（backend / worker / postgres / redis healthy）；`/api/v1/health`
  status=ok、db/redis/celery ok、tshark 4.4.18 + zeek 8.2.2 + suricata 7.0.10 均 available；
  `http://192.168.110.50/` `/cockpit` `/index.html` 全 200；`openapi info.version = 3.0.0`；
  `admin / $ADMIN_PASSWORD`（口令取目标机 `.env`，仓库里不记明文）登录 200 并拿到会话 Cookie；按前端 `api/*.ts` 真实调用的 47 条路径逐条 curl
  全部 200；Playwright 带会话截图 `/cockpit` 与 `/` 两个首页均正常渲染（驾驶舱显示“API ok、
  集成组件 5/8、Sigma 6 条规则”，数据为空属全新库正常现象）。`.env` 落盘为 `600 root:root`。
- `source` 栈保留在目标机运行；交付包（3.4G）与 tar.gz（1.2G）留在 `/home/user/` 供重跑/回滚。
- **部署期踩到的两个坑（已处理，值得写进交付说明）**：
  1. `deploy.sh` **每次执行都会重写同目录的 `.env`**，且 `DATA_ROOT` 跟着本次参数走。为验证 chown 修复，
     我在同一目录又跑了一次 dstfix（`--data-root ./deploy-data-fix`），`.env` 就被改成
     `HTTP_PORT=18081 / API_PORT=18001 / DATA_ROOT=./deploy-data-fix`。运行中的 source 容器不受影响
     （端口/卷在创建时已定型），但**此后任何 `compose up`、重启、`deploy.sh` 重跑都会把栈搬到 18081
     并指向一个已被删除的数据目录，看起来就像"数据全丢了"**。已用原参数重跑 `deploy.sh` 把 `.env`
     复原（`--no-load`，容器配置未变故未重建、零停机，任务 id=1 与 3 条资产仍在）。
     结论：同一目录只服务一个部署；要并行验证就换目录（`--config` 或整包再解一份）。
  2. 控制台端口是**部署时 `--http-port` 定的 80**，不是 `deploy.conf` 里默认的 8080；访问 `:8080` 会被拒绝连接。
- 按用户要求把控制台从 80 换到 **8080**：重跑 `./deploy.sh --no-load --http-port 8080`（其余参数不变），
  `.env` 里 `HTTP_PORT=8080`、`DLP_SELF_ENDPOINTS=8080,8000,5432,6379,5555`；frontend 重新发布端口，
  backend 因 `DLP_SELF_ENDPOINTS` 变化一并重建（`deploy-data/` 是 bind mount，数据未动）。验证：
  `http://192.168.110.50:8080/` 与 `/cockpit` = 200，80 已关闭，任务/资产条数不变。
- 另在本机生成探针下发用密钥对 `~/.ssh/dst_probe_ed25519`（ed25519，无口令，指纹
  `SHA256:NDjn+JBGGYb2rwfuGfOxfKe0EkBCB/IcpN+DDqZRyYM`）；原有 `~/.ssh/id_ed25519`（plk@kirin）未改动。
- 按用户要求把服务访问范围收敛到 **192.168.110.0/24**（此前 ufw 未启用、`DOCKER-USER` 为空，
  8080/8000 对任何能路由到该机的网段都是开放的）。两个关键技术点：
  1. **必须写 `DOCKER-USER`**：docker 发布端口是 nat/PREROUTING DNAT 后经 FORWARD 转发，
     ufw 的 INPUT 规则管不到容器端口。
  2. **必须用 `-m conntrack --ctorigdstport`**：DNAT 之后 dport 已被改写成容器端口
     （frontend 是 `8080->80`），用 `--dport 8080` 匹配不到——第一版规则就是这么错的，
     实测非 110 网段访问 8080 仍返回 200，而 8000（宿主/容器端口同为 8000）却被正确丢弃，
     正好暴露了这个坑。
  最终规则：ESTABLISHED → 放行 docker 网段 172.16.0.0/12 → 放行 110 网段到 8080/8000 → 其余来源丢弃。
  落地为 `/usr/local/sbin/dst-port-scope.sh` + `dst-port-scope.service`（`PartOf=docker.service`
  + `Requires`/`After`，docker 重启会重建链，靠它自动重放），已 `enable`。
  验证（真跑）：110 网段 `.168` → 8080/8080-cockpit/8000-health 全 200；用一台临时 netns
  `10.99.99.1`（非 110）→ 两个端口均超时丢弃；SSH 22 不受影响；`systemctl restart docker`
  之后规则仍在、8 容器自动恢复 healthy。临时 netns/veth 已清理。增删网段改脚本里的 `ALLOW_CIDRS`。

- 按用户要求把目标机上的项目接入远程仓库并纳入版本控制（**目标机现在是可开发的工作副本**）：
  1. **同一个仓库**：`/home/user/dst-toolbox-3.0.0-linux-arm64` 接的是
     `origin git@github.com:1376524890/data-security-toolbox.git`，在 `develop` 分支跟踪 `origin/develop`。
     与研发机**逐字节一致**：HEAD 都是 `43c2092`、树哈希都是 `594070b8`、131 个提交 / 717 个跟踪文件。
  2. **认证走目标机自己的密钥**：目标机生成 `~/.ssh/id_ed25519`（ed25519），公钥已加进 GitHub 账号
     `1376524890`；`git ls-remote`、`git fetch`、`git push --dry-run`（`Everything up-to-date`）均实测通过。
     提交身份 `Codex <codex@example.com>`（`git config` 局部设置，未动全局）。
  3. **解包残留只在本机忽略**：`README-离线部署.md` / `SHA256SUMS.txt` / `VERSION` / `deploy.conf` /
     `deploy.sh` / `undeploy.sh` 写进 **`.git/info/exclude`**（故意**不进共享 `.gitignore`**：它们是打包脚本
     从 `deploy/` 拷到包根的产物，仓库里已有正规来源，不该被全局忽略）。这样 `git status` 保持干净，
     又不会把交付件误提交。
  4. **`.env` 不入库**（`.gitignore:8`）：目标机 `.env` 是 `600 root:root`，含管理员口令、
     `SECRET_KEY`、`POSTGRES_PASSWORD`、`PROBE_BOOTSTRAP_TOKEN`，**不要 `git add -f`**。
  5. 目标机可直接开发提交：`cd ~/dst-toolbox-3.0.0-linux-arm64 && git add -A && git commit -m '…' && git push`。
- **安全提醒（本轮发现，尚未处理）**：远程仓库 `1376524890/data-security-toolbox` 当前是 **public**
  （GitHub API `visibility=public`），而本文件第 30 行记着控制台的真实管理员口令（`admin / <见该行>`）。
  建议**把仓库改成 private**，或抹掉该口令后只保留「口令在目标机 `.env` / 由 `deploy.sh` 打印」。已核对
  **源码本身没有硬编码真实凭据**（`.env.example`、`backend/tests/conftest.py`、`probe/install.sh` 里
  都是占位或测试值）。另：默认分支是 `master`，`develop` 只是分支，改默认分支前先确认没有依赖。

## 第四十批：v3.0.0 一键离线部署套件与发布（2026-09-22）

用户目标：给一个**一键配置脚本**，包含全部参数的设置，一键跑完部署；然后重新推 git、发布包、发布 release，
版本号从 **v3.0** 开始编号。硬约束：交付包必须能**完全离线部署、不依赖目标机本地环境**，
部署后还要**能在服务器上继续开发**；目标架构 **arm64**。用户明确要求不要过度测试。

**已完成**

- 版本号升到 3.0.0：`backend/app/main.py`、`frontend/package.json`、`frontend/package-lock.json`；
  探针保持 3.7.0；迁移 head 仍为 `0019_policy_group_fingerprints`。
- 一键部署套件 `deploy/`：`deploy.conf`（唯一配置入口，全部参数带中文注释、按段分组，`auto` = 首次生成
  以后沿用；优先级 命令行 > deploy.conf > 内置默认）、`deploy.sh`（环境自检 docker/compose v2/架构 →
  `docker load` → 渲染并落盘 `.env`（chmod 600）→ 数据目录授权 10001（无 root 时用包内
  `redis:7.4-alpine` 跑 chown）→ 端口预检（仅当本项目还没有容器）→ `docker compose up -d --no-build
  --pull never` → 等 backend healthy 最多 180 秒 → 打印地址/口令/数据目录）、`undeploy.sh`
  （停栈保留数据，`--purge` 二次确认后删数据目录）、`README-离线部署.md`（112 行，含排错表）。
  支持 `--dry-run / --force / --no-load / --config / --project / --data-root / --http-port / --api-port /
  --backend-url / --admin-password`。
- 发布打包脚本 `scripts/make_offline_release.py`：硬链接暂存（不额外占盘）→ 跳过
  `dist-release/dist-deploy/deploy-data/data/0916_v2.7/.refactor-trash/.ruff_cache/.pytest_cache/.local`
  与 `ChatGPT Image*` / `FRICSE*` 前缀及 `backend/data`、`frontend/node_modules/.vite` → 把 `deploy/`
  拷到包根 → 生成 `VERSION` 与 `SHA256SUMS.txt` → `tar --hard-dereference --owner=0 --group=0 | gzip -1`
  出包并写 `.sha256`；缺 `dist-offline/security-toolbox-images.tar` 时拒绝打包。
- 文档：新增 `docs/releases/v3.0.0.md`；`docs/versioning.md` 增 v3.0 条目与章节；`CHANGELOG.md` 顶部新增
  v3.0.0 段；`README.md` 离线部署章节改指向 `deploy/`。
- 镜像：`source-backend` / `source-worker` / `source-frontend` 用 legacy builder 重建（前端必须
  `--no-cache`，否则 `COPY . .` 命中缓存会复用旧产物），`offline_bundle.py --save` 重出
  `dist-offline/security-toolbox-images.tar`（2.95 GB，6 个 arm64 镜像）。

- 交互式配置：`./deploy.sh` 在终端里逐项提问必要参数（回车 = 取 `deploy.conf` 的值，口令留空 = 自动生成、
  隐藏回显），确认摘要不回显口令明文；确认后非口令项写回 `deploy.conf`（只改真正变了的项，行尾注释保留），
  口令只进 `.env`。`--non-interactive` 全自动，`-i` 强制提问，`--dry-run` 配 `-i` 可先看一遍。
- 打包脚本两处真缺陷已修（都是打包期实测抓到的）：
  1. 暂存目录未先创建，而 `.dockerignore` 按字典序排在最前 → 顶层文件硬链接时 `FileNotFoundError`
     （上一版没暴露，是因为 `.dockerignore` 是 2.14.0 打包之后才加进仓库的）；
  2. 交付包里混进了操作者本机的 `.env`（真实口令 + 现场 IP），且目标机首次部署会沿用这些值 →
     打包脚本现在显式排除 `.env`，只带 `.env.example`。
- **交付包**：`dist-release/dst-toolbox-3.0.0-linux-arm64.tar.gz`（1.28 GB，
  sha256 `54b99448712ed7875935dc4e9ad995077665f840da22307e7358e912ee642f40`）。
- **解包全新部署冒烟（真实执行，非 dry-run）**：解到干净目录，用交互式回答（项目名 `dstcheck3`、
  端口 18082/18002、管理员口令手工指定、其余口令自动生成）起栈 → 8 容器全部 Up
  （backend / worker / postgres / redis healthy）、`/api/v1/health` = ok、
  `http://127.0.0.1:18082/` 与 `/cockpit` 均 200、`openapi info.version = 3.0.0`；
  `deploy.conf` 写回只改了回答过且真不同的项并保留注释；`undeploy.sh` 停栈后临时目录已清理。
- 打包脚本第三处小缺陷：`Path.with_suffix('.tar.gz.sha256')` 只会替换最后一个后缀，产出
  `….tar.tar.gz.sha256`；改为直接拼 `.sha256`，并把已产出的校验文件改名到位（内容本来就对）。
- 发布：`develop` 推送到 `bbb3a3b`（`1303634` 一键部署套件 + `bbb3a3b` 交互式配置与打包修复），
  创建并推送注释标签 **`v3.0.0`**（指向 `bbb3a3b`）。本机没有 `gh`，GitHub Release 页面需在有 `gh` 的
  机器上补建；标签与说明已经推上去了。

## 第三十九批：数据安全综合驾驶舱与浅色控制台（2026-09-22）

用户目标：首页不能只有一块演示用大屏，日常使用要有**综合驾驶舱**（数据安全健康度、合规进度、
本周重点关注、流水线、最近任务），同时控制台整体改成**浅色**更好日常看；大屏继续保留给会议/演示。

**已完成**

- **两个首页**：`/` = 数据安全态势大屏（`DashboardScreen.vue`，`meta.layout='screen'`，`App.vue` 见
  `screenLayout` 即不渲染侧边栏/顶栏，固定深色 1920×1080）；`/cockpit` = 数据安全综合驾驶舱
  （`modules/dashboard/cockpit/DashboardCockpit.vue`，在控制台壳层内）。`/screen` 重定向到 `/`，
  旧链接不落空；`menu.ts` 里两者是仅有的无分组标题条目。
- **驾驶舱实现**：10 个面板组件（KPI 卡、健康度环、资产/风险分布环、合规板、本周重点关注、流水线、
  流动卡片、最近任务）+ `CockpitCard` / `DistributionDonut` 两个通用件，投影与刷新全在
  `composables/useDashboardCockpit.ts`（30 秒刷新、卸载清 timer、失败保留上一次成功数据并显示过期提示）。
- **后端**：`services/cockpit_service.py` 集中健康度（`HIGH_SEVERITIES` 命中率等加权）、合规进度、
  周环比（`week_pair`）与流向汇总；`api/dashboard.py` 把驾驶舱块作为 `_cockpit_blocks` 并入
  `GET /dashboard/overview`（大屏与驾驶舱共用，不会两页两套数字），新增
  `GET /dashboard/trend?range=7d|24h`（发现/事件/告警 + 三类流向，共用一条零填充时间轴）与
  `GET /dashboard/tasks?limit=`（复用 `visible_tasks` + `default_task_filter` + `serialize_task`，只读）。
- **浅色主题**：`frontend/src/utils/theme.ts` 提供 `themeMode` ref + `applyTheme` + `chartColors`，
  默认浅色（`main.ts` 只在 `dst-theme === 'dark'` 时深色）；图表包装组件监听 `themeMode` 重建 option，
  避免切主题后画布保留上一种主题的网格/轴色。大屏保持固定深色。

**交付（arm64 离线包，2026-09-22）**

- 提交 `cd6845c`（本批源码）+ `5eacada`（`.gitignore` 忽略交付包）已推送 `origin/develop`。
- 三个应用镜像与提交修订一致（后端/worker 逐文件 md5 与工作树相同，前端为本轮重建）；
  `dist-offline/security-toolbox-images.tar` 2.95 GB、6 个镜像全部 `arm64/linux`。
- 交付包 `dist-release/dst-toolbox-2.14.0-linux-arm64.tar.gz`（1.28 GB，sha256 `1db744ef…`），
  内含镜像归档、全量源码（含 `.git`）、`probe_packages/probe-3.7.0/arm64`、`frontend/node_modules`、
  `.env`、`deploy.sh` / `undeploy.sh` / `README-离线部署.md` / `SHA256SUMS.txt`。
- **打包期在真机（本机）冒烟部署抓到一个真缺陷**：backend/worker/beat/deployment-worker 反复重启，
  日志 `PermissionError: [Errno 13] '/app/data/storage'`。根因是容器以 `appuser`(uid 10001) 运行，
  而 `deploy-data/backend` 是 docker 以 root 创建的 bind mount，容器内无权创建 `storage/`。
  修法是 `deploy.sh` 在启动前把该目录授权给 10001：有 root 直接 `chown`，没有 root（只在 docker 组）
  就用包内 `redis:7.4-alpine` 跑一次 `chown`。修后从新包解压 → `./deploy.sh` → 8 个容器全部健康、
  `/api/v1/health` = ok、`/`、`/cockpit`、`/screen` 均 200。**这段修复只存在于交付包内的 `deploy.sh`
  与本机 `dist-release/extras/`，重新生成发布包时不要弄丢。**

**复验（真实执行）**

- 前端：`npx vue-tsc --noEmit` 干净；`npx vitest run` 全量 **18 文件 / 89 项通过**，其中
  `dashboard-cockpit.test.ts`（6 项，整页挂载）与 `dashboard-cockpit-state.test.ts`（10 项，投影/
  竞态/失败态）是本批新增。
- 后端：本批相关域 12 个文件 **61 项**（含 `test_cockpit_api.py` 9 项）+ `test_transfer_file_binding.py`
  3 项通过。
- 全量对照：工作树 **43 项失败/错误**、干净 HEAD 检出 **50 项**；两边共同的 41 项逐项一致（本机无 Redis → `/health` degraded、缺 amd64 探针包与原生导出器、`shared/scanning` 默认值与用例不一致、`test_database_scan_api` 的 teardown 等），只在 HEAD 出现的 9 项全是需要 `probe_packages/`（gitignored，干净检出里没有）的探针包/分发用例；工作树多出的 2 项经单独复跑确认与本批无关：`test_transfer_file_binding.py` 单独跑 3/3 通过（全量顺序下的数据污染），`test_create_deployment_persists_data_asset_config` 在干净 HEAD 上单独跑同样失败（`retain_credential` 口径不一致）。

## 第三十八批：数据安全态势大屏（2026-09-22）

用户目标：现有首页偏「传统后台统计页」，要重做成可用于**客户演示 / 会议 / 大屏展示**的**数据安全态势大屏**：
16:9、默认 1920×1080、深色科技风；重点不是漏洞数量，而是①数据资产态势 ②数据流动可视化 ③敏感数据风险
④探针采集状态 ⑤检测引擎运行状态 ⑥安全事件闭环。硬要求：**所有数据接真实来源，不得有任何虚假数据**。

**已完成**

- **换页**：`/` 从旧 `modules/dashboard/Dashboard.vue` 换成 `DashboardScreen.vue`（`meta.layout = 'screen'`），
  `App.vue` 见 `screenLayout` 即隐藏侧边栏与顶栏；旧页与其 composable、旧 `dashboard-state.test.ts` 一并删除。
  整页固定 1920×1080 设计稿 + `useScreenScale` 等比缩放（1920×1080 / 1366×768 / 2560×1440 实测均满屏无裁切）。
- **组件拆分**（`modules/dashboard/components/`）：SecurityHeader（Logo/标题/副标题/API 状态/集成组件/在线探针/
  时钟/管理员/全屏/返回控制台）、MetricCards（6 张 KPI，含图标、数值滚动、同比或「今日新增」）、
  TrafficMap、TrendPanel、DonutPanel、RiskChart、AssetChart、EngineStatus、ProbeHealth、ClosedLoop、
  EventStream（自动滚动、悬停暂停、尊重 prefers-reduced-motion），另有 AnimatedNumber、ScreenIcon、chartTheme。
- **状态与刷新**：全部落在 `composables/useDashboardScreen.ts`（30 秒刷新 + 1 秒时钟，卸载清 timer）。
  死数据、投影（`riskSlices`/`assetSlices`/`engineRows`/`engineSummary`）与「检测趋势」指标切换都在这一个文件里。
- **四条新聚合**（`api/dashboard.py`，全部按行实时算、无缓存、无写死）：
  `GET /dashboard/overview`、`GET /dashboard/traffic-flow?limit=&days=`、`GET /dashboard/risk-distribution`、
  `GET /dashboard/detection-trend?range=`。边界清单已被 `tests/test_dashboard_boundaries.py` 冻结。
- **一份「集成组件」口径**：把 `/integrations` 的函数体提成 `integration_catalogue()`，大屏 overview 与
  `/integrations` 共用，避免一页两个「x/y」。
- **实时事件**：`GET /alerts` 增加 `order=recent`（`last_seen desc, id desc`），默认 `risk` 顺序不变——屏幕要的是
  最新而不是最严重。
- **流向判定（口径决定不造数）**：只报三类——内部流量 / 外部流出 / 目的未识别。库里没有 zone 表，
  所以**没有「跨域访问」这一档**，宁可少一档也不用同义词凑数；`external` 只在地区表命中或黑名单命中时成立，
  未证实的一律黄灯 `unknown`，不当出境（红）报。

**用真实浏览器走查后查出并修掉的 4 个真缺陷**（jsdom 单测看不到，都是实机截图量出来的）

- **中间一行整行塌成 0**：`SecurityHeader` 的 `height: 100%` 让它在 1080 高的纵向 flex 里拿到整列基准尺寸，
  实测 header 高 **662px**、`.ds-middle` 高 **0**，中部三块面板全被压没。改为固定 `76px` + `flex-shrink: 0`。
- **拓扑画进一个角**：`TrafficMap` 在拿到数据前是 hidden 的，echarts 对 0×0 容器初始化成 **100×100** 画布，
  之后没人告诉它盒子出现了（`flush:'post'` 也救不回来，实测无效），整张拓扑被画进左上角。
  改为 `ResizeObserver` 观察容器（窗口 resize 从来不会触发）。
- **引擎卡吃掉 2 行**：底部一行 226px 装不下 8 个适配器（表格 `scrollHeight 225 > clientHeight 202`），
  Wazuh/OpenSCAP 被切掉，屏幕上却写着「共 8」。收紧行距并把底栏提到 250px，实测四个面板 `clipped = 0`。
- **检测趋势横轴标签被裁**：`detection-trend` 回的是完整 ISO 日（`2026-09-22`），最后一个刻度被面板右边裁掉；
  统一走新增的 `shortDay()` 显示成 `09-22`（与旁边的流量趋势一致）。
- 另外：`EventStream` 的 `let paused` 被 vue-tsc 收窄成字面量 `false`，模板里的 `paused = true` 编译不过，
  改用 `ref`；大屏接管标签页标题（`<title>` 仍是控制台的通用标题）。

**顺带的性能修正**：`/dashboard/traffic-flow` 的节点风险扫描原来 `select(DetectionFinding)` 整行 hydrate 2000 行
（findings 带大 payload），改成只取 `evidence` + `risk_level` 两列，实测 **1.6s → 1.06s**，返回内容逐字段一致。

**复验（真实执行）**

- 前端：`vue-tsc --noEmit` 干净；`vitest` **16 文件 / 72 项**全绿，其中新增
  `dashboard-screen-state.test.ts`（11 项：KPI/拓扑/两个环形/引擎分级与排序/指标切换/失败态）与
  `dashboard-screen.test.ts`（2 项：整页挂载断言六个 KPI、引擎卡、探针卡、闭环与事件流都渲染出真实形状；
  失败时出「态势数据不可用」遮罩而不是空白大屏）。
- 后端：`tests/test_dashboard_screen_api.py`（5）、`test_dashboard_boundaries.py`（8）、`test_alerts.py` 等
  相关 9 个文件 **66 项通过**；`ruff check` + `ruff format --check` 对本批文件干净（`test_alerts.py` 余下
  10 条 E501/F401 是历史存量，未动）。
- **真机数据核对**（部署态，非 mock）：overview 返回 alert 166 / incident 97 / finding 3313 / asset 7 /
  data_asset 0 / probe 0 / 集成组件 8（健康 5）；traffic-flow 出 36481 条会话、12 个节点、18 条链路，
  `172.23.0.4` 正确判为 `internal`（私网不当出境），红线的四个目的地是地区表命中的公网地址；
  「数据资产 0」「在线探针 0」就照实显示 0，没有补数。
- **真浏览器走查**：headless Chromium 带会话 cookie 打开 `:8080/`，在 1920×1080 / 1366×768 / 2560×1440 三种
  视口截图核对版式（帧尺寸与视口完全一致、`scrollHeight == clientHeight`）；并合成点击拓扑中心节点，
  确认抽屉弹出且字段来自真实聚合（172.23.0.4：10953 会话 / 19.0 GB / 769400 包 / 928 检测发现 / 97 高危）。
- 镜像已重建（`source-backend:latest`、`source-worker:latest`、`source-frontend:latest`）并用
  `docker compose -p source up -d --no-build --force-recreate backend worker beat deployment-worker frontend` 切换。

**与本批无关的既有失败（记录，未修）**：`tests/test_gap_fixes.py::test_integrations_reports_worker_zeek_suricata_capability`
（API 容器里真装了 suricata，`not entry["healthy"]` 的守卫使 worker 的 `rule_count` 永不合并，HEAD 同）；
`tests/integrations/test_adapter_pipeline.py`、`tests/test_dlp_detection_quality.py`（presidio/DLP 侧）；
`tests/probe/*`（镜像内无 `probe` 包）、`tests/test_rule_libraries.py`（import `app.api.rules`，该模块在当前
检出里不存在）。

## 第三十七批：CVE 规则库找回、网络资产页与出境报告明细，以及 ARM 离线部署复验（2026-09-22）

用户目标：① 网络扫描后**按指纹匹配 CVE 规则库**做风险检查，把 git 历史里丢掉的这个功能找回来并展示在
「采集与规则」，支持**手动导入 + 在线更新**；② 数据资产板块加「网络资产」页展示端口扫描与 CVE 匹配结果，
板块标题改为**资产中心**，原「资产中心」改为**数据大屏**并去掉板块标题，作为全部信息总览；
③ 数据出境报告支持查看/解析**具体流量与 pcap 包**，并展示是否含敏感信息、命中了什么规则。

**功能确实是被删的，不是没做**
- 控制台的 CVE 库 UI（`modules/threat/CveCenter.vue` + `api/offline.ts`）在 `c83c7e7`（2026-09-21）被删，
  同时 `_import_cves` 把 NVD 记录**拍平成纯文本**，受影响版本区间丢失 → `local_cves` 表为空，
  扫描结果永远只能给出「线索」，无法确认任何 CVE。本批是把这条链路重新接起来，不是从零新做。

**已完成**
- **导入器恢复结构化区间**（`integrations/offline_manager.py`）：保留 `product` 与 `affected_versions`
  （NVD `configurations[].nodes[].cpeMatch[]`，含 `versionStartIncluding` / `versionEndExcluding`）；
  严重度改按 CVSS 分档（此前一律 Medium）；CVSS 三代指标（v3.1/v3.0/v2）都读（此前只读 v3.1，老 CVE 全 0 分）。
- **在线更新 + 手动导入**：`services/cve_sync.py` 按**扫描到的指纹**（`assets.extra->product`，跳过
  http/https/unknown 这类泛化名）查 NVD，单个关键字失败不影响其余；`api/integrations.py` 增加
  `GET /offline/cves/fingerprints`（先看范围再决定要不要打）与 `POST /offline/cves/sync`。
  前端 `modules/collection/VulnerabilityLibrary.vue` 进「采集与规则」的**漏洞库** tab：在线更新、手动导入
  CVE 文件、手动添加单条、Grype DB 下载/导入，并显示「规则总数 / 可确认漏洞的规则 / 待更新指纹」。
- **网络资产页**：`api/network_assets.py`（`GET /network/assets`、`/network/assets/summary`）按
  `assets.extra->source ∈ {platform_scan,nmap_scan,probe_scan}` 出端口清单，CVE 命中来自已落库的
  `CVE_*` findings，按 (ip, port) 归组；前端 `modules/data-security/NetworkAssets.vue` 作为
  **资产中心**的新 tab（`/data-assets?view=network`）。
- **菜单重排**（`router/menu.ts` + `App.vue`）：`数据大屏` 分组标题置空（`v-if="section.group"` 不再渲染
  标题）作为总览；`资产中心` 分组下是 `数据资产` + `网络资产`；`采集与规则` 增 `漏洞库`。
- **出境报告明细**（`services/assessments/egress.py` + `flow/EgressReport.vue`）：传输对象补
  `object_id / src_ip:port → dst_ip:port / sha256 / complete / content_type / binary_available /
  sensitive / matches(含命中值样本) / rule_ids / files / file_bound`，新增「命中的敏感规则」段落与
  KPI；详情抽屉展示具体流量、是否含敏感信息、命中了哪条规则与**命中的原文**、对应文件、该会话的
  **报文列表**（`getPcapFlowPackets` 精确匹配五元组）与单包解析、对象二进制下载。

**实测中查出并修掉的两个真实缺陷（才是这轮的关键）**
- **区间跨产品拍平**：NVD 会把一个 CVE 覆盖的**所有**产品都列进配置树，`CVE-2016-0746` 的配置里
  nginx `<=1.8.0` 与 android `<13.0`、ubuntu_linux `==14.04` 并列。拍平后 `nginx 1.27.5` 会被
  android 的 `<13.0` 判为「已确认」。修法：区间按 CPE 产品分桶，主产品进 `affected_versions`，
  其余进 `product_ranges`，引擎按指纹产品取对应那一份。
- **无法解析的约束被静默跳过 → 整条规则空真通过**：`_version_in_range` 对 `==3.7.1p1` 这类带补丁后缀的
  约束 `continue`，循环结束时返回 `True`，于是 `OpenSSH 8.2p1` 命中了只列 `3.7.1` 的 CVE。修法：
  约束解析不了就返回 `False`（不能确认 ≠ 已确认），正则也放宽到带后缀的版本号。
- 还顺手修了两处展示问题：候选线索行**不带自己的 CVE 号**（抽屉里全是匿名「candidate」），
  以及同一规则被每次扫描重复列出（按 `(rule_id, cve_id)` 去重，保留最新一条）。

**复验（真实执行，非断言）**
- 单元/边界测试：`tests/test_cve_library.py`（10）、`tests/test_network_assets_api.py`（1）、
  `tests/test_network_asset_boundaries.py`（5）、`tests/test_egress_flow_detail.py`（1）、
  `tests/test_integration_offline_boundaries.py`、`tests/engine/test_threat_intel_cve.py` 全绿；
  前端 `vue-tsc` 干净、`vitest` 15 文件 / 67 项通过。
- **旧 worker 镜像导致过一次假复验**（值得记）：改完引擎只重建了 `source-backend`，扫描任务跑在
  `source-worker` 里，用的仍是旧引擎（`source-worker` / `source-beat` / `source-deployment-worker`
  共用 `source-worker:latest`）。症状是「API 里手工调用判不命中，扫描结果却写着命中」。
  **改引擎必须同时重建 backend 与 worker 两个目标。**
- 在线更新真实拉取：NVD 可达，按 9 个指纹导入 150 条、更新 208 条，本地库 300 条（可确认规则的 191 条）。
- 扫描复验：对 `192.168.110.168` 重跑检查任务 → 8 个服务、**已确认命中 0 条**（这批资产确实打到了新版，
  修掉误报后不该再有「已确认」）、候选线索带真实 CVE 号；修前同一批扫描会报出 4 条虚假「已确认」，
  已连同其派生告警一并删除（`detections` 无 FK，`alerts` 有，故先删告警再删 finding）。
- 前端走查（Playwright 实测）：菜单为「数据大屏（无标题）/ 资产中心（数据资产·网络资产）/ 采集与规则（…·漏洞库）」；
  `/data-assets?view=network` 出 8 行端口资产 + KPI（扫描主机 1、开放服务 8、匹配 CVE 76、已确认 0），
  点行开抽屉出 CVE 匹配表；`/collection-rules?view=vulnerabilities` 出漏洞库四个操作入口与 CVE 表；
  `/network/dlp?view=egress` 传输对象表（646 条）点行开抽屉，实测看到
  `172.23.0.8:80 → 172.23.0.1:44352`、对象 `http-body`、`命中 1 处敏感信息，规则：SD_PHONE_001`、
  命中值 `16238198296` 与上下文、200 条报文（协议/方向/长度/摘要）。

**ARM 离线部署复验（本机即 aarch64）**
- compose 需要的 6 个镜像（`source-backend` / `source-worker` / `source-frontend` /
  `postgres:16.6-alpine` / `redis:7.4-alpine` / `mher/flower:2.0.1`）本机全部存在且都是 `arm64/linux`。
- `docker save` 出 3.2 GB 的 `dist-offline/security-toolbox-images.tar`，包内 `manifest.json` 6 个镜像
  架构全部 `arm64`；`docker load` 回灌 6 个镜像全部成功。
- **离线启动实测**：`--no-build --pull never`（外加 `PULL_POLICY=never`）重建 5 个应用容器，全部起来、
  `backend` 转 healthy，全程没有拉取也没有构建。
- 附带修掉一个长期误报：`backend` 容器一直显示 `unhealthy`，但接口本身是 200。`/health` 要读 Celery 控制总线的
  队列深度（单这一项就 ~2.2s）再加规则数与探针直方图，整条链路 4.9–6.2s，而 compose 的健康检查超时是 5s，
  正好卡在边界上。把 `interval` 改 30s、`timeout` 改 20s（并写明原因），容器转为 `healthy`。
- `scripts/offline_bundle.py` 重写：镜像清单改为读 `docker compose config --images`（旧 README 里还写着
  `security-toolbox-*` 和 `mher/flower:2.0`，照它打会漏镜像）；新增**架构校验**（`docker info` 报
  `aarch64`、`docker image inspect` 报 `arm64`，必须归一化后再比），不一致直接退出而不是打出会在目标机
  失败的包；README 给出真实镜像清单与 `--pull never` 的离线启动命令。`docs/offline-deployment.md` 同步重写。
- 数据持久化：`postgres` / `redis` / `backend` 均为宿主机 bind mount
  `${DATA_ROOT:-./deploy-data}`，compose 里**没有匿名卷**，`--force-recreate` 不丢数据；`.env` 里当前
  **没有** `DATA_ROOT`，一旦改动会让容器去读另一个空目录（看起来像数据丢失）。

**待办 / 未做**
- 网络资产页的筛选与分页在 Python 侧做（当前规模够用，已在模块注释里写明）。
- NVD 关键字匹配天然会有误召回，引擎已把「已确认」（`CVE_<id>`）与「线索」（`CVE_CANDIDATE_*`）分开，
  不要合并这两类。
- 本机 `.env` 未设置 `DATA_ROOT`、磁盘已用 84%；`deploy-data/backend/storage` 约 35 GB（pcaps 26 GB），
  与约 7 GB 的历史遗留命名卷（`0901-_*`、`0916_v27_*`、`dsttest_*`）清理都还没动，需用户确认后再做。

## 第三十六批：任务类型决定探针，检查任务接入服务扫描（2026-09-22）

用户目标（一次给全）：
① 清除探针 4；② 「新建任务」改为**先选任务类型**——检查任务单次、不下发探针，监测任务必须部署探针，
自动部署失败要给**手动安装 + 回连**途径，因此不再让用户自己勾「是否需要探针」；并保证连接成功 + 勾选路径后
「下发任务」按钮可用（此前是灰的）；③ 网络流量分析与敏感文件发现**共用同一套规则**；④ 敏感文件在网络上
传输时要**绑定到具体文件**，而不只是一个风险点；⑤ 检查任务要用扫描工具对资产网络服务做风险扫描、指纹识别
并匹配漏洞库。

**已完成（本批）**
- **探针 4 清除**：`services/probe_service.py::delete_probe_record` 不再被「监测任务永远 Running」挡住——
  `monitoring` 行是探针抓包的台账、没人等它结束，删除探针时把它置 `Cancelled` 而不是拒绝；真正在跑的
  扫描/采集任务仍然照旧 409。回归：`tests/test_probe_delete.py` 新增 2 项。
- **任务类型驱动向导**（`frontend/src/modules/tasks/composables/useTaskWizard.ts`，重写）：
  删除每台主机的「探针」复选框与 `mode`，改为向导级 `taskType`（inspection / monitoring），步骤变成
  任务类型 → 目标 → 连接方式 → 连通性 → 检测范围 → 属性。
  - 检查任务：不接触目标主机，`POST /scan`（`nuclei=true` → nmap 指纹 + 漏洞模板）+
    每个勾选目录各建一个只读文件源并立即扫描（此前只取 `paths[0]`，其余勾选被静默丢弃）。
  - 监测任务：`POST /probe-deployments` 下发探针（profile=standard，`retain_credential`），轮询回连；
    失败/超时则显示手动安装步骤与配置。
- **手动部署 + 回连**：新增 `POST /probe-deployments/{id}/manual-bootstrap`，为同一部署行签发**新的**一次性
  入网令牌并返回完整 `probe.toml` + 安装步骤；`GET /probe-deployments/packages/{version}/{arch}/download`
  供手工拷贝探针包。向导侧「检测回连」复用 `GET /probe-deployments/{id}`。回归：
  `tests/deployment/test_manual_bootstrap.py`（3 项）。
- **按钮不再无故变灰**：`blockReason` 计算属性给出唯一原因（未填 IP / 未测通 / 未勾目录），`ready` 由其派生；
  改了 IP、端口、用户名、认证方式或凭据都会让上一次连通性测试失效，避免拿旧结果提交。回归：
  `frontend/src/__tests__/task-wizard-state.test.ts`（7 项）。
- **规则共用（网络 ← 文件）**：`services/policy_groups.py` 新增 `network_rule_overlay` / `merge_network_rules`，
  `application/analysis.py` 组装 `dlp_policy` 时合并**启用且 scope 含 network** 的策略组指纹/关键词/类别，
  这样「文件扫描确认的指纹」在流量侧同样生效（此前只写入策略组，网络侧读的是 `dlp_policy.fingerprints`，
  两半各跑各的）。回归：`tests/test_network_rule_sharing.py`（3 项）。
- **传输对象绑定到具体文件**：`services/data_objects/queries.py::files_by_content_hash` 按内容哈希（SHA256，
  与传输对象同一口径）找回 `ACTIVE` 的 `asset_instances`；`GET /dlp/transfers` 给每个对象加
  `files` / `file_bound`，数据流动报告新增「对应文件」列与详情抽屉段落。回归：
  `tests/test_transfer_file_binding.py`（3 项）。

**待办 / 未做**
- **检查任务的服务扫描沿用既有 `network_scan_task`**（nmap `-sV` 指纹 + `cve_lookup_enabled` CVE 关联 +
  nuclei 模板匹配），本批只把它接进向导，未改动扫描实现本身；nuclei 模板是否随镜像就绪需在真机确认。
- 规则共用**只做了指纹/关键词/类别**（策略组 → 网络）。反向（网络侧 `dlp_policy.categories` 收窄文件侧）与
  「策略组 rule_ids 下发到流量分析」未做，需要先定口径。
- 后端全量回归、镜像重建与真机端到端（点选下发、手动部署回连）尚未完成。

## 第三十三批：菜单收敛与数据安全评估（2026-09-21，进行中）

用户目标：菜单从 11 项收敛到 6 项（资产中心 / 任务中心 / 数据资产 / 数据流动与防护 / 文件证据 / 策略中心），
数据安全评估作为「数据资产」下的一个 Tab（不再单独成页）；检测规则库归「策略中心」并支持策略分组，下发任务时勾选
策略组；采集来源等下发必要项归「任务中心」；出境管理只在「数据流动与防护」出现一次；所有展示只出现一遍。
非文本数据（Word/PDF/Excel/图片/数据库/压缩包）要有内容检查方法，**OCR 放服务端**（需 OCR 的字节上传到平台分析，
减轻探针负担）；压缩包做有界递归解压，加密/无法解析的报告「无法解析」。

用户已定：策略分组用**数据库表**保存；数据库等重要数据**映射到本地持久化目录**，避免重建后丢失。

**已完成（第三十三批 批次 1：后端策略分组 + Docker 本地持久化）**
- `backend/app/models.py` 新增 `PolicyGroup`（策略组：规则 id + 类别/关键词/阈值 + 适用范围 file/network/database）。
- `backend/alembic/versions/0018_policy_groups.py`（`down_revision=0017_file_sources`，幂等、不改历史迁移）。
- `backend/app/services/policy_groups.py`（validate/serialize/apply_values，未知字段与越界值一律拒绝）。
- `backend/app/api/policy_groups.py` + `v1.py` 注册一次：`GET/POST /policy-groups`、`GET/PATCH/DELETE /policy-groups/{id}`；
  删除守卫：仍未完成的任务若快照引用了该组则 409。
- `backend/tests/test_policy_group_boundaries.py`（路由面冻结、只注册一次、无重复路径、服务不重定义规则）。
- `docker-compose.yml` / `docker-compose.dev.yml`：命名卷改为本地绑定目录 `${DATA_ROOT:-./deploy-data}/{postgres,redis,backend}`，
  删除顶层 `volumes:`；`.gitignore` 忽略 `deploy-data/`；`docs/数据安全工具箱作业指导书.md`、`docs/部署与运行手册.md`
  补「本地持久化 + 从旧命名卷一次性迁移」说明。

**验证**：`ruff check` 新文件仅剩与既有 `profiles.py` 同款的 B008（历史存量写法）；`python3 -m ast.parse` 全部通过；
`docker compose config -q` 在 base / +prod+dev / +integrations 三种合并下均 exit 0，绑定路径解析到 `deploy-data/*`。
未跑 pytest（host 无 py3.11 且无 venv，需重建后端镜像后在容器内跑）。

**已完成（第三十三批 批次 2：评估聚合 + 出境判定）**
- `backend/app/api/assessments.py`（6 个只读端点）与 `backend/app/services/assessments/`
  （`envelope` + `classification/exposure/compliance/flow/egress/overview`），统一五段式信封、每卡带分母。
- `backend/app/services/egress_regions.py`（白名单 > 黑名单 > 特殊网段 > 静态 CIDR→地区表；无表降级「无法判定」）
  与 `GET/POST /api/v1/egress/policy`（挂在 `api/extensions.py` 的 DLP/flow 域）。
- 测试：`test_assessments_api.py`、`test_assessment_boundaries.py`、`test_policy_groups.py`、
  `test_policy_group_boundaries.py`（15 项全通过）。

**已完成（第三十三批 批次 3：前端收敛与部署）**
- `router/menu.ts`/`router/index.ts`：11→6 菜单；`DataAssetHub`（3 视图 + 评估）、任务中心、策略中心、
  数据流动与防护四个 Hub；旧顶层路由重定向，详情路由保留。
- 评估 UI：`AssessmentPanel` 单一渲染五段式；`api/assessments|policyGroups|egress.ts`。
- 验证：`vue-tsc` 通过、`vitest` 277 项通过；实际部署 `source-*` 栈（API 8000 / 控制台 8080）健康，
  迁移 head `0018_policy_groups`；旧 `0916_v27` 栈已停并清理容器与镜像。
- Git：`9cb08b2`（后端+基础设施）与 `d67c989`（前端）已推送 `origin/develop`。

**待办（第三十三批 批次 4）**：非文本数据抽取与服务端 OCR（docx/doc/xls/pdf/图片/压缩包有界解压，
加密/无法解析如实标注；需 OCR 的字节上传平台分析）；把 `NetworkDlp` 的策略/规则控件物理搬入策略中心；
全量后端回归补跑。

## 第三十二批：探针自带运行时（探针 3.7.0，2026-09-21）

用户要求：继续完成对探针的修改。承接 2026-09-21 上午已改到工作树的探针 3.7.0 自带运行时（分发包自带
解释器/依赖/抓包工具、平台预检走同一运行时、探针包与平台补丁镜像已构建），本轮把它收尾成可交付状态：
补文档、对齐单元模板与安装脚本、重建镜像并切换运行栈、重出离线交付包。**不改变采集身份**：仍是
`dstprobe` + `NET_RAW`/`NET_ADMIN`/`DAC_READ_SEARCH`，不改成 root 服务（用户既有要求）。

已完成源码（本轮）：
- `probe/README.md` 改成自带运行时口径：包内含私有 CPython 3.11、依赖、`dumpcap`/`tcpdump`、库闭包、
  私有加载器与 CA，目标机不需要 Python、pip、apt、wheel 或抓包工具；新增「升级与回退」小节（换包目录重跑
  `install.sh`，identity/config/spool 保留）与卸载入口，并写明运行时树 `root:root`、不可被 `dstprobe` 改写。
- `probe/data-security-toolbox-probe.service`（随包分发的单元模板）的 `ReadWritePaths` 与 `install.sh`
  生成的单元对齐为 spool/rules/cache/config 四个目录，消除模板与生成物的漂移。
- `scripts/build_probe_packages.py` 删除已无用的 `BIN_NAMES`（3.7.0 起抓包工具在 runtime 内，
  不再有 `probe_packages/bin/<arch>/` 这条路径）。
- `backend/app/deployment/preflight.py` 修正导入顺序（ruff I001，本批新增项归零）。
- 文档同步自带运行时口径：`docs/offline-package.md`（前置条件不再要求主机 Python，补「先
  `build_probe_runtime.py` 再 `build_probe_packages.py`」的打包顺序与实测数据）、
  `docs/部署与运行手册.md` §5.5 改写、`docs/architecture.md` 补探针运行时与预检说明。
- **启动链路也不依赖目标环境（本批新要求：下发后不依赖目标环境就能跑）**：
  - `probe/run-probe.sh` 只用 shell 内建命令定位自身目录（去掉 `dirname`——systemd 的最小环境里没有
    可靠 PATH），自设 `PATH=/usr/sbin:/usr/bin:/sbin:/bin`，导出 `PYTHONUTF8=1`/`PYTHONIOENCODING=utf-8`，
    再 exec `runtime/bin/python -X utf8 -s probe/probe.py`。
  - 语言环境必须固定：systemd 启动时 `LANG` 未设置，CPython 会退回 C/POSIX 语言环境、stdio 按 ASCII
    处理，中文日志（中文文件名、规则包消息）会被转义甚至抛 `UnicodeEncodeError`。随包单元模板
    `probe/data-security-toolbox-probe.service` 与 `install.sh` 生成的单元都加了
    `Environment=PYTHONUTF8=1 PYTHONIOENCODING=utf-8`。
  - `probe/install.sh` 增加主机工具前置检查：`tar systemctl useradd id chown find dirname mktemp` 缺任一个
    就一次性列出全部缺失项后退出（运行时自带，但安装器本身要用这几个工具），并用 `-X utf8` 调
    `runtime_check.py`。
  - `probe/runtime_check.py` 增加运行时布局完整性检查（`bin/{python,dumpcap,tcpdump}`、`lib/ld.so`、
    `python/bin/python3.11`、`ca-certificates.crt`）与「解释器必须来自包内 `python/`」断言（`sys.base_prefix`），
    防止主机解释器被顶替进来。
  - 冒烟脚本 `scripts/probe-runtime/{smoke-install.sh,smoke.py}` 增加：空环境 + `LANG=C` 时启动器仍可用、
    经自带解释器在 C 语言环境下写 UTF-8 中文文件、缺配置时报错不含 `Unicode*Error`、逐个导入 runtime 内
    76 个扩展模块、`sys.executable`/`prefix`/`base_prefix` 都在 runtime 内、单元与启动器必须含
    `Environment=PYTHONUTF8=1` 与 `-X utf8`。
  - 新增静态回归 `backend/tests/deployment/test_probe_self_contained.py`（5 项）：启动器只用内建命令并带
    `-X utf8`、单元固定语言环境、安装器缺工具即退出且不调用 pip/apt/主机 `python3`、探针源码不调用主机
    解释器、`runtime_check.py` 覆盖 `requirements.txt` 全部依赖。
- **判据**：主机只需要 systemd 与基础 coreutils/shadow 工具；平台 `README.md`、`docs/部署与运行手册.md`§5.5、
  `docs/user-guide.md`、`docs/数据安全工具箱作业指导书.md`、`docs/offline-package.md`、`probe/README.md` 与
  包内交付 README 都按此改写（此前仍写「需要 Python 3.11+」「系统 Python 过旧需另装」）。

验证（本轮真实执行）：
- **离线整包安装冒烟**（`scripts/probe-runtime/smoke-install.sh`，一次性 `ubuntu:22.04`、`--network none`、
  仅挂 `NET_RAW`/`NET_ADMIN`）：分别挂载仓库包与**交付包内**的 `probe_packages/probe-3.7.0/amd64`，
  两次都 PASS——容器内无 python3/pip/dumpcap/tcpdump，旧 venv 不被采用，`run-probe.sh` 可执行，
  `/proc/self/maps` 只引用 runtime 内的 .so（76 个自带扩展模块全部可导入，`sys.executable`/`prefix`/
  `base_prefix` 都在 runtime 内），TLS 根/DNS/XLSX/regex/共享引擎/HTTP 与真实 `dumpcap` 抓包全部通过，
  重装保留 `probe.token` 与 spool，`--keep-data` 卸载保留数据；本轮新增的「空环境 + `LANG=C`」项也在其中
  （`env -i LC_ALL=C LANG=C run-probe.sh --help` 有 usage、经自带解释器写出 UTF-8 中文、缺配置的报错不含
  `Unicode*Error`）。
- **arm64 包在 qemu 下同样跑通**（`--platform linux/arm64`）：除真实抓包外全部 PASS。qemu-user 不能翻译
  libpcap 需要的 socket ioctl（`dumpcap -D` 都因 `SIOCETHTOOL(ETHTOOL_GLINK)` 失败），属模拟器限制，
  冒烟脚本据此显式打印 `SKIP: real capture under emulation` 而不是误报失败；同一份包在 amd64 原生执行时
  抓包仍是硬断言。arm64 抓包能力待在原生 arm64 主机上复验。
- 后端：`backend/tests/deployment` + `shared` + `probe` + `test_probe_delete` 全通过（只有
  `test_probe_identity` 因 Windows 无 POSIX 权限位失败，与基线同项）；全量 `backend/tests` = **6 failed**
  （Windows chmod 1 / 本机无 Redis 1 / 本机无 tshark 3 / 本机缺原生导出器 1），与基线逐项一致，
  日志 `data/regression-backend-20260921-probe-runtime.log`。
- ruff：本批涉及文件与基线逐项一致，`preflight.py` 还少 2 项（删掉 `json` 导入 + 导入排序）；
  `git diff --check` 通过。
- 平台镜像与运行栈：legacy builder 重建 `source-backend`/`source-worker`（worker 镜像另打
  `source-beat`/`source-deployment-worker` 标签）与 `source-frontend`（旧前端镜像早于第三十一批的页面解耦，
  本批一并重建，把工作树前端改动纳入交付镜像），重建 5 个应用容器后 `/api/v1/health` 全绿
  （worker 能力 tshark 4.4.18 / zeek 9.0.0 / suricata 7.0.10 52270 签名、`features.test_data_import=false`）、
  `openapi.json` 2.14.0、`alembic current` = `0017_file_sources (head)`、管理台 8088 返回 200；三个容器内
  `app/deployment/{preflight,runtime,package}.py` 与工作树 SHA256 逐字节一致，前端容器 `assets/`（218 个）
  与本地生产构建逐字节一致。构建日志 `data/rebuild-20260921-probe-runtime-build.log`。
- 补丁标签与镜像清理：上午打的 `dst-toolbox/*:2.14.0-probe3.7.0` 与最终交付镜像只差
  `app/deployment/preflight.py` 的导入顺序（镜像内 `28b6ce64…` vs 工作树 `f4adbc1d…`，语义相同），现已改用
  `docker tag` 指向本批验证过的镜像（backend `14794f029d31`、worker/beat/deployment-worker
  `82e3156c5141`），旧构建 `42e696deac67`/`6d4e52712955` 与悬空镜像一并删除（`docker image prune -f`
  回收 2.9 GB），另删掉 2 个探针 runtime 构建遗留的退出容器（`python /tmp/collect.py`，退出码 1）。
- 交付包（工作区 `dist-linux-build/`）：`make_bundle.py` → `save_images.py` → `finalize_bundle.py`
  （`DEPLOY_REV` r2 → **r3**，文档修正后 **r4**，本批启动链路加固与文档口径统一后再进 **r5**）→
  `verify_bundle.py` PASS（**1005/1005** 校验和、0 个非法 UTF-8 名、0 个缺可执行位、8 个镜像标签齐全；
  比上一版多 1 个文件 = 本批新增的 `backend/tests/deployment/test_probe_self_contained.py`）；staging 内
  `docker compose -f docker-compose.yml -f docker-compose.offline.yml config -q` 通过且 8 个服务全部指向包内
  标签（镜像未变，本批未重跑 `save_images.py`）。
- 交付文档收尾：平台 `README.md` 的探针前置条件与 systemd `ExecStart` 说明、包内交付 README
  （`make_bundle.py` 生成）的探针段落都改成「自带运行时 + 只需 systemd/基础工具」口径（含 `run-probe.sh`
  自设 `PATH`、固定 UTF-8 的说明），并修掉过期的「启动时会打印 `deploy.sh r2`」（改用 `{DEPLOY_REV}`）、
  残留孤句、以及「install.sh 会 `setcap`、无 tcpdump/dumpcap 时退化为 Lite 模式」这类与包内容矛盾的排错行。
- 本批最终交付包：外层 `dst-toolbox-2.14.0-linux-x86_64.tar.gz` = **1 439 181 476 B**（1.34 GB），sha256
  `42adc92dacdea2369a3a1ba3a9e1a51ac6c0e2cad047fea5b9eb1b41bcfe078a`；`deploy.sh` sha256
  `8ac151e835e3726bd59e524df75a7e9a963f7a14de48f67f8c3bc220c0eaa91f`（自报 **r5**）；包内探针包
  `probe-3.7.0-amd64.tar.gz` sha256 `0ac9fe87e3676bb6ef85186679ca0e796b5b7cfb6f9c2459f843aa0132ac2ce3`、
  `probe-3.7.0-arm64.tar.gz` sha256 `027ad5038917914bfa752aaa56df75694e30583f5d643d8a261feb2bf89a6433`；两者与工作树
  `probe_packages/probe-3.7.0/<arch>/` 的 SHA256 逐个相同，`runtime.tar.gz` 仍是
  `b7a5f3aba812f28f34e715e2a63d8d6cf786c5abfdd49eff811c6dc496e4baca`（运行时本批未重建）；镜像归档
  1255.1 MB（beat/deployment-worker 与 worker 同一镜像 ID，`docker save` 已去重）。上一版外层包
  `6ebd6215…` 与之配套的 `c0eeb372…`（r4）随之作废。

未做 / 待用户决定：
- **真机就地升级（192.168.191.130）未执行**：需要用户确认目标与可操作窗口；identity/config/spool 保留由
  `install.sh` 保证（冒烟测试已覆盖）。升级后应核对心跳里的 `agent_version=3.7.0`、capabilities 与一次真实
  指定目录采集。
- 平台自报版本仍是 2.14.0（未升 2.14.1）：本次按「同一发布版本的交付更新 + 探针小版本」处理，
  `2.14.0-probe3.7.0` 镜像与 r5 交付包即交付物；若要单独发平台补丁版，需要连带改
  `backend/app/main.py`、`frontend/package.json` 与 lock、`docs/versioning.md` 后再出包。
- 探针 `/tmp` 的 `PrivateTmp` 宿主目录隔离仍未处理（用户此前要求不为此改成 root 或关闭沙箱，读不到的目录
  按覆盖缺口如实上报）。
- arm64 抓包未在原生环境验证：本机只有 qemu（qemu-user 不能翻译 libpcap 的 socket ioctl），arm64 冒烟
  显式跳过真实抓包，其余项通过；要给出 arm64 抓包证据需一台原生 arm64 主机。
- 已提交并推送到 `origin/develop`（`c903768`）并创建注释标签 `v2.14.0`；未在真机跑
  `sha256sum -c CHECKSUMS.sha256`（本地 `verify_bundle.py` 已等价校验）。
- 已知的测试隔离问题（本批未引入、也未修）：把 `tests/test_probe_delete.py` 与 `tests/deployment` 放进同一
  个 pytest 进程时 `tests/deployment/test_enrollment.py` 两项会因共享 DB 状态报 `IntegrityError`；分开跑
  各自全通过，全量 `backend/tests` 的 6 项失败与本批前逐项一致。

## 第三十一批：数据库连接页状态与视图解耦（2026-09-21，工作树未提交）

承接第三十批，用户确认继续 `DatabaseConnections` 前端状态解耦。本批只移动职责，保留现有 API、
口令提交规则、选择/清空时机和请求顺序；没有修改后端、探针或真实数据。

已完成：
- `useDatabaseConnections.ts` 331 → 120 行，保留连接列表、选中目标、删除/连通测试与跨流程刷新协调；
  用 computed 选中连接和显式回调连接子状态，旧返回字段及 `ConnectionForm` 类型导出保留。
- `useDatabaseConnectionForm.ts`（93 行）：创建/编辑草稿、校验、默认端口与保存；编辑空密码仍不提交
  password，成功后清空本地密码，失败仍保留草稿供重试。
- `useDatabaseScope.ts`（86 行）：库表读取、勾选、范围限定与采集派发，派发后调用注入的任务刷新；
  `useDatabaseScans.ts`（59 行）：连接详情、任务历史/抽屉与唯一的 5 秒 timer，初次加载后启动、卸载清除。
- `DatabaseConnections.vue` 323 → 186 行。表单与详情抽屉分别迁到
  `components/DatabaseConnectionForm.vue`（84 行）和 `DatabaseScanDetail.vue`（83 行），通过 props、
  v-model 和 save 事件绑定，子组件不调用 API；标签函数集中在 `databaseConnectionPresentation.ts`。
- 统计卡的 enabledCount/reachableCount 移入协调入口。对照本轮修改前快照，原有函数体在替换注入依赖后
  一致；将两个子模板还原并归一缩进后，页面模板与原版一致（仅调整 model/save 事件接线）。

验证（本轮真实执行）：
- 修改前：typecheck 通过，数据库连接状态/组件 15 项通过。
- 修改后：typecheck 通过；数据库连接状态/组件 22 项通过（新增 7 项）；全量 vitest 31 文件 / 277 项通过。
- 新增覆盖：保存失败保留草稿、切换目标后范围/派发/轮询使用新连接、读取范围失败、历史刷新失败保留
  服务端数据、卸载停止轮询、子表单提交与密码清空、清空选表后按整库派发。
- `git diff --check` 通过；`VITE_DEMO_MODE=false npm run build` 通过（既有大 chunk 提示）。

未做：未提交、未重建 Docker 镜像或离线包、未操作真实目标、未做浏览器/真机复验；本批没有混入
异步竞态修复或调整原有选择清空规则。第三十批改动和其余用户工作树内容保留。

## 第三十批：规则源与网络 DLP 域解耦（2026-09-20，工作树未提交）

用户诉求：查看本机项目 → 解耦规则、网络 DLP 等核心内容 → 优化业务之间的逻辑（要整体）。
基线 a51bffe；改动仍在工作树、未提交，不下载、不构建、未部署。

已完成源码（本轮）：
- 网络 DLP 拆成 `backend/app/services/dlp/`：`constants`（资源上限、内置兜底策略、自身流量标记）、
  `policy`（`normalize_policy` / `alertable` / `host_internal` / `excluded_networks`）、
  `self_traffic`（自身管理通道身份判定）、`capture`（`reassemble` / `dechunk` / `http_objects` /
  `looks_like_text`）、`detect`（`inspect_content` / `analyze_capture`）。`services/dlp_service.py`
  460 → 63 行，只剩兼容重导出，旧调用方与回归测试继续可用。
- `detect` 里把原来一整个函数做完的事抽成有名字的步骤：`stream_objects`（没有 HTTP 解析器的明文协议
  仍做有界文本扫描）、`object_metadata`、`store_object_bytes`（临时文件 + `os.replace` 原子落盘）、
  `build_finding`；正文哈希只算一次，`import os/tempfile` 移出循环。
- 打断「规则库 ↔ 网络 DLP」互导：`masked()` 移到中立的 `backend/app/services/masking.py`
  （此前 `rule_library` 从 `dlp_service` import 它，DLP 侧又 import 规则库的置信度常量）。
- 规则源单一映射：`rule_library.stored_rule()` 是「规则库的一条规则 → 共享规则/规则包格式」的唯一映射，
  `sensitive_engine.analyst_rules()`（平台扫描）与 `ruleset_service.import_working_rules()`（探针工作副本）
  共用；删掉 `ruleset_service` 里第二份映射与自带的 `_SOURCE_BY_LEGACY` 表。
  **口径修复**：工作副本此前漏了平台侧的 `email_shape` 校验器，同一条导入规则在平台与探针上命中不同，
  现在两侧字段（含 `validator`）由同一处产生，规则包字节只在这一处变化（人工发布后才到探针）。
- 规则库布局单一入口：新增 `rule_library.rule_store_directory()` / `rule_store_files()` /
  `set_rule_enabled()`；`analyst_signature()`、`api/rule_presenter.py`、`PATCH /dlp/rules/{id}`
  不再各自 glob `data/integrations/dlp_rules/*.json`，`api/libraries.py` 不再直接读写规则库 JSON。
- 调用方迁到真实位置（不改 API/表/任务名/探针协议）：`engine/dlp_engine.py`、`services/pcap_files.py`、
  `api/{extensions,libraries,rule_presenter}.py`、`application/analysis.py`；回归测试里的 monkeypatch 目标
  迁到真实查找位置 `app.services.dlp.capture`（不再为迁就旧测试在实现层留转发）。
- 新增边界回归 `backend/tests/test_dlp_boundaries.py`（7 项）：分层文件集合、无 `app.api`/`app.workers`
  依赖、只有检测层引用敏感引擎、规则库不再 import 网络 DLP、兼容外观只做重导出、单一映射，
  以及「导入规则在规则包里带着平台侧同样的校验器」。
- 文档：`docs/architecture.md` 新增「网络 DLP 域分层与规则源单一映射（2026-09-20 第三十批）」，
  `docs/解耦操作指南.md` 新增第 2 节耦合行与「I. 规则源与网络 DLP 分层」批次记录。

验证（真实执行，本机 `.venv` Python 3.13.5）：
- 后端全量 `pytest -q`：850 项 / 6 项失败 / 0 错误 / 1 跳过（843 通过）。对照本轮开始前同环境基线
  （843 项 / 同样 6 项失败），失败用例集合逐项一致、新增 7 项全部通过。
  本机跑全量必须先设 `SECRET_KEY`（测试不继承仓库 `.env`），否则会多出 20 项凭据相关失败——
  这是环境差异，不是本轮改动。
- 本轮相关用例单独复跑全绿：`test_dlp_boundaries.py`、`test_dlp_detection_quality.py`、
  `test_rule_libraries.py`、`test_rule_boundaries.py`、`test_rule_execution.py`、
  `tests/shared/test_engine_wiring.py`、`test_bugfix_regressions.py`、`test_v22_extensions.py`（76 项）。
- ruff 只对新增/改动文件负责：新文件无新增违规；`dlp_service.py` 26 处长行拆开后共 24 处（未新增），
  未批量重排老文件。
- 6 项基线失败与本轮无关：`tests/engine/test_protocol_engine.py::test_protocol_engine_runs_on_fixture`、
  `tests/probe/test_probe_identity.py::test_first_registration_persists_identity`、
  `tests/test_api.py::test_health`、
  `tests/test_pcap_workbench.py::test_native_exporter_retains_response_without_python_reassembly`、
  `tests/test_protocol_service.py::test_stream_tshark_watchdog_timeout`、
  `tests/test_protocol_service.py::test_parse_pcap_total_exceeds_index_limit`。

未做（本轮不宣称）：前端未改动（`DatabaseConnections.vue` + `useDatabaseConnections.ts` 偏大，属后续批次）；
`models.py` 未包化；探针未模块化；镜像与离线包未重建；真机未复验；探针侧规则要等人工发布。

## 当前整改批次：资产与数据安全增强（2026-09-20，未完成）

用户已要求按 docs/资产与数据安全增强-Agent执行任务书.md 实施；本节覆盖旧任务“只做结构移动”的范围约定。
基线 a51bffe；本批改动仍在工作树、未提交。不要回滚这些修改。
后端/worker/前端镜像已于 2026-09-20 重建并切换（见下「部署」）；探针源码改动**未出包、未升级任何主机**。

已完成源码（第一批：止增与诊断）：
- DataEngine 按 context.target_type + context.path 识别原始抓包容器，只阻止登记为文档资产，保留 YARA/检测路径及提取文件；显式上传的普通文件不按 .pcap 后缀排除。
- run_pipeline 将 scan_status/scan_reason 保存在 DataAsset.extra，修复解析说明丢失。
- collection_outcome 统一采集终态文字和预算原因；新报告持久化准确阶段，旧报告由 task_presenter 兼容展示，不改写历史 Task。
- 采集任务页读取 directories_scanned（兼容 directories_visited），避免目录数始终显示空。
- 探针目录入口区分不存在/非目录/符号链接/无权限/其他系统错误；错误报告 coverage.complete_scope 不再误报 true。
- scripts/audit_capture_assets.py：只读核对历史错误投影，与 PcapRecord.storage_path 文件名精确匹配，并限定 Unknown/file/空 columns/空 extra/同名 source/唯一抓包匹配。只生成候选，不删除。

已完成源码（第二批：预算截断语义，2026-09-20 下午）：
- `shared/scanning/budget.py` 把「目录枚举终止」与「内容采样截断」分开记账：`row_budget` / `single_file_limit`
  只进内容维度（`content_complete`），不再代表遍历结束；枚举维度（文件/目录/字节/超时/取消/资源/未配置/不可读）
  由 `enumeration_complete` 表示，且 `termination_reason` 优先报枚举原因。`complete` / `complete_scope`
  仍是「两者都完整」的保守口径，未新增可退役未访问资产的路径。
- `probe/data_assets.py` 的遍历改判 `enumeration_complete`：一个长文件只损失它自己的样本，不再终止整棵目录；
  读不到的路径按 `unreadable` 记录终止原因（`complete_scope` 保持 false），`coverage` 新增两个布尔字段。
- `services/data_objects/progress.collection_outcome` 与采集任务页据此措辞：目录已枚举完、只有内容被截断时显示
  「部分文件内容达到读取行数上限」，不再与「目录不存在/未遍历」共用一句话；缺字段的旧报告措辞不变。

已完成源码（第三批：命中原文回传，2026-09-20 傍晚）：
- 用户明确要求「发现敏感内容之后要回传原文」，这是对既有「检测证据不含匹配值」契约的**有意变更**：
  `DetectionHit.matches` 携带**有上限**的样本（`value` = 命中原文，`context` = 该值所在行），
  落库在 `DetectionEvidence.extra['matches']`（不新增列，因此无新迁移，`0015_alert_hits` 仍是 head）。
- 上限两侧各自强制：探针 `shared/sensitive_detection/engine.py` 每条命中最多
  `MAX_RETURNED_MATCHES=3` 条、`value ≤ MAX_RETURNED_CHARS=120`、`context ≤ MAX_CONTEXT_CHARS=240`
  （超宽行按命中位置取窗口，保证值本身不丢）；平台 `services/data_objects/evidence.py` 收到主机上报后
  **再次**按同样上限重裁、只接受非空 `value`，避免探针被替换后放大回传。
- 只有 `matches` 允许出现原文：`shared/sensitive_detection/report_guard.py` 把它列为 `RAW_TEXT_KEYS`
  （该子树内不脱敏、不截断），`Evidence` 与引擎 `ScanReport` 依旧不持有任何值；只命中字段名/关键字的
  命中 `matches` 为空列表——表示「没有可回传的原文」，不是「没有命中」。
- 平台出口：`GET /api/v1/detections/{id}/evidence` 每条证据新增 `matches`，响应新增
  `matches_returned` 与更新后的说明文案；`DetectionEvidence` 表仍无任何存值列。
- 前端：实例详情与对象详情的「检测证据」抽屉加宽到 760px，展开行显示原文（value + context）；
  旧探针或仅字段名命中显示「这条证据没有回传原文（旧版探针，或只命中了字段名/关键字）」。
- 兼容性：旧报告、旧证据行没有 `matches`，读取端一律按空列表处理，不伪造也不报错。

第一批验证：
- 修改前 DataEngine 6 项通过；修改后引擎/任务呈现/边界 34 项通过；新增持久化回归后 test_collection_outcome 5 项通过，相关后端累计 77 项（非全量）。
- 探针盘点/采集 API/任务生命周期 42 项包含在上述累计 77 项中，全通过；权限错误测试用隔离模拟，尚无真实 Linux root 验证。
- 前端 typecheck 通过，26 文件 231 项单测通过；生产构建通过（既有大 chunk 提示）。
- 真实只读审计 1457 条候选（持续增长的时点值），明细 data/capture-asset-audit-20260920.json（本地忽略文件，后续可重新生成）。未删除任何资产、PCAP 或检测证据。

第二批验证（2026-09-20 下午）：
- 隔离对照：把 `enumeration_complete` 临时替回 `complete`（模拟改动前的遍历判断），同一棵目录树只返回长文件本身
  （`['dpkg.status.0']`），`nested/customers.csv` 永远到不了——与任务 4441 `/var` 只出 9 个资产的现象一致；
  改后同一场景两个文件都在，`enumeration_complete=true`、`content_complete=false`、`complete_scope` 仍为 false。
- 后端相关回归 303 项通过（含 shared/scanning、probe 盘点、采集 API、任务生命周期、data_objects、scan_profiles），
  其中新增 5 项：预算维度拆分 2 项、长文件不终止遍历 1 项、终态措辞 2 项。
- 前端 `npm run typecheck` 通过；vitest 26 文件 232 项通过（新增 1 项）；`npm run build` 通过（未启用 VITE_DEMO_MODE）。
- ruff 对改动文件无新增告警（既有 E501/I001 历史存量未动）；`git diff --check` 通过。

第三批验证（2026-09-20 傍晚）：
- 后端全量 747 项：**740 passed / 6 failed / 1 skipped**；6 项失败与既有基线逐项相同
  （Windows chmod 语义 1、本机无 Redis 1、本机无 tshark 3、本机缺原生导出器 1），
  并在 HEAD `a51bffe` 的干净 worktree 上复跑同一组，失败集合完全一致——不是本批引入。
- 定向回归：`tests/shared`、`tests/probe`、`test_data_objects.py`、`tests/engine` 全通过；本批新增/更新
  引擎侧 3 项（原文只进 `matches`、条数与长度上限、落行上下文）、探针报告 2 项、平台侧 2 项（重裁与持久化）。
- 前端 `npm run typecheck` 通过；vitest **27 文件 234 项**通过（新增组件级 2 项：抽屉渲染原文、
  无原文时如实说明）；`npm run build` 通过，dist 内无 DEMO 模式标记。
- ruff 统计与 HEAD 完全一致（164 项历史存量，无新增）；`git diff --check` 通过。

重建与镜像/容器清理（2026-09-20 傍晚，含第三批原文回传）：
- 按用户要求重建整个项目并切换（legacy builder）：backend `--target api`、worker `--target analysis-worker`
  （另打 beat / deployment-worker 标签）、frontend 单独构建；`docker compose -p source -f docker-compose.yml
  up -d --no-build --force-recreate backend worker beat deployment-worker frontend` 重建 5 个应用容器，
  postgres/redis/flower 未动。新镜像：backend `78fb7da8c119`、worker/beat/deployment-worker `e4a39813cc63`、
  frontend `cc4b658ed510`。
- 部署证据：`/api/v1/health` 全绿（api/database/redis/celery ok、worker 能力 tshark 4.4.18 / zeek 9.0.0 /
  suricata 7.0.10 52270 签名、`features.test_data_import=false`）；迁移仍 `0015_alert_hits (head)`；
  容器内 10 个关键文件（`shared/sensitive_detection/{engine,result,report_guard}.py`、`shared/scanning/budget.py`、
  `app/services/data_objects/{evidence,progress}.py`、`app/api/data_catalog.py`、`app/models.py`、
  `app/engine/data_engine/engine.py`、`app/application/analysis.py`）与工作树 SHA256 逐字节一致；
  frontend 容器 213 个构建产物与本地 `frontend/dist` 逐字节一致（多出的 `50x.html` 是 nginx 自带错误页）。
- 真实/合成只读验证：容器内用容器自身管理员会话读真实接口，最近的真实证据
  `GET /api/v1/detections/112/evidence` 返回 200，响应含 `matches` / `matches_returned`（该行来自旧探针，
  `matches_returned=0`），`DetectionEvidence` 列清单仍无存值列；worker 容器内用合成文本调用同一份引擎，
  命中带回原文（`value`/`context` 与合成输入逐字相等），平台侧重裁把 5 条 × 400 字符压回 3 条 × 120/240 字符。
- 清理（按用户「不要留下历史镜像容器等」）：删除 2 个遗留的 `source-backend` 测试容器（`dst-test-full`/`dst-test-inc`），
  `docker image prune -f` 回收悬空镜像 **11.01GB**、`docker builder prune -f` 回收构建缓存 **2.1GB**，
  并删除两组旧回退标签 `pre-capture-asset-fix-20260920` / `pre-v2.13.0-20260920`（共 10 个 tag）。
  Docker 镜像计账 82.98GB → **31.35GB**，容器层 1.529GB → 992MB，悬空镜像与构建缓存归零；
  剩余 9.97GB 可回收镜像属于其他项目（opendlp/openaev），未触碰；C: 可用 45.8GiB。
- **本轮之后没有可回退镜像**：回退方式为从 git 提交重新构建（下一步先建卷/标签再重建，见「下一位 agent」列表）。

部署（legacy builder，2026-09-20）：
- 回退标签 `source-backend|source-worker|source-beat|source-deployment-worker|source-frontend:pre-capture-asset-fix-20260920`
  曾指向部署前的镜像（该组标签已在傍晚清理中删除，见上「重建与镜像/容器清理」）；
  构建用 `DOCKER_BUILDKIT=0`，backend target `api`、worker target `analysis-worker`
  （另打 beat / deployment-worker 标签）、frontend 单独构建。
- 容器重建后：`/health` 全绿（api/database/redis/celery ok，worker 能力 tshark 4.4.18 / zeek 9.0.0 / suricata 7.0.10 52270 签名，
  `features.test_data_import=false`），迁移仍 `0015_alert_hits (head)`，前端首页 200。
- 部署证据：容器内 `app/engine/data_engine/engine.py` 含 `capture_container`、`progress.py` 含 `enumeration_complete`；
  在 worker 容器里用合成上下文实跑 DataEngine：PCAP 上下文只登记提取文件（`['unsupported.bin']`），
  显式上传的 `user.pcap` 仍被登记；线上前端 `DataAssetJobs-DL7DB-Uz.js` 与本地生产构建 SHA256 逐字节一致（含新措辞、无 DEMO 模式）。
- 真实数据口径：部署前只读审计候选 **1457 → 1491**（旧镜像期间继续增长），部署后 DataAsset 2239 行、PcapRecord 4581 行；
  明细 data/capture-asset-audit-20260920-post-deploy.json（本地忽略文件）。未删除、未改写任何资产/PCAP/检测证据。
- 预算改动在重建后又做过一次「去掉重复私有状态」的重构（行为不变，回归 303 项与重构前一致），因此 backend/worker 镜像
  再次重建并重建容器；部署后的 `shared/scanning/budget.py`、`app/services/data_objects/progress.py`、
  `app/engine/data_engine/engine.py`、`app/application/analysis.py` 与工作树 SHA256 逐字节一致。

复验命令（source 根目录，隔离测试配置由 conftest 固定）：

```powershell
.venv/Scripts/python.exe -m pytest backend/tests/engine/test_data_engine.py backend/tests/test_collection_outcome.py backend/tests/test_data_asset_boundaries.py backend/tests/test_task_boundaries.py backend/tests/test_tasks_reports_boundaries.py backend/tests/probe/test_data_assets.py backend/tests/probe/test_data_assets_scanning.py backend/tests/test_data_asset_probe_api.py backend/tests/test_probe_task_lifecycle.py backend/tests/shared backend/tests/test_data_objects.py backend/tests/test_scan_profiles.py -q
# frontend 目录：npm run typecheck；npm test -- --run；npm run build
```

下一位 agent 的执行顺序：
1. **原文回传的未验证项**：平台侧与探针侧都已改完并部署镜像，但**在线探针仍是旧版本**，没有任何真实证据行带
   `matches`；因此「真实主机扫描 → 原文出现在页面」这条链路目前只有容器内合成文本 + 真实接口契约的证据。
   探针出包升级后，用一台已授权目标的真实扫描确认 `matches_returned > 0` 且页面显示原文。
   同时注意：报告、探针缓存与 `DetectionEvidence.extra` 现在会保存敏感原文，探针→平台链路与库内静态数据
   的保护要求随之提高（此前载荷可证明不含值）——传输加固与静态保护应作为后续任务登记。
2. **回退能力**：本轮清理删除了全部旧镜像标签，仓库里没有可回退镜像。下次重建前请先给当前 `source-*:latest`
   打一个 `pre-<批次>-<日期>` 标签并保留到验证通过，再按本轮方式清理。
3. 后端/worker/前端镜像已按 legacy builder 重建并切换（见上「部署」）。**未验证项**：部署后还没有新的真实抓包经过分析，
   所以「新抓包不再新增 DataAsset」目前只有运行时合成上下文的证据 + 部署前 1457→1491 的止增对照；
   下一次真实 PCAP 分析任务完成后，用 scripts/audit_capture_assets.py 复核候选数不再增长。
4. 历史候选（现 1491 条）仍只是候选：核对对应分析任务，设计事务内可回退归档与审计修复，仅处理确认的错误投影；
   同步核对图关系/统计，不删除抓包或 Findings，不按后缀批量删除真实文件。
5. 继续 P0：root 运行身份（**用户本次明确要求暂不执行**，等其再次指示）——service/install.sh/所有权与可写目录、PrivateTmp 的 /tmp 可见性、升级/回退脚本、
   scripts/build_probe_packages.py 出包与校验和）。预算截断语义已改完（见第二批），但**只改了源码**：
   在线探针仍是旧版本，必须出包并在明确目标上升级后才算生效。
6. 继续 P1 统计/来源/详情与竞态完整验收。P2 MySQL/PostgreSQL 直连已实施、已部署并真机验证
   （见下「目标数据库直连盘点与规则匹配（2026-09-20 夜，P2）实施与验证」）：
   MySQL/MariaDB 已用用户给的测试库端到端跑通；PostgreSQL 走同一适配层但**没有真实 PG 目标**，只有隔离测试，
   不要报告为已验证。
7. 更新版本/迁移及架构以最终实现为准；新迁移不可回改旧文件。本批新增迁移 `0016_database_connections`
   （另有字段级变更：`coverage` 多两个布尔字段、证据接口多 `matches`/`matches_returned`，旧消费者不受影响）。

联调条件：当前观测 probe 2/test123 为 3.4.1，历史目标 192.168.191.130；/root/home 是否存在尚无远端证据，不能自行改成 /home。
测试数据库在同一主机：MariaDB 11.8.6，本机 127.0.0.1:3306（MariaDB root 是 unix_socket 认证，平台用只读账号 `dst_ro`；
已加 `/etc/mysql/mariadb.conf.d/99-dst-remote.cnf` 把 bind-address 放开到 0.0.0.0，用户给的 3389 是 RDP、目标上没有服务监听它）。
口令只在被 git 忽略的 `.local/db-target.env`；`dst_demo` 是按用户要求创建的测试数据（`.local/db-target-seed.sql`，
建库脚本 `.local/target-db-setup.py`，SSH 助手 `.local/target-ssh.py`，需 `SSH_PASS` 环境变量）。

## 目标数据库直连盘点与规则匹配（2026-09-20 夜，P2）实施与验证

用户要求：平台要能**直接连接目标数据库**做资产整理，并对数据库数据做规则匹配；给了测试目标 `192.168.191.130`
（SSH root/0210），并要求「如果数据库没有数据就创建数据；如果不能远程连接就自己修配置」。本批就是这件事。

已完成源码（仍在工作树，未提交）：

- 新包 `backend/app/services/database_scan/`：
  - `credentials.py`：口令 AES-GCM 加密落库，AAD 绑定 `db:<连接 id>:<用户名>:<密钥 id>`，密钥取
    `DATABASE_CREDENTIAL_KEY`，未配置时由 `SECRET_KEY` 以 `dst/database-credential/v1` 标签派生；空口令不写密文。
  - `adapters.py`：引擎白名单 `mysql`→PyMySQL、`postgresql`→psycopg2；驱动选项白名单
    （`charset`/`sslmode`/`connect_timeout_seconds`/`statement_timeout_seconds`，秒数夹取 1..3600）；
    连接池的 connect 钩子在**每条**连接上执行 `SET SESSION TRANSACTION READ ONLY`，并回读
    `@@session.transaction_read_only`——服务器若回答「可写」直接拒绝采集（`read_only_violation`）。
    表/列标识符一律来自反射，模块里没有任何接收 SQL 文本的入口。
  - `detect.py`：按列复用探针同一份敏感引擎（`SensitiveDetectionContext(source_type="database")`）；
    只有**值命中**才计入 counts/categories，字段名/关键字线索进 `candidates`/`field_only_categories`，
    命中原文沿用探针同一上限（每命中 ≤3 条、value ≤120、context ≤240）。
  - `ingest.py`：表 → `DataObject(database_table)` + `AssetInstance(owner_key=db:<id>, source_kind="database", probe_id=None)`，
    列元数据进 `extra`；检测/证据复用 `data_objects.evidence` 的同一写入口；`retire_unseen` 只在范围完整时才退役。
  - `connection_service.py`：字段校验、只写口令序列化（响应只有 `password_set`）、任务配置快照 + `config_hash`、
    凭据 AAD 校验（用户名/密钥在排队后变更则明确报 `CredentialError`）、单连接同时只允许一个采集任务、
    删除时拒绝与进行中任务竞争且保留已采集资产。
  - `scan.py`：只读连接 → 枚举库/表 → 逐表采样 → 检测 → 落库 → 退役 → 汇总
    （`complete_scope`、`termination_reason` ∈ complete|table_budget|time_budget|read_error|no_tables|cancelled、
    `notes`、按表明细、`table_errors`）；每张表更新一次任务进度，停止请求只在表之间生效，不中断语句。
- 新路由 `backend/app/api/database_connections.py`：CRUD + `POST /{id}/test` + `GET /{id}/schemas` +
  `GET /{id}/tables` + `POST /{id}/scans` + `GET /{id}/scans` + `GET /scans/{task_id}`；
  写操作要求管理员会话并写审计（只记标识，不记口令），响应只含 `password_set`。
- 模型与迁移 `0016_database_connections`（**不可回改**）：新表 `database_connections`；
  `asset_instances` 增加 `owner_key`/`source_kind`、`probe_id` 改可空、唯一键改为 `(owner_key, path)`；
  `detections` 增加 `source_kind`、`probe_id` 改可空。
- worker：任务名 `security_toolbox.database_scan`（`analysis_tasks.database_scan_task`），
  `STOPPABLE_TASK_KINDS` 纳入 `database_scan`（任务中心可停止）。
- 依赖：`backend/requirements.txt` 增 `PyMySQL==1.1.1`。
- 前端：`modules/data-security/DatabaseConnections.vue` + `composables/useDatabaseConnections.ts` +
  `api/databaseConnections.ts`（连接列表、新建/编辑、测试连接、库与表选择、启动采集、采集历史与按表明细抽屉，
  口令只写不读、留空表示不修改），路由 `/database-connections` 与菜单「资产与数据安全 → 数据库直连盘点」；
  实例/对象详情新增来源徽标（探针文件 / 数据库直连）与 `owner_key`，实例表在对象详情里多一列「来源」。
- 测试：新增 `test_database_credentials.py`(9)、`test_database_adapters.py`(10)、`test_database_scan_detect.py`(6)、
  `test_database_scan_ingest.py`(8)、`test_database_scan_pipeline.py`(11)、`test_database_scan_api.py`(19)
  与真机门控 `test_database_scan_target.py`(5，缺 `.local/db-target.env` 时 skip)；前端新增
  `database-connections-state.test.ts`(11) 与 `database-connections-page.test.ts`(4，挂载真实组件渲染模板)。

验证结果：

- 后端全量：`803 passed / 6 failed / 1 skipped`；6 项失败与 HEAD `a51bffe` 基线集合完全一致，全部是本机环境
  （Windows chmod 语义 1、本机无 Redis 1、本机无 tshark 3、本机缺原生导出器 1），本批未新增失败。
- 数据库直连相关 63 项全通过；ruff 统计与 HEAD 逐项一致（24 E501 / 11 B008 / 3 I001 / 1 UP017，无新增）；
  新增包与新增测试文件 ruff 零告警。
- 前端 `npm run typecheck` 通过；vitest **29 文件 249 项**通过；生产构建通过，`dist` 含
  `DatabaseConnections-Cu5CZJWu.js`。
- **真机验证（用户给的测试库，只读账号）**：适配层直连 `192.168.191.130:3306` → `11.8.6-MariaDB-6 from Debian`、
  `read_only=True`；库 `['dst_demo']`；9 张表（含中文表名 `订单明细` 与含空格表名 `order detail`）反射正常；
  故意写入被服务器拒绝（`OperationalError 1792 Cannot execute statement in a READ ONLY transaction`）。
  部署后的完整链路（HTTP 管理员会话 → 建连接 → 测试 → 读库表 → 下发采集 → 真 worker 执行 → 读结果）
  结果：`Success`、9/9 表、样本 213 行、命中 11、检测 9、`read_only=True`、`complete_scope=True`、原因 `complete`；
  逐表：`customers` phone/id_card/email、`payments` bank_card/phone、`secrets` api_key、
  `big_table`/`order detail`/`订单明细` phone、`clean_notes` **零命中**（负对照）、
  `empty_table`/`nulls_only` 保留为元数据且只有字段名候选；`GET /detections/{id}/evidence` 取回 **43 条命中原文**；
  27 个响应体逐一检查，**没有任何响应包含数据库口令**。目标库未被修改（9 张表、行数不变）。
- 部署证据：迁移 `0016_database_connections (head)`；容器内 13 个关键文件（`database_scan/*`、
  `api/database_connections.py`、`0016_*.py`、`models.py`、`api/data_catalog.py`、`evidence.py`、
  `analysis_tasks.py`、`requirements.txt`）在 api 与 worker 两个容器里与工作树 SHA256 **逐字节一致**；
  `database_connections` 表与 `asset_instances.owner_key/source_kind` 已在库中；
  前端容器 `index.html` 与本地 `dist` 哈希一致，新页面 bundle 经 8088 端口返回 200。

重建与清理（2026-09-20 夜，按用户「修改完成后完全重启整个项目」「不要留下历史镜像容器等」）：

- 按 legacy builder（`DOCKER_BUILDKIT=0`）重建：backend `--target api`、worker `--target analysis-worker`
  （另打 beat / deployment-worker 标签）、frontend 单独构建；新镜像 backend `ef5d8a173a6a`、
  worker/beat/deployment-worker `72a9f437b2e5`、frontend `18bcd8a8f13b`。
- 先给旧镜像打 `pre-database-scan-20260920` 回退标签，`docker compose -p source -f docker-compose.yml down`
  停掉并删除**全部 8 个**容器（含 postgres/redis/flower，卷保留），再 `up -d --no-build` 全量拉起；
  8 个容器全部 Up，backend/worker/postgres/redis healthy，`/api/v1/health` 为 `ok` 且
  `features.test_data_import=false`。
- 验证通过后清理：删除 5 个 `pre-database-scan-20260920` 回退标签（旧镜像随即删除）、
  `docker image prune -f` 与 `docker builder prune -f`（构建缓存 0B）；**悬空镜像 0、遗留容器 0**，
  只剩 5 个 `source-*:latest`；Docker 镜像计账 35.28GB → 31.35GB 回到重建前水平，
  剩余 9.968GB 可回收镜像属于其他项目（opendlp/openaev），未触碰。C: 可用 **41.1 GiB**。
- 与上一批一样，**本轮之后同样没有可回退镜像**：回退方式是 `git stash` 后用当前提交重新构建。

本批遗留（不要当作已完成）：

- PostgreSQL 直连走同一适配层，但本批**没有真实 PG 目标**，只有隔离测试；需要真机验证后再声明支持。
- 采集到的命中原文会随证据落库（`DetectionEvidence.extra['matches']`），因此目标库数据会驻留在平台库里：
  这一点的静态保护与传输加固仍未做（与第三批同一条待办）。
- 前端新页面有 composable 状态测试、组件渲染测试、生产构建与部署后接口验证，但**没有**在真实浏览器里
  走完「登录 → 建连接 → 选表 → 采集 → 看结果」的端到端点击验证。
- 部署库里保留了一条测试连接「Kali MariaDB 测试库（dst_demo）」与它采集的 9 张表资产（用户明确说这台库
  用于测试）；删除连接可在页面上完成，已采集资产会作为历史保留。
- root 运行身份、探针出包与升级仍未执行（用户要求暂缓 root）。

## 数据类型中心 500 修复（2026-09-20 夜，P2 收尾）

用户报「数据类型中心 500」。后端日志定位到 `backend/app/services/data_objects/queries.py` 的 `_type_scope`：

```
TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'
File "/app/app/services/data_objects/queries.py", line 108, in _type_scope
    hosts.setdefault(category, set()).add(int(row[5]))
```

原因是上一批引入数据库直连后，数据库来源的实例没有探针（`probe_id IS NULL`、`owner_key='db:<连接 id>'`），
而 `host_count` 仍按 `probe_id` 计数：`int(None)` 直接抛错，于是 `GET /api/v1/data-types` 与
`GET /api/v1/data-types/{category}` 全部 500；`GET /api/v1/data-objects/{id}` 的 `host_count` 也会把每个
目标库并成一个「空主机」（不报错但口径错）。

修复（源码仍在工作树，未提交）：

- `queries.py` 新增 `owner_key_of(probe_id, owner_key)`：有 `owner_key` 就用它（文件 `probe:<id>`、
  数据库 `db:<id>`），没有则回退 `probe:<id>`；两者都没有（0016 之前的旧行、SQLite 测试库默认空串）
  返回空串，不参与计数。`_type_scope` 的 `hosts` 改为 `dict[str, set[str]]`，`data_type_summary`
  的 `all_hosts` 同步为 `set[str]`。
- `api/data_catalog.py`：对象详情 `host_count` 改为按 `owner_key_of` 去重；`dedup_rules` 增加 `host_count` 口径。
- 前端文案随口径更新：类型详情「主机数」副标题改为「按来源去重（文件探针 / 数据库连接）」，
  类型中心的去重说明补一句「一个数据库连接也算一个来源」。
- 回归测试 `test_database_scan_ingest.py::test_the_type_centre_counts_a_connection_as_a_host`：
  两个连接各采一张 `bank_card` 表（`probe_id IS NULL`）后，`/api/v1/data-types` 与
  `/data-types/bank_card` 返回 200、`host_count == 2`、对象详情 `host_count == 1` 且实例带 `db:<id>`。

验证结果：

- 后端全量 `809 passed / 6 failed / 1 skipped`（比上一批多出的 6 项即本批新增回归）；6 项失败与 HEAD `a51bffe`
  基线逐项一致（Windows chmod 1、本机无 Redis 1、本机无 tshark 3、本机缺原生导出器 1），本批未新增失败；
  数据库直连 + 数据对象相关 89 项通过。
- ruff：`queries.py`/`data_catalog.py`/新测试文件与前次统计逐项一致（11 B008 / 2 E501 均为 `data_catalog.py`
  既有项，无新增）。
- 前端 `npm run typecheck` 通过；vitest 29 文件 249 项通过。
- 部署后线上验证（管理员会话）：`/api/v1/data-types` 200、`/api/v1/data-types/phone` 200、
  `/api/v1/asset-instances?source_kind=database` 200（`probe_id=None`、`owner_key=db:1`）；
  totals `hosts=2`（1 台文件探针 + 1 个数据库连接），`bank_card/email/id_card/phone` 均 `hosts=2`；
  数据库对象详情 `host_count=1`、实例 `owner_key=db:1`。前端 8088 端口 `index.html` 与 `/data-types` 均 200，
  容器内 `DataTypeDetail-*.js`/`DataTypeCenter-*.js` 命中本次新增文案。
  容器内 `index-fE6OMqXi.js`、`DataTypeCenter-pAmSp_jY.js`、`DataTypeDetail-JA-DQoC0.js` 与本地
  `npm run build` 产物 SHA256 逐字节一致。

完全重启与清理（按用户「修改完成后完全重启整个项目」「不要留下历史镜像容器等」）：

- legacy builder（`DOCKER_BUILDKIT=0`）重建 backend/worker/beat/deployment-worker/frontend：backend
  `a1eb9f7708ff`、worker `65ee2fa17e05`、beat `356efa862b0b`、deployment-worker `0c89925ba707`、
  frontend `3dbecec78599`。
- `docker compose -p source -f docker-compose.yml down` 停掉并删除**全部 8 个**容器（卷保留），再
  `up -d --no-build` 全量拉起；8 个容器全部 Up，backend/worker/postgres/redis healthy，
  迁移仍为 `0016_database_connections (head)`；容器内 `queries.py`/`data_catalog.py` 的 SHA256
  在 api 与 worker 两个容器里都与工作树一致。
- 清理：`docker image prune -f` + `docker builder prune -f` + `docker container prune -f`；
  **悬空镜像 0、遗留容器 0、构建缓存 0B**，只剩 5 个 `source-*:latest`；C: 可用 **43.67 GiB**
  （重建前 41.05 GiB）。Docker 镜像计账 39.02GB，其中 13.74GB 可回收属于其他项目（opendlp/openaev），未触碰。
- 本轮同样没有可回退镜像：回退方式是 `git stash` 后用当前提交重新构建。

口径变化（需要周知）：类型中心的「主机数」含义从「不同探针数」变为「不同观测来源数」
（文件探针算一个、数据库连接也算一个），前端副标题与 `dedup_rules` 已同步说明。

# 当前任务：分批解耦（数据资产采集与展示优先）

## 历史任务记录

## 用户需求与约定

- 用户提出业务需求，AI 负责后续代码修改；优先让数据资产采集方式与展示方式更易维护。
- 按批次持续推进后端与前端解耦，探针放在最后；本机服务允许短暂停机更新。
- 每批保持现有行为/API/数据库/探针协议兼容，以隔离回归和真实环境只读检查验收。
- 禁止导入测试数据、生产 mock；未授权操作真实探针主机。

## 第一批：数据资产边界（2026-09-19）

基线 `5c5b1d4`，分支 `refactor/data-asset-boundaries`。

已完成代码：

- 公共鉴权移至 `api/dependencies.py`；采集建任务移至 `services/probe_task_service.py`；
  服务领域异常在 `api/error_handlers.py` 转为原有 404/409。提交时点和任务快照不变。
- 采集协议 `api/data_collection_schemas.py`、采集接口 `api/data_collection.py`、
  旧资产页与敏感发现接口 `api/data_assets.py` 从大路由独立；旧入口保留兼容导出。
- 数据对象服务拆为 `services/data_objects/{definitions,values,identity,coverage,persistence,evidence,ingestion,projection,queries,progress}.py`；
  旧 `data_object_service.py` 仅为 58 行兼容导出，新生产调用使用具体模块。
- 前端 `DataAsset.vue` 从 285 行缩至 144 行；列表/详情与采集任务状态分别由两个 composable 管理，模板不变。
- 增加 3 项后端依赖边界检查、3 项前端行为回归；明确禁止循环依赖与服务反向导入 API/worker。
- 新增 [数据资产开发入口](docs/数据资产开发入口.md)，压缩当前上下文，旧记录完整归档。

验证：

- 同环境后端基线 579 passed / 17 failed；本批 582 passed / 17 failed，失败集合一致。
- 前端 typecheck、37 项单测、生产构建通过；新增/拆出的后端模块 ruff 通过。
- 拆分前后 OpenAPI、162 个路由记录、38 张表的列/索引定义完全一致；没有新增迁移。
- Python 模块语法检查、git diff --check 通过。全量回归中发现并修正的遗漏 `re` 导入已验证。
- 切换前真实环境 8 个只读 API 均 200，`/test/status present=false`；资产数 1087（时点值，不是固定验收值）。

已完成：应用镜像于 2026-09-19 重建并切换本机服务（backend/worker/beat/deployment-worker/frontend 正常）；
切换后复验 8 个只读接口均 200、`/test/status present=false`、迁移仍为 `0015_alert_hits`（head）。
回退标签 `source-{backend,worker,frontend}:pre-data-asset-refactor-20260919` 可用。第一批含切换收尾完成。

## 第二批：分析编排与 Celery 任务入口（2026-09-20）

基线 `f60dd11`，同一分支。目标：分析编排离开 Celery 任务文件，API 不再导入 worker 私有函数与任务对象。

已完成代码：

- 证据身份解析（资产 / IOC）移至 `domain/evidence_identity.py`（纯逻辑、不查库）；
  `incident_engine/engine.py` 只兼容重导出 `evidence_asset_keys`、`evidence_ioc_keys`、
  `evidence_primary_asset`、`_short_asset`、`_asset_identity` 等旧名字，语义不变。
- 跨域分析编排移至 `application/analysis.py`：`run_pipeline`、`recent_findings`、`merge_findings`、
  `upsert_incident`、`run_correlations_and_alerts`、`capture_exposure`。事务边界不变（仅自建 session 才 commit）。
- 任务行持久化移至 `services/task_service.py`（`create_task` / `update_task`）；派发端口为
  `services/task_dispatch.py`：按注册名派发，broker 不可用时回退本进程；`enqueue` 无内联回退，供需要 503 的路径使用。
- worker 按职责拆分：`workers/analysis_tasks.py`、`notification_tasks.py`、`maintenance_tasks.py`；
  任务生命周期在 `workers/task_runtime.py`，任务名集中在 `workers/task_names.py`（名字与参数顺序均未改）。
- 旧 `workers/tasks.py` 成为 43 行兼容门面且不再有任务装饰器；`celery_app.py` 的 include 指向新模块。
- API 不再导入 `app.workers.*`：`api/v1.py` 改为 `_dispatch(task_id, 注册名, ...)`，健康检查用 `queue_depth()`；
  `api/extensions.py` 用 `enqueue`；`api/deployments.py`、`services/test_service.py` 同样走端口。
- 新增 `tests/test_task_boundaries.py`（9 项）：端口独占 worker 依赖、路由不含任务对象/私有名、
  应用层不依赖 HTTP 与 worker、门面仍导出旧名字、门面无重复注册、beat/route 名字均已注册、派发参数顺序与回退行为。

验证：

- 本机隔离全量 608 项：601 passed / 6 failed / 1 skipped；同一提交的干净检出失败 16 项（含本机未构建探针包的 10 项），
  本批 6 项失败全部是该集合的子集，无新增失败、无新增错误。
- 路由仍为 162 条记录（158 APIRoute / 144 路径）；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增/拆出模块 ruff 与 ruff format 通过；`v1.py`、`extensions.py`、`deployments.py`、`test_service.py`
  改动前后 ruff 统计逐项一致（历史存量不因本批增加）。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker：worker 注册 12 个任务名，
  beat 正常派发，无 unregistered task；经真实队列往返一次 `worker_capability_heartbeat` 成功。
- 真实环境只读复验：health 与 8 个只读接口均 200，`/test/status present=false`；未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-analysis-task-split-20260920`。

## 第三批：PCAP 域路由拆分（2026-09-20）

基线 `9833cad`，同一分支。目标：按指南 §C 把 PCAP 域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页不变；
对应第二批清单第 2 项（继续拆其他大路由）的首个域。

已完成代码：

- PCAP 路由与专用序列化移至 `api/pcaps.py`：上传、列表/详情/分析、包/流、协议/流量、DNS/HTTP/TLS、
  提取清单/预览/下载、抓包告警共 18 条路径；`v1.router` 以 `include_router(pcaps_router)` 只注册一次，
  `/api/v1` 前缀只叠加一次。
- 上传归属与队列背压从 v1 私有函数移至 `api/dependencies.py`（`upload_probe_id`、
  `enforce_queue_backpressure`），语义不变（鉴权失败仍按原错误码抛出，队列拥挤仍是 429 + `Retry-After`）；
  文件上传路由继续复用同一份实现。
- Task 行序列化提取为 `api/task_presenter.py::serialize_task`，PCAP 域与 tasks 路由共用一份，不再复制。
- 文件末尾的兼容下载端点（`packets/{id}`、`streams/{id}`、`files/{id}/download`）随域整体移动，不是按连续行区间剪切。
  v1 保留 `_dispatch`（文件/探针域仍在用），PCAP 域直接经 `task_dispatch.dispatch_task_row` 派发，参数顺序不变。
- 新增 `tests/test_pcap_boundaries.py`（6 项）：18 条路径/方法冻结、仅由 `api/pcaps.py` 声明、仍挂在 `/api/v1` 下、
  全应用无重复「方法 + 路径」、PCAP 域不导入 workers/extensions、上传守卫位于共享依赖模块、v1 只聚合一次。
- 测试 monkeypatch 目标迁到真实位置：`tests/test_pcap_workbench.py` 改为 patch
  `pcaps.dispatch_task_row` 与 `pcaps.enforce_queue_backpressure`。

验证：

- 本机 .venv 隔离全量 614 项：607 passed / 6 failed / 1 skipped；6 项失败与第二批基线集合完全相同，无新增失败、无新增错误。
- 拆分前后 OpenAPI **字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute / 148 路径），
  端点函数名集合一致；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- `tests/test_pcap_workbench.py` 除本机缺少原生导出器 1 项外全部通过：重复上传仍返回原 ID、
  提取文件下载仍按抓包清单校验、缺包/越界/非法哈希仍为 404/422。
- 新增/拆出文件（`api/pcaps.py`、`api/task_presenter.py`、`tests/test_pcap_boundaries.py`）ruff check 与 ruff format 通过；
  `v1.py` 只减不增，另清理了拆分造成的 7 处未使用导入，历史存量（E501/B008/B904/F841）不变。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 注册 12 个任务名与第二批一致。
- 真实环境只读复验：登录后 16 个只读接口全部 200（含 PCAP 域的列表、详情、协议、异常、提取清单、抓包告警），
  `/test/status present=false`；迁移仍 `0015_alert_hits`（head）。本批未导入测试数据、未操作真实探针，
  也未写入任务行（不涉及派发，故未做队列往返）。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-pcap-route-split-20260920`。

## 第四批：文件域路由拆分（2026-09-20）

基线 `22fc303`，同一分支。目标：按指南 §C 把文件证据域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页不变；
对应后续批次第 1 项（继续按域拆其余 v1 路由）的第二个域。

已完成代码：

- 文件路由与专用序列化移至 `api/files.py`：`POST /files/upload`、`GET /files`、`GET /files/{file_id}`、
  `GET /files/{file_id}/download`、`POST /files/{file_id}/analyze` 共 5 条路径，连同扩展名/MIME 过滤器
  （`FILE_TYPE_ALIASES`、`_file_type_candidates`）；原 `_serialize_file` 改名导出为 `serialize_file`。
- 共享边界不复制：上传归属复用 `api/dependencies.py::upload_probe_id`，Task 行序列化复用
  `api/task_presenter.py::serialize_task`，派发直接走 `services/task_dispatch.dispatch_task_row`；
  文件哈希与元数据仍在 `services/metadata_service.py`，检测仍在 worker。
- `v1.router` 以 `include_router(files_router)` 只注册一次，`/api/v1` 前缀只叠加一次；v1 内对
  `serialize_file` 的调用改为从新模块导入，不保留重复实现。
- 新增 `tests/test_file_boundaries.py`（7 项）：5 条路径/方法冻结、仅由 `api/files.py` 声明、仍挂 `/api/v1` 下、
  全应用无重复「方法 + 路径」、文件域不导入 workers/extensions、不复制共享守卫、v1 只聚合一次。
- 上一批 PCAP 边界测试里「v1 必须直接导入某共享符号」的断言改为按域模块检查，避免后续域拆分误伤。

验证：

- 本机 .venv 隔离全量 621 项：614 passed / 6 failed / 1 skipped；6 项失败与第三批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute / 148 路径），
  端点函数名集合一致；移动符号的 AST 逐节点比对只差序列化器改名与派发端口调用；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出文件（`api/files.py`、`tests/test_file_boundaries.py`）ruff check 与 ruff format 通过；
  `v1.py` 2121 → 1985 行，只减不增，另清理了拆分造成的 3 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 注册任务名与上一批一致。
- 真实环境只读复验：登录后 16 个只读接口全部 200（含文件域列表/详情/下载与 PCAP 域接口），
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-file-route-split-20260920`。

## 第五批：平台资产域路由拆分（2026-09-20）

基线 `ee18eef`，同一分支。目标：按指南 §C 把平台资产（主机资产）域路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的第三个域。

已完成代码：

- 资产路由与资产行序列化移至 `api/assets.py`：`GET /assets`、`GET /assets/summary`、`GET /assets/relations`、
  `GET /assets/{asset_id}` 共 4 条路径，连同 `_incident_touches_asset`、`_finding_touches_asset` 两个
  「证据是否命中本资产」判定；原 `_serialize_asset` 改名导出为 `serialize_asset`（其余 6 处 v1 调用点改为导入）。
- 资产详情同时返回检测、事件、IOC 行，因此把跨域复用的行序列化下沉为 `api/incident_presenter.py`
  （`serialize_incident`）与 `api/ioc_presenter.py`（`serialize_ioc`），v1 与资产域共用一份，不复制。
- 三个序列化器共用的时间归一化函数独立为 `core/datetimes.py::aware`（原 v1 私有 `_aware`），
  v1 以 `aware as _aware` 复用，保留原有 tz-aware 输出语义。
- `v1.router` 以 `include_router(assets_router)` 只注册一次，`/api/v1` 前缀只叠加一次；数据资产（`data/assets`）
  与平台资产的边界保持不变，`/data/assets` 仍属 `api/data_assets.py`。
- 新增 `tests/test_asset_boundaries.py`（8 项）：4 条路径/方法冻结、仅由 `api/assets.py` 声明、仍挂 `/api/v1` 下、
  全应用无重复「方法 + 路径」、资产域不导入 workers/extensions、复用而非复制共享序列化器、
  `_aware`/`_serialize_*` 不再回到 v1、时间归一化只有一份实现、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 629 项：622 passed / 6 failed / 1 skipped；6 项失败与第四批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **语义与排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录
  （158 APIRoute / 144 个 API 路径），162 条「方法 + 路径 + 端点名」与拆分前逐条相同，无新增/丢失；
  AST 逐节点比对显示移动的 10 个函数只差 `_serialize_*`/`_aware` 改名与改名后的调用；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 长行按既有模块标准折行（与 PCAP/文件域一致），新增/拆出 5 个文件 ruff check 与 ruff format 通过；
  `v1.py` 1985 → 1763 行，只减不增，另清理了拆分造成的 2 处未使用导入（`String`、`cast`）。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 18 个只读接口全部 200（含 `/api/v1/assets`、`/assets/summary`、`/assets/relations`、
  `/assets/{id}` 与文件域、PCAP 域、数据资产接口），`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-asset-route-split-20260920`。

## 第六批：事件与情报域路由拆分（2026-09-20）

基线 `e8994a9`，同一分支。目标：按指南 §C 把事件（incidents）与情报（iocs）域路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的第四个域。

已完成代码：

- 事件与情报路由移至 `api/incidents.py`：`GET /incidents`、`GET /incidents/{incident_id}`、
  `PATCH /incidents/{incident_id}`、`POST /incidents/correlate`、`POST /incidents/rebuild-attribution`、
  `GET /iocs`、`GET /iocs/{ioc_id}/associations` 共 7 条路径；关联计算仍在 `incident_engine`
  （路由只调用 `IncidentEngine().correlate`），归属重建仍在 `incident_engine.attribution`。
- 列表时间过滤（原 v1 私有 `_string_time_filter`）下沉为 `api/query_filters.py::string_time_filter`，
  供事件域与其他列表域共用；v1 以别名导入，检测列表调用点不变。
- 行序列化继续复用第五批已下沉的 presenter（检测/事件/IOC/资产），本批不新增序列化副本。
- `v1.router` 以 `include_router(incidents_router)` 只注册一次，`/api/v1` 前缀只叠加一次。
- 新增 `tests/test_incident_ioc_boundaries.py`（8 项）：7 条路径/方法冻结、仅由 `api/incidents.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、事件域不导入 workers/extensions、
  复用而非复制共享 presenter、关联计算未在路由里重写、时间过滤只有一份实现、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 637 项：630 passed / 6 failed / 1 skipped；6 项失败与第五批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；8 个移动函数的 AST 与拆分前逐节点完全一致
  （唯一的差异是过滤函数改名）；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增/拆出文件 ruff check 与 ruff format 通过（长行按既有模块标准折行）；`v1.py` 1763 → 1674 行，
  只减不增，无因拆分产生的未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 18 个只读接口全部 200（含 `/incidents`、`/incidents/{id}`、`/iocs`、
  `/iocs/{id}/associations` 与资产、文件、PCAP、数据资产接口），`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-incident-route-split-20260920`。

## 第七批：告警域路由拆分（2026-09-20）

基线 `74118db`，同一分支。目标：按指南 §C 把告警域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页与
响应结构不变；对应后续批次第 1 项的第五个域。

已完成代码：

- 告警路由移至 `api/alerts.py`：`GET /alerts`、`GET /alerts/summary`、`GET /alerts/stream`（SSE）、
  `GET /alerts/{alert_id}`、`PATCH /alerts/{alert_id}` 共 5 条路径；抑制合并、命中聚合与投递仍由
  `services/alert_service.py` 负责，路由只做鉴权、筛选与响应组装。
- 告警详情依赖探针行与规则定义，因此跨域复用部分下沉为 `api/probe_presenter.py::serialize_probe`
  与 `api/rule_presenter.py::rule_definition`/`rule_file_entries`（原 v1 私有 `_serialize_probe`、
  `_rule_definition`、`_rule_file_entries`）；`/rules` 路由改为导入共享 `rule_file_entries`，
  测试 monkeypatch/导入目标同步迁到 `app.api.rule_presenter`，不保留 v1 重复实现。
- 行序列化继续复用既有 presenter（检测/事件/IOC/资产/数据资产/PCAP），本批不新增序列化副本。
- `v1.router` 以 `include_router(alerts_router)` 只注册一次，`/api/v1` 前缀只叠加一次。
- 新增 `tests/test_alert_boundaries.py`（8 项）：5 条路径/方法冻结、仅由 `api/alerts.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、告警域不导入 workers/extensions、
  复用而非复制共享 presenter、抑制/投递未在路由里重写、探针与规则查询未回到 v1、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 645 项：638 passed / 6 failed / 1 skipped；6 项失败与第六批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；8 个移动函数的 AST 与拆分前逐节点一致
  （唯一差异是 `_serialize_probe`/`_rule_*` 改名与改名后的调用）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 4 个模块 ruff check 与 ruff format 通过；`v1.py` 1674 → 1320 行，只减不增，
  另清理了拆分造成的 9 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 18 个只读接口全部 200（含 `/alerts`、`/alerts/summary`、`/alerts/{id}`），
  告警详情返回全部 11 个字段，规则快照可解析（`matched_snapshot`，标题「端口扫描」）、探针字段正常；
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-alert-route-split-20260920`。

## 第八批：任务/审计/报表域路由拆分（2026-09-20）

基线 `d5e7f73`，同一分支。目标：按指南 §C 把任务队列、审计与报表路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的下一个域（指南中记为 tasks/audit/reports）。

已完成代码：

- 任务路由移至 `api/tasks.py`：`GET /tasks`、`POST /tasks`、`GET /tasks/{task_id}`、
  `POST /tasks/{task_id}/stop`、`DELETE /tasks/{task_id}` 共 5 条路径；行创建仍走
  `services/task_service.py::create_task`、过期仍走 `services/probe_task_service.py`
  （`expire_probe_tasks`、`visible_tasks`），停止/删除的 `PROBE_TASK_KINDS`、`TERMINAL` 判定随域移动。
- 审计与报表路由移至 `api/reports.py`：`POST /audit/logs`、`GET /audit/summary`、
  `POST /reports/generate`、`GET /reports`、`GET /reports/{report_id}/download` 共 5 条路径；
  汇总/日志分析仍在 `services/audit_service.py`、报告构建/渲染仍在 `services/report_service.py`。
- 报告行序列化 `_serialize_report` 随域下沉为 `api/reports.py::serialize_report`，v1 不再保留副本；
  资产/文件/PCAP/检测/事件/数据资产行继续复用既有 presenter，本批不新增序列化副本。
- `v1.router` 以 `include_router(tasks_router)`、`include_router(reports_router)` 各只注册一次。
- 新增 `tests/test_tasks_reports_boundaries.py`（10 项）：两组路径/方法冻结、仅由对应模块声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、两域均不导入 workers/extensions、
  Task 行与共享 presenter 复用而未复制、任务/报表逻辑仍在 service、`serialize_report` 未复制回 v1、
  v1 各只聚合一次。

验证：

- 本机 .venv 隔离全量 655 项：648 passed / 6 failed / 1 skipped；6 项失败与第七批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同，仅注册顺序变化（子路由在 v1 末尾追加；
  全应用无单段通配路径，匹配结果不变）；11 个移动函数的 AST 与拆分前逐节点一致（唯一差异是
  `_serialize_report`→`serialize_report` 改名与改名后的调用，长行折行不改 AST）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 3 个模块 ruff check 与 ruff format 通过；`v1.py` 1320 → 1176 行，只减不增，
  另清理了拆分造成的 6 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 28 个只读接口全部 200（含 `/tasks`、`/tasks/{id}`、`/audit/summary`、`/reports`），
  任务详情返回 13 个字段、审计汇总返回 8 个键；任务 3795 条、报告 2 条为时点采样值，随真实采集变化；
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-task-report-route-split-20260920`。

## 第九批：检测/引擎域路由拆分（2026-09-20）

基线 `6e19403`，同一分支。目标：按指南 §C 把检测结果与引擎目录路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的下一个域（指南中记为 detections/engine）。

已完成代码：

- 检测结果路由移至 `api/detections.py`：`GET /detections`、`GET /detections/{detection_id}`、
  `GET /analysis/results` 共 3 条路径；行序列化继续复用 finding/事件/PCAP/告警 presenter，
  列表时间过滤改用共享 `api/query_filters.py::string_time_filter`（原 v1 `_string_time_filter` 别名）。
- 引擎路由移至 `api/engines.py`：`GET /engine/registry`、`POST /engine/pipeline` 共 2 条路径；
  引擎清单读 `app.engine.registry`、规则清单走 `api/rule_presenter.py::rule_file_entries`，
  内部引擎名到 UI slug 的映射 `ENGINE_PRESENTATION`（原 v1 模块常量）随域移动，v1 不再保留。
- 检测判定仍在 `app/engine/*`，本批未改任何引擎、规则或评分逻辑。
- `v1.router` 以 `include_router(detections_router)`、`include_router(engines_router)` 各只注册一次。
- 新增 `tests/test_detection_engine_boundaries.py`（9 项）：两组路径/方法冻结、仅由对应模块声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、两域均不导入 workers/extensions、
  检测域复用而未复制共享 presenter 与时间过滤、引擎域读真实 registry 与规则清单、
  `ENGINE_PRESENTATION` 未复制回 v1、v1 各只聚合一次。

验证：

- 本机 .venv 隔离全量 664 项：657 passed / 6 failed / 1 skipped；6 项失败与第八批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；`analysis_results`、`detection_detail`、
  `engine_registry`、`run_engine_pipeline` 的 AST 与拆分前逐节点一致，`list_detections` 只差
  `_string_time_filter` 改名与改名后的调用，`ENGINE_PRESENTATION` 常量值一致；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 3 个模块 ruff check 与 ruff format 通过；`v1.py` 1176 → 1055 行，只减不增，
  另清理了拆分造成的 7 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 38 个只读接口全部 200（含 `/detections`、`/detections/{id}`、
  `/analysis/results`、`/engine/registry`），检测详情返回 4 个键、引擎清单 15 项且带 UI slug；
  检测 3502 条为时点采样值，随真实采集变化；`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-detection-engine-route-split-20260920`。

## 第十批：看板/流量视图域路由拆分（2026-09-20）

基线 `25cbbd5`，同一分支。目标：按指南 §C 把看板、风险总览、关系图与全局流量视图从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的下一个域（指南中记为 dashboard）。

已完成代码：

- 看板与流量视图移至 `api/dashboard.py`（13 条路径）：`GET /risk/summary`、`GET /graph`、
  `GET /dashboard/summary|risk-trend|severity|engines|incidents|high-risk-assets|sensitive-data|incident-trend`、
  `GET /flows`、`GET /protocols`、`GET /network/live`。
- 所有数字仍由 `app/models.py` 的行实时聚合，未新增缓存、派生表或写死常量；行序列化继续复用
  资产/事件/流量/探针 presenter，协议分层复用 `services/protocol_service.py::protocol_layer`，
  分页复用 `api/pagination.py`，本批不新增序列化副本。
- `network_live` 内的 `packets` 死赋值是 v1 存量（`ruff` F841），按原样搬运并加行内 `# noqa: F841`，
  不在结构拆分中删除查询或改变行为。
- `v1.router` 以 `include_router(dashboard_router)` 只注册一次。
- 新增 `tests/test_dashboard_boundaries.py`（7 项）：13 条路径/方法冻结、仅由 `api/dashboard.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、域不导入 workers/extensions、
  复用而非复制共享 presenter 与协议分层、聚合结果来自模型行、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 671 项：664 passed / 6 failed / 1 skipped；6 项失败与第九批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；13 个移动函数的 AST 与拆分前逐节点一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 2 个模块 ruff check 与 ruff format 通过；`v1.py` 1055 → 804 行，只减不增，
  另清理了拆分造成的 17 处未使用导入（`v1.py` 因此第一次达到 `ruff check --select F` 全通过，
  仅余的存量 F841 已随 `network_live` 迁到本域并用行内 noqa 标注）。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 38 个只读接口全部 200（含看板全部卡片、`/risk/summary`、`/graph`、`/flows`、
  `/protocols`、`/network/live`），看板汇总 17 个键、关系图 1834 节点/4426 边、协议 24 行且带 layer、
  `/network/live` 窗口 300 秒；这些为时点采样值，随真实采集变化；`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-dashboard-route-split-20260920`。

## 第十一批：探针域路由拆分（2026-09-20）

基线 `c2dc28b`，同一分支。目标：按指南 §C 把探针域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页不变；
对应后续批次第 1 项的下一个域（指南中记为 probes），也是探针模块化之前的最后一块探针相关 HTTP 边界。

已完成代码：

- 探针注册、心跳、列表、删除、分析、任务、扫描、指标与加密画像移至 `api/probes.py`（9 条路径）：
  `POST /probes/register`、`POST /probes/{probe_id}/heartbeat`、`GET /probes`、`DELETE /probes/{probe_id}`、
  `POST /probes/{probe_id}/analyze`、`GET /probes/{probe_id}/tasks`、`POST /probes/{probe_id}/scan`、
  `GET /probes/{probe_id}/metrics`、`GET /crypto/probe-profile`，连同本域私有辅助
  `_merge_metadata`、`_latest_ruleset_version`、`_probe_removal_target` 一并随域下沉。
- 共享边界不复制：探针鉴权仍在 `core/security.py` 与 `api/dependencies.py`，登记入册仍在
  `deployment/enrollment.py`，删除记录与远端卸载仍在 `services/probe_service.py`、`deployment/removal.py`，
  任务行仍在 `services/task_service.py`，行序列化复用 `api/probe_presenter.py::serialize_probe` 与
  `api/task_presenter.py::serialize_task`；探针下发/回收、规则下发、扫描任务与采集上报仍分属
  `api/deployments.py`、`api/rulesets.py`、`api/extensions.py`、`api/data_collection.py`。
- 本域原先在 v1 内使用的私有派发 `_dispatch(task_id, 注册名, ...)` 下沉为共享
  `api/dependencies.py::dispatch_task`（docstring 原样保留、参数顺序与回退语义不变），v1 删除该本地定义。
- 随域移动的两处 `raise HTTPException(...)` 按 ruff B904 补 `from exc`（异常类型与状态码不变，
  是纯 lint 修复，不是行为改动）；`v1.py` ruff 存量由 68 项（37 E501 / 29 B008 / 2 B904）降为 46 项
  （27 E501 / 19 B008），只减不增。
- 新增 `tests/test_probe_boundaries.py`（9 项）：9 条路径/方法冻结、仅由 `api/probes.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、域不导入 workers/extensions、不复制共享守卫、
  派发走共享端口、v1 只聚合一次。
- 拆分造成的 1 项测试回归已修：`tests/deployment/test_removal.py` 的 monkeypatch 目标从
  `v1.dispatch_probe_deployment` 迁到真实查找位置 `app.api.probes`（PCAP 批同一约定）；
  `tests/test_ruleset_release.py` 的 `_latest_ruleset_version` 导入改到 `app.api.probes`。

验证：

- 本机 .venv 隔离全量 680 项：673 passed / 6 failed / 1 skipped；6 项失败与第十批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；探针路由由 v1 中段零散位置改为随子路由在末尾注册，
  逐条比对 158 个操作的「方法 + 路径」首个命中函数与拆分前完全一致（匹配优先级未变）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 11 个移动函数的 AST 与拆分前逐节点一致；另 5 处差异均为本批声明过的改名/`from exc`（见上）。
- 新增/拆出文件 ruff check 与 ruff format 通过；`v1.py` 只减不增且 `--select F` 全通过。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 38 个只读接口 + 本域 3 个明细接口（`/probes/{id}/tasks`、`/probes/{id}/metrics`、
  `/crypto/probe-profile?probe_id=`）共 41 项全部 200；探针 1 台（`test123`）、指标 15 个键、
  任务行 9 条、加密画像 11 个键；`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未对真实探针主机做任何写操作（仅 GET 读取）。
- 真实环境资产/图/流量等数字是时点采样值，会随真实 PCAP/探针任务持续写入而变化；
  重构前后数字差异来自真实数据继续写入，不是本次结构拆分导致的数据迁移。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-probe-route-split-20260920`。

## 第十二批：集成与离线导入域路由拆分（2026-09-20）

基线 `dc07b2f`，同一分支。目标：按指南 §C 把适配器目录与 `/offline` 导入面收拢成一个域，
路径/方法/鉴权/分页不变；对应后续批次第 1 项的下一个域（指南中记为 integrations/offline）。

已完成代码：

- 新建 `api/integrations.py`（11 条路径）：`GET /integrations`、`POST /integrations/{name}/analyze`、
  `POST /integrations/offline/upload`、`POST /integrations/offline/import`、`GET /offline/resources`、
  `GET /offline/cves`、`POST /offline/upload`、`POST /offline/cves`、`POST /offline/grype/update`、
  `POST /offline/grype/import`、`GET /offline/grype/jobs/{identifier}`；`CveRule`、`job_path`、
  `run_grype_job` 随域下沉，`v1.router` 与既有域一致地只 include 一次、`/api/v1` 前缀只叠加一次。
- `/offline` 原先分散两处：`api/v1.py`（资源/CVE 列表、上传）与 `api/libraries.py`（手工 CVE、Grype
  更新/导入/任务）。本批一并归位，`libraries.py` 只留 dlp 规则、规则源与规则导入（302 → 217 行）。
- 共享边界不复制：适配器元数据/执行仍在 `app.integrations`（registry/runner），离线包解析仍在
  `app.integrations.offline_manager`，Grype 库仍在 `services/grype_library.py`，告警仍在
  `services/alert_service.py`，事件聚合仍走 `incident_engine`，路径校验复用 `core/storage.safe_path`，
  分页复用 `api/pagination.page_response`。
- worker 能力与规则清单读取（原 v1 私有 `_read_worker_capabilities`、`_merge_capability`、
  `_engine_rule_counts`）下沉到共享 `api/runtime_status.py`（改名 `read_worker_capabilities`、
  `merge_capability`、`engine_rule_counts`），`/health` 与 `/integrations` 共用一份实现；
  v1 因此删除已无使用者的 `incident_engine = IncidentEngine()` 句柄（事件聚合逻辑与调用点未变）。
- 从 `libraries.py` 迁出的四条 `/offline` 路由保留原 `rule-libraries` tag（仅文档分组，不涉行为），
  使拆分前后 OpenAPI 排序后仍**字节一致**。
- 新增 `tests/test_integration_offline_boundaries.py`（8 项）：11 条路径/方法冻结、仅由本域声明、
  v1 与 libraries 不再声明 `/integrations*` 与 `/offline*`、libraries 仍保留规则编写面、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、本域不导入 workers/v1/extensions、
  不复制共享守卫、能力读取归 `runtime_status`、v1 只聚合一次。
- 测试迁移：`tests/test_rule_libraries.py` 的独立 app 同时挂 `libraries` 与 `integrations` 子路由；
  `tests/test_gap_fixes.py` 的 monkeypatch 目标由 `app.api.v1` 改到 `app.api.integrations`。

验证：

- 本机 .venv 隔离全量 688 项：681 passed / 6 failed / 1 skipped；6 项失败与第十一批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作，含 tags）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；158 个操作的「方法 + 路径」首个命中函数完全一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 14 个移动定义的 AST 比对：9 个完全相同，5 处差异均为本批声明的改名与 tag 保留；三个能力助手改名后逐节点一致。
- 新增模块/测试 ruff check 与 ruff format 通过；`v1.py`（46 → 26）与 `libraries.py`（15 → 11）ruff 存量只减不增，
  没有顺带批量重排老文件。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy，worker 仍注册 12 个 `security_toolbox.*` 任务名，日志无 Traceback/ERROR/unregistered。
- 真实环境只读复验：登录后 38 个只读接口 + 本域与探针域明细共 41 项全部 200，其中 `/integrations` 8 条、
  `/offline/resources` 1 行、`/offline/cves` 旧数组契约仍为定长数组、分页契约返回 `{items,total,page,page_size}`
  且 `total=394371`；`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未操作真实探针主机，也未调用 `/offline/*` 的写接口。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-integration-offline-route-split-20260920`。

## 第十三批：规则域路由拆分（2026-09-20）

基线 `052ac15`，同一分支。目标：按指南 §C 把检测引擎规则面收拢成一个域，路径/方法/鉴权/分页不变；
对应后续批次第 1 项的下一个域（指南中记为 rules）。

已完成代码：

- 新建 `api/rules.py`（5 条路径）：`GET /rules`、`GET /rules/content`、`GET /rule-sources`、
  `POST /rules/sync`、`POST /rules`，`RuleSyncRequest`、`DetectionRule` 两个请求模型随域下沉；
  后三条与两个模型原先在 `api/libraries.py`，归位后该文件只保留敏感数据（DLP）规则族 `/dlp/rules*`
  （217 → 101 行），职责从「规则编写 + 漏洞库维护 + 引擎规则」收敛为单一的 DLP 规则目录。
- 共享边界不复制：规则枚举仍只有 `api/rule_presenter.py::rule_file_entries` 一份（`/engine/registry`
  共用），来源出处读 `app.rules.catalog`、`app.rules.library`，在线拉取走 `app.rules.sync`，
  手工 Suricata/YARA 导入走 `app.integrations.offline_manager` 与 `yara` 编译校验（写盘前校验不变），
  `record_audit` 审计不变，`v1.router` 只 include 一次。
- 从 `libraries.py` 迁出的三条路由保留原 `rule-libraries` tag（仅文档分组），使拆分前后 OpenAPI
  排序后仍**字节一致**。
- 新增 `tests/test_rule_boundaries.py`（8 项）：5 条路径/方法冻结、仅由本域声明、v1 与 libraries 不再声明、
  DLP 规则族仍在 libraries、仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、
  本域不导入 workers/v1/extensions、不复制共享守卫、来源读取走 catalog/sync 服务、
  presenter 仍与 engines 域共用、v1 只聚合一次。
- 测试迁移：`tests/test_rule_libraries.py` 的独立 app 再挂上 `rules` 子路由（与原 `libraries`、
  `integrations` 并列）；上一批的 `tests/test_integration_offline_boundaries.py` 相应收窄为只冻结
  DLP 四条，并断言 `/rules*`、`/rule-sources` 已不属于 libraries。

验证：

- 本机 .venv 隔离全量 697 项：690 passed / 6 failed / 1 skipped；6 项失败与第十二批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作，含 tags）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；158 个操作的首个命中函数完全一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 7 个移动定义的 AST 比对：4 个完全相同，3 处差异仅为保留 tag。
- 新增模块/测试 ruff 通过；`v1.py`（26 → 23）与 `libraries.py`（11 → 5）ruff 存量只减不增，
  未批量重排老文件。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy，worker 仍注册 12 个 `security_toolbox.*` 任务名，日志无 Traceback/ERROR/unregistered。
- 真实环境只读复验：登录后 38 个只读接口 + 本域 3 项（`/rule-sources`、`/rules`、`/rules/content`）
  + 探针域 3 项共 44 项全部 200；`/rule-sources` 15 个引擎、键集合与拆分前一致；`/rules` 3512 条、
  14 种类型；`/rules/content` 返回内置/文件规则的正文；`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针主机，
  也未调用 `POST /rules`、`POST /rules/sync` 等写接口。
- 全量偶发第 7 项失败来自既有 flaky `tests/deployment/test_credential.py::test_tamper_rejected`
  （密文末字节恰为 0x00 时篡改等于没改，约 1/256），与本批无关，按约定不在结构移动中顺手修。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-rules-route-split-20260920`。

## 第十四批：v1 剩余零散入口收敛（2026-09-20）

基线 `2da7390`，同一分支。目标：把 `v1.py` 里最后几组零散入口按域收拢，使聚合文件只剩
`include_router`；路径/方法/鉴权/分页不变。

已完成代码：

- 新建四个域，`v1.py` 288 → 79 行，且**自身不再声明任何路径**（只剩兼容重导出与聚合）：
  `api/auth.py`（`POST /auth/login`、`POST /auth/logout`、`GET /auth/me`）、
  `api/health.py`（`GET /health`）、`api/network_scan.py`（`POST /scan`、`GET /scan/{task_id}`）、
  `api/test_data.py`（`POST /test/import`、`POST /test/clear`、`GET /test/status`）。
- 共享边界不复制：会话/口令仍走 `core/security.py` 与 `AdminSession`；`/health` 的 worker 能力与
  规则清单仍读 `api/runtime_status.py`（与 `/integrations` 共用），队列深度读
  `services/task_dispatch.py::queue_depth`，探针行形状读 `api/probe_presenter.py`；`/scan` 的端口
  选择走 `services/scan_service.py`、探针侧排队走 `services/probe_task_service.py`、派发走
  `api/dependencies.dispatch_task`；测试数据导入/清理/状态仍在 `services/test_service.py`。
- 写入口的 opt-in 守卫 `_require_test_data_import`（读 `settings.test_data_import_enabled`，默认关闭）
  随域下沉，两个写入口都必须先过守卫；`main.py` 对 `/api/v1/health` 的免鉴权放行与
  `/api/v1/auth/login` 的公开例外不变，说明「只允许真实数据」的开关仍默认关闭。
- 这四条路径无 tag 变化，OpenAPI 拆分前后**完全一致**（144 条路径 / 158 个操作，含路径顺序）；
  路由仍 162 条记录（158 APIRoute），路径/方法/端点函数名多重集与拆分前完全相同，仅注册顺序变化。
- 新增 `tests/test_auth_boundaries.py`（7 项，含「`v1.py` 自身不再声明任何路径」这条总约束）、
  `tests/test_health_boundaries.py`（7 项）、`tests/test_network_scan_boundaries.py`（8 项，含
  `/scan` 与 `/scan/{task_id}` 与 `/scan-profiles*` 不互相遮蔽）、`tests/test_test_data_boundaries.py`（7 项，
  含守卫只有一个实现、两个写入口都过守卫）。
- 测试迁移：`tests/test_integration_offline_boundaries.py` 的 worker 能力共用断言由 `v1.py` 改指
  `api/health.py`（`/health` 迁出后 v1 不再导入 `runtime_status`）。

验证：

- 本机 .venv 隔离全量 726 项：719 passed / 6 failed / 1 skipped；6 项失败与第十三批基线集合完全相同，
  无新增失败、无新增错误（其中 29 项为本批新增边界测试）。
- 拆分前后 OpenAPI **完全一致**（144 条路径 / 158 个操作，含路径顺序与 tags）；路由仍 162 条记录
  （158 APIRoute）、158 条「路径 + 方法」多重集相同；158 个操作的首个命中函数完全一致；
  10 个被移动定义的 AST 逐节点比对完全相同；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增模块/测试 ruff check 与 format 一次通过；`v1.py` ruff 存量 23 → 0（14 E501、9 B008 随代码迁出），
  未批量重排老文件。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy，worker 仍注册 12 个 `security_toolbox.*` 任务名，日志无 Traceback/ERROR/unregistered。
- 真实环境只读复验：登录后 35 个只读接口 + 本批 3 项（`/auth/me`、`/health`、`/test/status`）
  + 规则域 3 项 + 探针域 3 项共 44 项全部 200；`/health` 返回 status=ok、redis=ok、
  analysis_worker=ready、`features.test_data_import=false`；`/test/status present=false`；
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针主机，
  也未调用 `POST /test/import`、`POST /test/clear` 等写接口。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-v1-residual-route-split-20260920`。

## 第十五批：前端 PCAP 工作台状态解耦（2026-09-20）

基线 `e7eb701`，同一分支。目标：按指南 §F「前端先抽状态，再抽视图」把工作台的状态与 API 编排
从组件里抽出来，模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/network/pcap/composables/usePcapWorkbench.ts`（382 行），
  `PcapWorkbench.vue` 只保留模板、弹窗与格式化（582 → 312 行）；迁入的 278 行脚本逐行比对，
  只有两处声明过的改动：`streamData` 改用 `api/pcaps.ts` 已有的 `TcpStreamFollow` 类型
  （原来重复声明了一份等价的内联类型），以及新增 `closeFileDialog()`。
- 模板原来在弹窗 `@closed` 上直接 `++fileVersion`；`let` 计数器不能通过 composable 的返回值
  暴露成活绑定（返回值只是取值拷贝），因此改为调用 `closeFileDialog()`，语义不变：
  关弹窗即作废在途的文件预览请求。
- 过期响应防护与轮询原样保留：`viewVersion`（切换抓包）、`packetVersion`（包分页）、
  `detailVersion`（包详情）、`fileVersion`（文件预览）、`taskVersion`（分析轮询）；
  轮询 timer 在组件卸载时清除，离开页面即停止轮询（指南 §F 第 3 条）。API 仍只走
  `frontend/src/api`，没有第二套 HTTP 客户端。
- 新增 `frontend/src/__tests__/pcap-workbench-state.test.ts`（9 项）：列表失败进页面状态、
  两次打开抓包的竞态只保留最新、去重上传定位到记录并清空筛选、空文件拒绝且不调 API、
  包分页按当前查询并丢弃过期页、TCP 流跟踪与文件预览（无保留字节时拒绝）、
  关弹窗后丢弃迟到的预览、分析轮询成功后重开抓包、返回列表并重新加载。

验证：

- `npm run typecheck` 通过；全量 vitest 11 个文件 46 项通过（原 37 项 + 本批 9 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：容器 Up，
  `http://localhost:8088/`、入口 chunk 与 `PcapWorkbench` chunk 均 200，入口 chunk 名与本地构建一致，
  工作台 chunk 内仍是真实 API 调用、无 demo/mock 代码；本批未导入测试数据、未操作真实探针主机。
- 回退标签 `source-frontend:pre-pcap-workbench-state-20260920`。

## 第十六批：前端数据资产采集任务页状态解耦（2026-09-20）

基线 `1abca8c`，同一分支。目标：按指南 §F「前端先抽状态，再抽视图」把采集任务页的状态、派发与
轮询从组件里抽出来，模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useDataAssetJobs.ts`（159 行），
  `DataAssetJobs.vue` 只保留模板与按钮（251 → 131 行）；迁入的 113 行脚本逐行比对，
  只有一处声明过的改动：任务列表原来由页面直接调 `apiGet('/tasks', ...)`，改用
  `api/tasks.ts::listTasks`（同一个请求）。
- 探针与扫描配置下拉、任务列表、派发/取消/移除与统计卡计数仍在 composable；5 秒自动刷新 timer 归
  composable 所有，`onMounted` 启动、`onBeforeUnmount` 清除，离开页面即停止轮询（指南 §F 第 3 条）。
- 派发 payload 语义原样保留：显式路径按行切分并去空行，优先于扫描配置；路径非空且选了配置时两个
  字段都发；没有选中探针时不发请求。API 仍只走 `frontend/src/api`，没有第二套 HTTP 客户端。
- 新增 `frontend/src/__tests__/data-asset-jobs-state.test.ts`（9 项）：加载探针/配置/任务与默认选中、
  加载失败进页面状态、统计卡计数、路径优先 payload、空路径只发 profile_id、无探针拒绝派发、
  派发失败不改任务列表、取消/移除后刷新、5 秒轮询与关闭自动刷新、卸载停止轮询。

验证：

- `npm run typecheck` 通过；全量 vitest 12 个文件 55 项通过（原 46 项 + 本批 9 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataAssetJobs` chunk 均 200，线上 chunk 与本地
  构建 SHA256 一致、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-data-asset-jobs-state-20260920`。

## 第十七批：前端数据目录类型页状态解耦（2026-09-20）

基线 `290dbc1`，同一分支。目标：按指南 §F 把数据类型中心与类型详情的状态从组件里抽出来，
模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useDataTypeCenter.ts`（64 行）与
  `useDataTypeDetail.ts`（68 行）；`DataTypeCenter.vue` 154 → 117 行、`DataTypeDetail.vue` 134 → 99 行，
  两个页面只保留模板与行跳转。迁入的 37 行与 35 行脚本逐行比对未改。
- 两处声明过的改动：类型详情的路由 `category` 改为由页面传入的 `ComputedRef`（composable 不再自己
  调 `useRoute`），并新增 `setPage()`；模板分页由 `@current-change="(value) => (page = value)"` 改为
  `@current-change="setPage"`——composable 返回的 ref 不能在模板里直接赋值（同 PCAP 批的
  `closeFileDialog`）。
- 顶部卡片继续直接用服务端去重后的 `totals`/`totals_scope`，不把每行相加；`search` 只过滤表格，
  不改总数；失败的刷新保留上一次成功的数据。
- 新增 `frontend/src/__tests__/data-type-catalog-state.test.ts`（7 项）：加载行与分级目录并保留
  服务端 totals 与范围标签、按类型/实体过滤且总数不变、失败刷新保留旧数据、按路由 category 加载、
  翻页与换类型重新查询、身份徽标四态（确认/疑似副本/待确认身份/作用域内）、失败进页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 13 个文件 62 项通过（原 55 项 + 本批 7 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataTypeCenter`/`DataTypeDetail` chunk 均 200，
  chunk 名与本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-data-type-catalog-state-20260920`。

## 第十八批：前端数据目录对象/实例详情页状态解耦（2026-09-20）

基线 `1a1d53c`，同一分支。目标：按指南 §F 把数据对象详情与实例详情的状态抽到 composable，
模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useDataObjectDetail.ts`（104 行）与
  `useAssetInstanceDetail.ts`（72 行）；`DataObjectDetail.vue` 219 → 159 行、
  `AssetInstanceDetail.vue` 193 → 153 行，两个页面只保留模板、行跳转与时间格式化。
  迁入的 61 行与 40 行脚本逐行比对未改。
- 两处声明过的改动：路由 id 以 `ComputedRef` 参数传入（composable 不再自己 `useRoute`），
  对象页新增 `setDetectionPage()`；模板分页由
  `@current-change="(value) => { detectionPage = value; loadDetections() }"` 改为
  `@current-change="setDetectionPage"`——composable 返回的 ref 不能在模板里直接赋值
  （同 PCAP 批的 `closeFileDialog`）。
- 证据抽屉的打开/加载/失败状态随域进 composable；实例页的 `formatTime`/`formatMtime` 是纯展示，
  留在视图；`includeHistory` 与重查一起进 composable。翻分页只重查检测，不重查对象本身。
- 新增 `frontend/src/__tests__/data-object-instance-state.test.ts`（8 项）：按路由 id 加载对象与
  第一页检测、翻页只重查检测、身份文案四态、证据抽屉成功与失败都不关闭、加载失败进页面状态；
  实例按 `include_history` 加载、历史开关翻转后重查、证据抽屉、失败进页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 14 个文件 70 项通过（原 62 项 + 本批 8 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与两个详情页 chunk 均 200，chunk 名与本地构建一致、
  线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/data-objects`、
  `/data-objects/{id}`、`/data-objects/{id}/detections`、`/asset-instances`、`/asset-instances/{id}`
  （含 `include_history=true`）、`/detections/{id}/evidence`、`/data-types`、`/data-types/address`、
  `/data/assets`、`/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles` 均 200；
  本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-data-object-instance-state-20260920`。

## 第十九批：前端扫描配置与规则版本页状态解耦（2026-09-20）

基线 `9bcfd74`，同一分支。目标：按指南 §F 把扫描配置页与规则版本页的状态抽到 composable，
模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useScanProfiles.ts`（188 行）与
  `useRuleVersions.ts`（141 行）；`ScanProfiles.vue` 289 → 155 行、`RuleVersions.vue` 256 → 156 行。
  去掉缩进后，迁入的 132 行与 96 行脚本逐行比对未改。
- 一处声明过的改动：扫描配置页模板分页由
  `@current-change="(value: number) => { page = value; load() }"` 改为 `@current-change="setPage"`，
  由 composable 保证「移动分页」与「重新查询」一起发生；规则版本页模板逐字节未改。
- 扫描配置页的草稿与两个路径文本框、新建/编辑/删除/下发弹窗全部进 composable，
  `emptyDraft()`/`splitLines()` 一并迁入；`ElMessage` 与 `ElMessageBox.confirm` 仍在 composable 里，
  与采集任务页一致。
- 规则版本页把 `syncedProbes`/`outOfDateProbes`/`failedProbes` 与模板要用的
  `probedVersion`/`probeField`/`shortHash` 一起进 composable。
- 新增 `frontend/src/__tests__/scan-profile-rule-version-state.test.ts`（17 项）：扫描配置页的
  列表与探针加载（服务端 total）、启用/定时计数不走第二次请求、翻页重查、新建清空草稿与编辑回填、
  路径文本框切分与新建/更新分支、保存被拒时不关弹窗、删除前确认与取消不请求、下发选中的探针与
  未选探针不下发、探针拒绝时显示服务端原因、失败进页面状态；规则版本页的规则集+版本+探针加载、
  规则集未初始化时清空、探针版本分类、发布前时间戳版本号与发布后重查、发布被拒显示服务端原因、
  回滚生成新版本、失败进页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 15 个文件 87 项通过（原 70 项 + 本批 17 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与两个页面 chunk 均 200，chunk 名与本地构建一致、
  线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/scan-profiles`、
  `/rulesets`、`/rulesets/{id}/versions`、`/probes`、`/data/assets`、`/data-types`、`/data-objects`、
  `/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-scan-profile-rule-version-state-20260920`。

## 第二十批：前端文件分析、网络 DLP 与敏感发现页状态解耦（2026-09-20）

基线 `38efb98`，同一分支。目标：按指南 §F 把数据安全域剩下三个页面的状态抽到 composable，
模板与交互不变。本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useFileAnalysis.ts`（110 行）、
  `useNetworkDlp.ts`（106 行）与 `useSensitiveDiscovery.ts`（63 行）；`FileAnalysis.vue`
  185 → 115 行、`NetworkDlp.vue` 142 → 83 行、`SensitiveDiscovery.vue` 102 → 71 行。
  去掉缩进后，迁入的 67 行、65 行与 36 行脚本逐行比对未改。
- 文件分析：列表+筛选+详情抽屉+4 秒刷新 timer 全部进 composable（卸载即停，抽屉关闭时不轮询）；
  视图保留 `filterFields`、`scanOutcome`（行 → 徽标文案）与 `downloadOriginal`（下载窗口）。
- 网络 DLP：策略表单、传输记录、正则规则与 `evidenceRequest` 竞态守卫一起进 composable。
- 敏感发现：服务端返回的 totals/entities/sources 与图表投影进 composable，翻页沿用原有
  `onPageChange()`，所以模板一个字都不用改。
- 唯一修饰改动：`FileRecord`/`FileDetail` 改为在 composable 模块作用域声明并 `export`，
  视图按类型导入。
- 新增两个测试文件：`frontend/src/__tests__/file-analysis-state.test.ts`（9 项：首屏加载与服务端 total、
  重置回第一页、上传后重查、详情成功才开抽屉、隐写块透出、重新分析与被拒、4 秒刷新与卸载停止、
  抽屉关闭时不轮询、失败进页面状态）与 `network-dlp-discovery-state.test.ts`（13 项：策略+传输+规则
  一起加载、保存时文本框切回列表、保存被拒、内置规则开关镜像到 categories、新增规则与被拒、
  Presidio 导入、慢证据响应不覆盖后点的行、无二进制时不请求、命中是否可告警、失败进页面状态；
  敏感发现的加载与投影、翻页重查、失败进页面状态）。

验证：

- `npm run typecheck` 通过；全量 vitest 17 个文件 109 项通过（原 87 项 + 本批 22 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与三个页面 chunk 均 200，chunk 名与本地构建一致、
  线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/files`、`/files/{id}`、
  `/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、`/rulesets`、`/probes`、
  `/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、
  `/sensitivity-levels` 均 200；本批未导入测试数据、未操作真实探针主机；后端未重建，
  迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-data-security-pages-state-20260920`。

## 第二十一批：前端事件中心与告警中心页状态解耦（2026-09-20）

基线 `978f113`，同一分支。目标：按指南 §F 把事件中心与告警中心的状态抽到 composable，
模板与交互不变。本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/operations/incidents/composables/useIncidentCenter.ts`（117 行）与
  `modules/operations/alerts/composables/useAlertCenter.ts`（84 行）；`IncidentCenter.vue`
  268 → 193 行、`AlertCenter.vue` 215 → 164 行。去掉缩进后，迁入的 75 行与 51 行脚本逐行比对未改。
- 事件中心：列表+详情+状态流转+手工关联整块进 composable；视图保留 `filterFields` 与
  `stages`（攻击阶段标签）以及 `formatDateTime`/`formatRiskScore`。
- 告警中心：列表+汇总卡+详情+状态流转进 composable；视图保留 `filterFields` 与格式化函数。
- 两个 composable 都从 `../../../..` 回到 `src`，路径深度与数据安全域不同，移交时容易写错。
- 新增 `frontend/src/__tests__/incident-alert-center-state.test.ts`（17 项）：事件中心的
  首屏加载与服务端 total、重置回第一页、详情成功/失败（保留上一次 detail 与 selected 分离）、
  攻击阶段回退到选中行、状态流转后重读详情与列表、未选中时不请求、手工关联成功/非数组/非法 JSON、
  失败进页面状态；告警中心的列表+汇总一起加载、重置、详情与 confidence、详情失败、状态流转、
  未选中时不请求、失败进页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 18 个文件 126 项通过（原 109 项 + 本批 17 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与两个页面 chunk 均 200，chunk 名与本地构建一致、
  线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/incidents`、
  `/incidents/{id}`、`/alerts`、`/alerts/{id}`、`/alerts/summary`、`/files`、`/dlp/policy`、
  `/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、`/rulesets`、`/probes`、`/data/assets`、
  `/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels`
  均 200；本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-incident-alert-center-state-20260920`。

## 第二十二批：前端资产中心页状态解耦（2026-09-20）

基线 `c9ddf01`，同一分支。目标：按指南 §F 把资产中心的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/asset/composables/useAssetCenter.ts`（171 行）；`AssetCenter.vue`
  290 → 147 行。去掉缩进后，迁入的 145 行脚本逐行比对未改。
- 资产列表 + 详情抽屉 + 关系图投影 + 网络扫描控制台整块进 composable；视图保留
  `filterFields`、`formatDateTime`/`formatRiskScore` 与组件导入，`load`/`open`/`reset`/`runScan`
  由模板直接绑定。
- 扫描控制台：平台/探针两种来源、3 秒间隔轮询（平台 240 次、探针 200 次）、终态判定、
  失败与超时提示、完成后重载列表全部原样迁移。
- 本批唯一非机械改动：删除页面里从未使用的 `useRouter()`（模板与脚本都没有引用它）；
  `loadProbes` 只在 composable 的 `onMounted` 里调用，视图不再解构它。
- 新增 `frontend/src/__tests__/asset-center-state.test.ts`（15 项）：首屏加载与筛选条件、
  探针下拉只保留选项标签用到的字段、探针请求失败时列表为空、重置回第一页、点击行打开详情并回到
  「基础」页签、详情失败把服务端原因写进页面状态、列表失败进页面状态、关系图由资产/数据资产/IOC/
  事件拼出且无详情时为空、`scanSummary` 的存活主机来源（`alive_hosts` 或 `hosts`）、未填目标或
  未选探针时拒绝下发、平台扫描的下发参数（去空格目标、CIDR 判定、端口解析过滤非法端口）与轮询到
  终态后的计数提示和列表重载、探针扫描的提示与阶段名脱敏、扫描失败、永不终态时的超时提示。

验证：

- `npm run typecheck` 通过；全量 vitest 19 个文件 141 项通过（原 126 项 + 本批 15 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `AssetCenter` chunk 均 200，chunk 名与本地
  构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/assets`（214 条）、
  `/assets/{id}`（findings 100、incidents 28、relations 200）、`/probes`（1 台 `test123` online）、
  `/incidents`、`/alerts`、`/alerts/summary`、`/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；本批未导入测试数据、未操作真实探针主机；
  后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-asset-centre-state-20260920`。

## 第二十三批：前端检测中心页状态解耦（2026-09-20）

基线 `b71ae43`，同一分支。目标：按指南 §F 把检测中心的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/operations/detections/composables/useDetectionCenter.ts`（101 行）；
  `DetectionCenter.vue` 183 → 111 行。去掉缩进后，迁入的 78 行脚本逐行比对未改。
- 发现列表 + 详情抽屉（详情到位后才开抽屉）+ 手动流水线整块进 composable；视图保留
  `filterFields`（引擎下拉选项来自 composable 的 `engineOptions`）与 `formatDateTime`。
- 手动流水线：`target_type`、日志行按换行拆分并过滤空行、可选 JSON 体解析、成功/失败提示、
  执行期间 `pipelineRunning` 与结果清空全部原样迁移。
- composable 的导入路径是 `../../../../api/...`（比数据安全域深一层），迁移时最容易写错。
- 新增 `frontend/src/__tests__/detection-center-state.test.ts`（10 项）：首屏加载与筛选条件、
  引擎选项按 `detection_engine || name` 取值并用「`label || name`（发现数）」作标签、注册表失败时
  选项为空且不影响列表、重置回第一页、详情到位后才开抽屉、详情失败时的提示与抽屉保持关闭、
  列表失败进页面状态、手动流水线拆日志行与解析 JSON（空值走 `undefined`/`{}`）、JSON 非法时拒绝下发、
  流水线失败时清空上一次结果。

验证：

- `npm run typecheck` 通过；全量 vitest 20 个文件 151 项通过（原 141 项 + 本批 10 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `DetectionCenter` chunk 均 200，chunk 名与本地
  构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/detections`（3606 条）、
  `/detections/{id}`（37 个关联事件、9 项证据、命中 alert）、`/engine/registry`（15 个引擎）、
  `/assets`、`/probes`、`/incidents`、`/alerts`、`/alerts/summary`、`/files`、`/dlp/policy`、
  `/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；本批未导入
  测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-detection-centre-state-20260920`。

## 第二十四批：前端引擎详情页状态解耦（2026-09-20）

基线 `1952b3a`，同一分支。目标：按指南 §F 把引擎详情的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/engines/composables/useEngineDetail.ts`（114 行）；
  `EngineDetail.vue` 208 → 126 行。去掉缩进后，迁入的 83 行脚本逐行比对未改。
- composable 接收路由派生的 `name`（`ComputedRef<string>`，`watch(name)` 也在里面），路由、
  导航与 `executionLabels` 静态标签留在视图，与对象/实例详情页同一约定。
- 注册表解析（`slug || name` 再退回同名匹配）、规则数（注册表 → 同名适配器 → `null`）、
  适配器状态合并、规则清单的关键字筛选与 30 条分页、`expandRule` 懒加载规则内容、发现列表与
  最近任务全部原样迁移。
- 本批删除视图里因搬迁而不再使用的 `EngineStatus` 类型导入。
- 新增 `frontend/src/__tests__/engine-detail-state.test.ts`（11 项）：首屏四路加载（集成/健康/注册表/
  任务）、路由经注册表解析到 `detection_engine` 后再取规则与发现、注册表无匹配时退回路由名、
  规则数取注册表优先再取适配器（都为缺省时为 `null` 且不改写适配器值）、适配器按名字大小写不敏感
  匹配与缺失时为 `null`、`isSigma` 判定、规则 30 条分页、关键字按名称/ID/路径筛选并回到第一页、
  路由名变化时重载并回到第一页、`expandRule` 只对展开行且只加载一次、规则内容失败与整页失败进
  页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 21 个文件 162 项通过（原 151 项 + 本批 11 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `EngineDetail`/`EnginesOverview` chunk 均 200，
  chunk 名与本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、`/engine/registry`
  （15 个引擎，`sigma_log_engine` 的 `slug=sigma`、`rule_count=2949`）、`/integrations`、`/tasks`、
  `/detections`、`/rules?engine=sigma_log_engine&include_content=false`、`/assets`、`/probes`、
  `/incidents`、`/alerts`、`/alerts/summary`、`/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；本批未导入测试数据、未操作真实探针主机；
  后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-engine-detail-state-20260920`。

## 第二十五批：前端看板页状态解耦（2026-09-20）

基线 `2322347`，同一分支。目标：按指南 §F 把看板的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/dashboard/composables/useDashboard.ts`（94 行）；`Dashboard.vue`
  195 → 127 行。去掉缩进后，迁入的 69 行脚本逐行比对未改。
- 十路并发加载（汇总、风险、健康、两条趋势、严重度、引擎、事件、高风险资产、敏感数据）、
  风险档位投影、两处环形图共用的 `levelBreakdown`、引擎图表的 x/y 投影全部原样迁移。
- 视图保留路由与 `formatDateTime`/`formatRiskScore`（模板绑定），以及模板里 `Incident`/`Asset`
  类型注解需要的两个类型导入。
- 本批删除视图里因搬迁而不再使用的 `utils/mapping` 导入（`severityLabels`/`severityOrder`/
  `severityTagColors` 随 `levelBreakdown` 进 composable）。
- 新增 `frontend/src/__tests__/dashboard-state.test.ts`（7 项）：十路加载与投影结果、风险档位按
  Critical→Low 固定顺序并补 0、严重度环形图按共享刻度排序且颜色与标签一致、计数为 0 的档位被丢弃且
  保留接口多出来的档位、敏感类别走同一套刻度、引擎图表投影成并行的 x/y、失败进页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 22 个文件 169 项通过（原 162 项 + 本批 7 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `Dashboard`/`EngineDetail` chunk 均 200，chunk 名与
  本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/dashboard/summary`（告警 479、开放告警 475、事件 208、高危检测 3266、
  高风险资产 13、敏感数据资产 33、在线探针 1、健康集成 4）、`/risk/summary`（3614 条：Critical 234 /
  High 3032 / Medium 339 / Low 9）、`/dashboard/risk-trend`、`/dashboard/incident-trend`、
  `/dashboard/severity`、`/dashboard/engines`、`/dashboard/incidents`、`/dashboard/high-risk-assets`、
  `/dashboard/sensitive-data`（含 `Unknown` 额外档位）、`/health`、`/test/status`（`present=false`）、
  `/auth/me`、`/engine/registry`、`/detections`、`/assets`、`/probes`、`/incidents`、`/alerts`、
  `/alerts/summary`、`/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、
  `/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、
  `/sensitivity-levels` 均 200；本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍
  `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-dashboard-state-20260920`。

## 第二十六批：前端安全审计页状态解耦（2026-09-20）

基线 `3086f81`，同一分支。目标：按指南 §F 把安全审计的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/operations/audit/composables/useSecurityAudit.ts`（69 行）；
  `SecurityAudit.vue` 167 → 121 行。去掉缩进后，迁入的 50 行脚本逐行比对未改。
- 视图保留 `riskLabels` 静态标签与 `formatRiskScore`；审计汇总、日志分析、`matchGroups` 投影进
  composable（模板直接调用 `matchGroups`，因此它由 composable 导出）。
- 行为不变：汇总只读；日志内容为空或全空白时只提示不发请求；日志分析失败只写 `logError`，不改页面级
  `error`；`matchGroups` 顺序与标签不变、计数为 0 的分组丢弃、缺 `log_summary` 时返回空数组。
- 新增 `frontend/src/__tests__/security-audit-state.test.ts`（7 项）：首屏加载审计汇总、汇总失败进
  页面状态、空日志被拒绝、日志分析成功保留结果、日志分析失败只进 `logError`、`matchGroups` 按固定
  顺序分组并丢弃空分组、缺 `log_summary` 时返回空数组。

验证：

- `npm run typecheck` 通过；全量 vitest 23 个文件 176 项通过（原 169 项 + 本批 7 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `SecurityAudit`/`Dashboard` chunk 均 200，chunk 名
  与本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/audit/summary`（资产 214、文件 1、PCAP 3996、异常 9；资产风险 Medium 33 /
  High 13 / Low 168；异常等级 High 9；泄漏风险 High，高危协议 `http`）、`/health`、`/test/status`
  （`present=false`）、`/auth/me`、`/dashboard/summary`、`/risk/summary`、`/engine/registry`、
  `/detections`、`/rulesets`、`/tasks`、`/assets`、`/probes`、`/incidents`、`/alerts`、`/alerts/summary`、
  `/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、`/data/assets`、
  `/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  本批未 `POST /audit/logs`（保持只读），未导入测试数据、未操作真实探针主机；后端未重建，迁移仍
  `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-security-audit-state-20260920`。

## 第二十七批：前端流量视图页状态解耦（2026-09-20）

基线 `673e5f1`，同一分支。目标：按指南 §F 把流量视图的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/network/traffic/composables/useLiveTraffic.ts`（77 行）；
  `LiveTraffic.vue` 143 → 90 行。去掉缩进后，迁入的 53 行脚本逐行比对未改。
- 实时告警流的 `EventSource` 归 composable 所有：`onMounted` 打开、`onBeforeUnmount` 关闭、
  只保留最新 50 条、非法 JSON 静默丢弃；页面保留路由与 `formatDateTime`/`formatBytes`。
- 行为不变：抓包速率从最近一次已分析捕获推导，无实时窗口时三项为 `null`；在线探针按 `status === 'online'`
  过滤；`recentPcaps` 仍被加载但模板未渲染（与本批无关，保持原样）。
- 新增 `frontend/src/__tests__/live-traffic-state.test.ts`（8 项）：五路加载、加载失败进页面状态、
  只保留在线探针、抓包速率推导与无窗口时的 `null`、挂载即打开告警流并只保留最新 50 条、告警缺字段时
  的默认值、非法事件被忽略、卸载时关闭告警流。

验证：

- `npm run typecheck` 通过；全量 vitest 24 个文件 184 项通过（原 176 项 + 本批 8 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `LiveTraffic`/`SecurityAudit` chunk 均 200，chunk 名
  与本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/network/live`（窗口 300s、连接 214、包 536、pps 1.79、bps 1553.67、在线探针 1）、
  `/pcaps`、`/alerts/summary`、`/probes`、`/flows`、`/protocols`、`/health`、`/test/status`
  （`present=false`）、`/auth/me`、`/audit/summary`、`/dashboard/summary`、`/risk/summary`、
  `/engine/registry`、`/detections`、`/assets`、`/incidents`、`/alerts`、`/files`、`/dlp/policy`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；未订阅真实告警流（`/alerts/stream` 未连接）、
  未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-live-traffic-state-20260920`。

## 第二十八批：前端算法评估页状态解耦（2026-09-20）

基线 `32f7821`，同一分支。目标：按指南 §F 把算法评估页的状态抽到 composable，模板与交互不变。
本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/tools/composables/useAlgorithmEvaluation.ts`（141 行）；
  `AlgorithmEvaluation.vue` 306 → 196 行。去掉缩进后，迁入的 116 行脚本逐行比对未改；模板与样式
  逐字节未改（175 行）。
- 两个标签页的状态一起进 composable：标签选择、密码配置与四个文本输入、评估结果、探针列表与选择、
  自动识别结果，以及代码/语言/复杂度结果；页面保留三个展示组件与静态语言下拉 `languages`。
- 行为不变：密码评估仍在浏览器本地计算，只读探针列表与单个探针的密码画像；从探针自动识别在
  `algorithms`/`cipherSuites`/`protocols`/`keyLengths` 为空时回退默认配置，`passwordSignals` 并入评估
  发现；复杂度分析仍用 `acorn` AST 本地计算；`cryptoLevelTone` 随结果进 composable。
- 新增 `frontend/src/__tests__/algorithm-evaluation-state.test.ts`（15 项）：默认标签与默认配置、挂载
  加载探针列表、空列表、加载失败、默认配置评估为「合规」、四个文本输入的解析（分号/换行与非数字
  过滤）、弱配置样例清空结果且评分低于 90、等级到颜色的映射、未选探针时只警告不发请求、从探针填充
  并立即评估、画像字段为空时回退默认、画像密码信号并入发现、画像读取失败、复杂度分析、切换语言后的
  复杂度分析。

验证：

- `npm run typecheck` 通过；全量 vitest 25 个文件 199 项通过（原 184 项 + 本批 15 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `AlgorithmEvaluation`/`LiveTraffic` chunk 均 200，
  chunk 名与本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/network/live`（窗口 300s、连接 115、包 277、pps 0.92、bps 436.04、在线探针 1）、
  `/pcaps`、`/alerts/summary`、`/probes`、`/flows`、`/protocols`、`/health`、`/test/status`
  （`present=false`）、`/auth/me`、`/audit/summary`、`/dashboard/summary`、`/risk/summary`、
  `/engine/registry`、`/detections`、`/assets`、`/incidents`、`/alerts`、`/files`、`/dlp/policy`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；未订阅真实告警流（`/alerts/stream` 未连接）、
  未导入测试数据、未提交密码评估或探针画像请求、未操作真实探针主机；后端未重建，迁移仍
  `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-algorithm-evaluation-state-20260920`。

## 第二十九批：前端威胁情报与规则页状态解耦（2026-09-20）

基线 `c1438a0`，同一分支。目标：按指南 §F 把威胁情报与规则三页的状态抽到 composable，模板与交互
不变。本批没有模板改动。

已完成代码：

- 新增 `frontend/src/modules/threat/composables/useRulesCenter.ts`（74 行）、`useCveCenter.ts`（92 行）
  与 `useIocCenter.ts`（59 行）；`RulesCenter.vue` 110 → 65 行、`CveCenter.vue` 126 → 60 行、
  `IocCenter.vue` 118 → 82 行。去掉缩进后，迁入的 52/70/39 行脚本逐行比对未改，三页模板与样式
  逐字节未改。
- 页面只保留静态展示：执行状态标签（`executionLabels`）、CVSS 等级映射（`cvssLevel`）、筛选字段配置
  （`filterFields`）与时间/展示格式化函数；`RulesCenter.vue` 仍保留模板用到的 `RuleItem` 行类型导入。
- 行为不变：规则库以 `include_content: false` 读取、内容按需展开拉取（已展开且已有内容时不重复请求）；
  新增规则仍由服务端校验后重载列表；CVE 页的 Grype 任务轮询（2s）归 composable 所有、任务 id 存
  `localStorage`、卸载时清除定时器、失败或完成即停止；IOC 启停仍按 `metadata.enabled` 取反提交后重载。
- 新增 `frontend/src/__tests__/threat-center-state.test.ts`（32 项）：规则中心的挂载加载与失败、类型/
  引擎过滤、名称/规则 ID/路径的忽略大小写搜索、每页 30 条分页、筛选变化回到第一页、去重并排序的类型
  列表、添加弹窗按当前类型赋默认值、超过 1 MB 的规则文件被拒、读取文件并推导规则名、校验新增后重载、
  新增失败不关弹窗、展开时按需拉取内容且不重复请求；CVE 中心的挂载加载与 Grype 库标注、已导入库的
  标注、加载失败、搜索回到第一页、跟踪并记住 Grype 任务、轮询到完成后重载、失败后停止轮询、导入错误
  优先于计数上报、导入计数、空文件选择被忽略、手工新增后关闭弹窗、挂载时恢复记忆任务且卸载后不再轮询；
  IOC 中心的挂载加载、加载失败、重置到第一页、打开关联抽屉、关联失败不开抽屉、启停取反并重载、
  启停失败上报。

验证：

- `npm run typecheck` 通过；全量 vitest 26 个文件 231 项通过（原 199 项 + 本批 32 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `RulesCenter`/`CveCenter`/`IocCenter` chunk 均 200，
  chunk 名与本地构建一致、线上字节 SHA256 相同；chunk 内无 `VITE_DEMO_MODE`（IOC chunk 里唯一命中
  「demo」的是 `IntelligenceSources.vue` 既有占位示例 `demo-exfil.example`，非本批改动）。
- 真实环境只读复验：`/network/live`（窗口 300s、连接 157、包 416、pps 1.39、bps 1022.7、在线探针 1）、
  `/pcaps`、`/alerts/summary`、`/probes`、`/flows`、`/protocols`、`/health`、`/test/status`
  （`present=false`）、`/auth/me`、`/audit/summary`、`/dashboard/summary`、`/risk/summary`、
  `/engine/registry`、`/detections`、`/assets`、`/incidents`、`/alerts`、`/files`、`/dlp/policy`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；未订阅真实告警流（`/alerts/stream` 未连接）、
  未导入测试数据、未提交规则新增或 CVE/情报导入请求、未操作真实探针主机；后端未重建，迁移仍
  `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-threat-centre-state-20260920`。

## v2.13.0 发布（2026-09-20）

基线 `5c5b1d4`（develop）。把 `refactor/data-asset-boundaries` 的 30 个提交合并回 `develop` 并发布：
平台版本 2.11.0 → **2.13.0**，探针保持 3.5.0，迁移保持 `0015_alert_hits`。本版是纯结构调整，不新增功能、
不改判定逻辑、不动历史数据；`refactor/data-asset-boundaries` 分支保留在原位（556a37d），未删除。

已完成：

- 版本：`backend/app/main.py`、`frontend/package.json`、`frontend/package-lock.json` 升到 2.13.0。
- 文档：`CHANGELOG.md` 新增 v2.13.0 段；`docs/versioning.md` 增加版本条目与发布说明；新增
  [发布记录](docs/releases/v2.13.0.md)；更新本文件与 `PROJECT_STATUS.md`。
- 后端核验（隔离容器、`--network none`、只读挂载源码、临时 SQLite 与隔离存储）：同环境对照 `develop`
  596 项 / 12 项失败 → 本版 726 项 / 同样 12 项失败（新增失败 0 项，新增 130 项回归）；工作树只读挂载复核
  726 项 / 2 项失败。
- 契约对照：OpenAPI 144 路径 / 158 操作、38 张表、104 个索引与拆分前逐项一致。
- 前端：`npm run typecheck` 通过；vitest 26 个文件 231 项通过；生产构建通过。
- 镜像与运行栈：重建 backend / worker / beat / deployment-worker 与 frontend 镜像并切换容器，运行栈自报
  2.13.0，`/health` ok，迁移 `0015_alert_hits`，只读复验的 27 个接口全 200。
- 回退标签：`source-backend` / `source-worker` / `source-beat` / `source-deployment-worker` /
  `source-frontend` 的 `pre-v2.13.0-20260920`（本机镜像，回退代码需回到发布提交前的快照）。
- 发布：发布快照提交 `15a6ace`，`develop` 上的合并提交 `a6ec580`（`--no-ff`），注释标签 `v2.13.0`；
  `origin/develop` 与标签均已推送。

未做（保持边界）：没有调用测试数据导入接口、没有历史数据重算、没有操作真实探针主机、没有重建或覆盖
同名探针分发包。

## 后续批次（尚未实施，不宣称全项目解耦完成）

后端路由已全部按域拆出（`v1.py` 只做聚合）。剩余：

1. 前端其余页面（检测分析、任务与报表、探针页等）按实际改动需求再拆（同一模式：
   先抽状态，再抽视图；数据安全域、事件/告警中心、资产中心、检测中心、引擎详情、看板、
   安全审计、流量视图、算法评估与威胁情报三页已完成）。
2. 模型包拆分放在业务依赖稳定之后；最后独立处理探针模块及分发包，不擅自升级真实主机。
3. 旧的 `workers/tasks.py` 兼容门面、`data_object_service.py` 与 `v1.py` 里的兼容重导出
   在确无调用方后再删除。

不要把本批的结构移动与历史数据回填或检测规则修改混在一起。

## 历史

- [本批前任务全文](docs/history/task-before-data-asset-refactor-2026-09-19.md)
- [本批前项目状态全文](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)
- [v2.12.0 发布记录](docs/releases/v2.12.0.md)
- [v2.13.0 发布记录](docs/releases/v2.13.0.md)
- [总体解耦指南](docs/解耦操作指南.md)

## 2026-09-20 任务到采集资产关联（本轮）

- 真实只读核对：file 投影 2171 条，其中 1491 条名称对应 PcapRecord；历史记录未被止增修复自动清理。任务 #5007（/opt）7 条、#4651（/etc）220 条、#4649（/home）46 条均有对应实例。
- 采集任务页原“数据类型”只跳全局列表，现改“查看资产”抽屉，按任务分页，支持跳转实例详情。
- `/asset-instances` 新增可选 task_id，任务查询额外返回 association，以任务所属 probe 隔离范围。新报告将实际入库实例 ID 集合写入 Task.result.asset_instance_ids，后续扫描不会抹掉成员关系；详情显示当前状态，不是历史快照。
- 旧任务没有成员清单时按任务 probe + result.scan_id 匹配 last_scan_id，association=latest_scan_only，前端说明后续扫描覆盖可能导致列表不完整；缺 scan_id 返回空，不回退为全局资产。
- 后端对象模型/采集 API/数据资产边界/DataEngine 62 项通过；前端 29 文件 251 项通过，typecheck 通过。新增测试覆盖跨探针隔离、无敏感命中的资产、重复扫描后成员保留、分页、旧任务兼容及关闭抽屉后的过期响应。
- 历史 PCAP 投影仍保留，未删除抓包、资产或证据；在线探针未操作。

部署验收：legacy builder 重建 source-backend:latest（89e5b928bdbe）与 source-frontend:latest（2b37ef01d50a），仅重建本机 backend/frontend 容器。登录真实 API 后，任务 #5007/#4651/#4649 分别返回 7/220/46 条，分页正确，association=latest_scan_only；data-types 与 health 均 200。nginx 实际下发的任务页 bundle 包含“查看资产”及 task_id 查询。浏览器停在登录页，未完成登录后的端到端点击验收。构建日志在 data/task-assets-{backend,frontend}-build.log；未清理镜像缓存或历史数据。

## 2026-09-20 后续请求：删除异常、/tmp、FTP 来源与界面整合（FTP 与界面整合见下一节；探针 /tmp 待处理）

用户要求先提问理解目的，再增加类似数据库来源的 FTP 共享文件源，压缩“资产与数据安全”模块重复功能、提高信息密度；若额度不足需要可交接总结。已发送三组澄清（检查交付/持续管理/演示目的；FTP/FTPS/SFTP 与读取方式和目标；异常线索与必须保留的操作），尚未收到回答。不要把建议的四入口当成用户已确认。

只读诊断：
- 卸载 7/8/9 均针对 192.168.191.130，7 成功释放 273387473 字节、5893 个文件；8/9 所有目标已不存在。实际远端卸载成功。
- 平台探针 2 test123 仍 offline。deployment-worker 日志给出 alert_hits_probe_id_fkey 外键错误，随后 PendingRollbackError；delete_probe_record 遗漏 AlertHit，RemovalService 在失败事务上继续记日志/销毁凭据。
- /tmp 任务 5061/5067/5069/5071 都 directories_scanned=1、files_discovered=0、files_analyzed=0；显示的资产 1 是实例 759（database_service，127.0.0.1:3306），不是文件。probe/install.sh 与 service 模板均 PrivateTmp=true，宿主 /tmp 隔离是强烈根因线索，但未 SSH 核对实际 unit。旧探针未升级，现已卸载，不应盲目重试远端删除或扫描。

本轮代码修复（未部署）：
- services/probe_service.py 清空 AlertHit.probe_id 后删除探针，保留告警命中证据。
- deployment/removal.py 平台删除 SQLAlchemyError 时先 rollback，再保留远端 REMOVED 事实并记录 platform_record_deleted=false / platform_record_error=database_error；允许 finally 正常销毁 SSH 凭据。
- 回归 backend/tests/test_probe_delete.py + deployment/test_removal.py：17 项通过，新增有外键的告警命中保留与真实失败事务恢复测试。
- 未部署、未删除线上平台记录、未连接目标主机；尚未新增 FTP 或调整菜单/UI，也未改变 PrivateTmp。

下一步：先收集用户回答确定业务流与 FTP 协议范围；整合来源/任务/资产/敏感发现，保留旧 URL 兼容。FTP 需新迁移（不改 0016）、加密凭据、目录范围和资源预算、只读下载与临时文件清理、共享敏感引擎、资产和任务关联、测试及部署。探针 /tmp 可见性须明确配置方案并出包验证；平台删除修复需重建 backend 和 deployment-worker 后验证，删除现有记录会按既有逻辑删除其对象实例/检测状态，执行前应明确用户是否要求保留这些历史结果。

## 2026-09-20 共享文件来源（FTP/FTPS/SFTP）与界面整合（本轮完成并部署）

用户给出真实 FTP 目标 `192.168.191.130`（vsFTPd 3.0.5）、账号 `kali`，口令以用户最后确认的为准。
上一段「等待澄清」的 FTP 来源本轮做成可用功能，接入界面并在真实目标上验证。

已完成源码：

- 后端 `services/file_scan/`：`adapters` 只读传输、`credentials` AES-GCM 口令、`service` 配置校验与任务快照、
  `scan` 预算化枚举与临时文件清理、`ingest` 复用共享敏感引擎与数据对象写入口；路由 `api/file_sources.py`
  （列表/新建/更新 + `test`/`scan` 两个动作）；任务名 `security_toolbox.file_source_scan` 与
  `file_source_schedule`（beat 每 60 秒检查到期来源）；迁移 `0017_file_sources`（head）。
- 真实目标暴露的缺口：vsFTPd 3.0.5 不实现 `MLSD`（`FEAT` 不声明、回答 `500`），原适配层只会用它列目录，
  真实采集必然失败。现改为优先 `MLSD`，遇到 500/502 回退解析 `LIST`（ls -l 格式）：目录/文件/符号链接分类、
  名字含空格不截断、符号链接只记 `skip` 不跟随、`-> 目标` 不参与名称校验；550 等真实回答不重试，
  直接归类为 `path_error`。传输失败按类别上报（`auth_error`/`path_error`/`protocol_error`/`timeout`/
  `dns_error`/`unreachable`），服务器回显文本永不落库。
- 界面整合：新增「来源管理」（`SourceManagement.vue`：共享文件 / 数据库 / 主机探针 / 手动文件四个入口）与
  「资产目录」（`AssetInventory.vue`，同一页支持「敏感发现」模式），路由 `/source-management`、
  `/asset-inventory`；菜单把「数据库直连盘点」换成「来源管理」并加「资产目录」，旧 URL
  （`/database-connections`、`/data-assets`、`/sensitive`）全部保留，未删除任何旧页面。
- 实例详情缺口：详情接口没返回 `source_kind`/`owner_key`/`source_name`，页面把共享文件与数据库来源
  一律显示成「探针文件」。现按 `owner_key` 口径返回来源类型与采集器名称/地址，页面按探针 / 数据库连接 /
  共享文件三类显示。

验证（真实 FTP，非合成）：

- 连通性测试任务 #5078 `Success`；采集任务 #5079 登记 11 个资产（`/srv/dst-e2e`，含 4 层嵌套与 UTF-8
  中文名 `客户信息.xlsx`）、7 个含值命中（`id_card`/`phone`/`bank_card`/`email`）、67MB 大文件按
  `single_file_limit` 跳过并如实标记 `complete_scope=false`；重复采集 #5095 为 `new=0 changed=0`，
  逐文件覆盖度/终止原因分别为 `complete`/`row_limit`/`sampled`/`single_file_limit`。
- 命中原文：实例 768（`客户信息.xlsx`）经 `GET /detections/{id}/evidence` 取回原文（如 `110101199001010040`）。
- 口令只写不读：库内为 20 字节 AES-GCM 密文 + 12 字节 nonce + `password_key_id=dbc1`；任务 payload/result
  与 4 条审计（`file_source.create/test/scan`）只有协议与任务号，没有任何口令字段；响应只有 `password_set`。
- 后端 829 passed / 6 failed（失败集合与基线逐项一致，均为本机缺 tshark 等环境项）；`test_file_sources.py`
  17 项（新增 `MLSD` 缺失回退、550 归类、登录回显不进错误、实例详情来源字段）；前端 `vue-tsc` 通过、
  vitest 31 文件 267 项通过（新增 `file-sources-state`、`asset-inventory-state` 与实例详情来源断言）。
- 部署：legacy builder 重建 backend/api 与 analysis-worker（另打 beat/deployment-worker 标签）与 frontend；
  容器重建后 `/health` 全绿、迁移 `0017_file_sources (head)`、worker 注册两个新任务名；线上 `index`、
  `SourceManagement`、`AssetInventory`、`DatabaseConnections` 四个 chunk 与本地生产构建 SHA256 逐字节一致，
  bundle 内无 DEMO/mock 代码。构建日志 `data/filesource-build-{backend,backend-2,frontend,frontend-2}-20260920.log`，
  后端回归日志 `data/regression-backend-20260920-filesource-batch.log`。
- 清理（按用户既有要求不留历史镜像）：删除 5 个 `pre-file-sources-20260920` 回退标签、`docker image prune -f`
  （回收 1.779GB）、`docker builder prune -f` 与 `docker container prune -f`（均 0B）；只剩 5 个
  `source-*:latest`，Docker 镜像计账 51.26GB → 34.37GB（剩余 13.55GB 可回收属于其他项目 opendlp/openaev，
  未触碰），C: 可用 42.9 GiB。仓库里已没有可回退镜像，回退需从 git 提交重建。
- 隐私/交付口径未变：未调用 `POST /api/v1/test/import`，未启用 `VITE_DEMO_MODE`，未导入任何测试数据。

未做 / 待用户决定：

- 浏览器点击验收仍无法在本机执行（自动化的 Codex 登录方式不支持浏览器控制），人工验收请在登录后打开
  `/source-management` 与 `/asset-inventory`。
- 该 FTP 的共享根 `/srv/ftp` 是空目录，本轮来源指向确有敏感内容的 `/srv/dst-e2e`；`root_path` 与目标地址
  不可改（保留来源历史），若要看 `/srv/ftp` 请另建来源。
- 界面整合只做「新增入口 + 去掉重复菜单项」，`/data-assets`、`/sensitive` 两个旧页面仍在菜单里；是否把
  它们合并进「资产目录」需要用户确认后再做。
- 探针 `/tmp` 的 `PrivateTmp` 可见性问题、以及平台删除探针记录的外键修复（已随本轮 worker/deployment-worker
  镜像部署，但未对真实探针执行删除验证）仍待处理，见上一节。

### 追加：共享目录可改、来源可删（2026-09-20 晚）

用户反馈「共享目录不支持修改」。原因是最初把 `root_path` 与协议/地址/端口一起锁成不可变，理由是保留来源历史；
但路径本身按远端绝对路径存储，改目录不会让历史错位，锁住它只挡住了正常操作。现在：

- `service.save` 只对 `protocol`/`host`/`port` 报 `create_new_source_for_new_target`；`root_path` 可随时改，
  改完重建 `next_scan_at` 并按新目录采集；移出目录的旧路径在下一次完整采集后才标记 `NOT_OBSERVED`（不删除）。
- 新增 `DELETE /api/v1/file-sources/{id}`（管理员 + 审计 `file_source.delete`）：只删配置，已采集的资产、
  检测与证据保留；采集中的来源返回 `source_busy`。前端行内加「删除」按钮（二次确认）。
- 前端：编辑抽屉里「根目录」不再禁用，提示文案改为「改目录不需要新建来源；移出目录的文件只会标记未再观测」，
  资产告警文案改为「协议/地址/端口改动请新建来源（保留原来源历史）；共享目录可随时修改」。
- 真实环境验证（`192.168.191.130`）：新增来源 #3 `kali-oscp-share`（`/home/kali/oscp`）→ 测试 `Success` →
  采集 `Success` 3 个文件；把 #3 根目录改成 `/home/kali/oscp/reports` → 立即生效且连通性测试 `Success`
  （口令未重发，`password_set` 仍为 true）→ 改回 `/home/kali/oscp`；改 `host` 仍被拒绝
  （`create_new_source_for_new_target`）；新建临时来源 #4（`/srv/ftp`）→ 删除成功 → 列表回到 3 条，
  重复删除返回「文件源不存在」。
- 回归：`test_file_sources.py` 19 项（新增共享目录可改 / 端点仍不可改 / 采集中不可删 / 删除后行不存在）；
  前端 `file-sources-state` 10 项（新增改目录随表单提交、删除需确认、取消不删、服务端拒绝时保留行）；
  后端全量 831 passed / 6 failed（失败集合与基线一致）；`vue-tsc` 通过、vitest 31 文件 269 项通过；
  线上 `index-CnNjiRpn.js`、`SourceManagement-DtMkEBNj.js` 与本地生产构建 SHA256 逐字节一致。
- 顺带发现：用户自建来源 #2 `test` 指向 `/root`，以 `kali` 走 FTP 时该目录只列出一个空目录（采集会得到
  0 个文件），现在可以直接改目录或删除。

### 追加：统一规则源与命中原文（2026-09-20 深夜）

用户反馈「pcap 包的规则也要匹配网络防泄密的规则；手动添加一条规则匹配张三，敏感发现、实时流量告警、
网络防泄密都要匹配到他，并且要显示传输原文」。

源码（平台侧统一规则源）：

- `services/sensitive_engine.py` 成为平台侧唯一引擎入口：`analyst_rules()` 把规则库
  （`data/integrations/dlp_rules/*.json`，`manual` + `presidio_static`）转成共享规则格式
  （`EMAIL`/`EMAIL_ADDRESS` 套 `email_shape` 校验器），`analyst_signature()` 用文件 mtime+size 做签名，
  `scan_engine()` 按签名重建并缓存「内置包 + 手写规则」的引擎，`scan_all()` 一次扫描两种来源，
  `has_analyst_rule()` 区分手写与内置，`scan_timeouts()` 上报超时规则；
  `to_legacy_hits(..., include_matches=True)` 新增 `matches` 出口，且**不再小写化 `kind`**
  （自定义实体 `COMPANY`/`测试` 原样保留），类别过滤改为大小写不敏感。
- 消费方全部改走统一引擎：`engine/data_engine/engine.py`（`scan_text` → `scan_all`、
  `infer_columns` → `scan_engine`，无历史类别的规则补 `counts`）、`services/file_scan/ingest.py`、
  `services/database_scan/detect.py`、`services/dlp_service.py`。
- `services/ruleset_service.py::sync_analyst_rules()` 把规则库镜像进规则集的**工作副本**（已发布版本不可变，
  仍需人工发布才下发给探针）；`api/libraries.py` 的规则新增/更新接口返回 `working_copy: {added, updated}`。
- 网络防泄密：`inspect_content()` 改用 `scan_all`；内置包命中按 `policy['categories']` 过滤，
  **手写规则命中不过滤**（作者意图优先）；每条命中带 `matches`（value + context，≤3 条 / value ≤120 /
  context ≤240）。策略关键词命中用 `shared/sensitive_detection/engine.py::text_matches()` 生成原文并标
  `rule_source='policy_keyword'`；文件指纹命中标 `rule_source='policy_fingerprint'`。`analyze_capture()`
  不再往策略里塞 `managed_rules`，改用局部 `rule_timeouts`，顺带修掉「把策略列表当列表用」导致跨任务累积的 bug。
- 前端：`useNetworkDlp.ts` 的 `Hit`/`Transfer` 加 `matches` 与 `rule_id(s)`/`rule_source(s)`，新增
  `matchedText(row)`/`hasMatchedText(row)`；`NetworkDlp.vue` 传输表提示「可查看传输原文」、证据抽屉新增
  「命中原文」表；`RuleMatchPanel.vue` 补 `context`/`rule_id(s)`/`rule_source(s)`/`action`/`mode` 标签。

真机验证（真实目标机 `192.168.191.130`，探针 3「kali」在线；未调用 `POST /api/v1/test/import`、未启用 DEMO）：

1. **敏感发现（文件来源）**：采集任务 #5213 登记新资产实例 791 `/srv/dst-e2e/客户名单.csv`，检测
   `detections.id=146`（类别 `测试`、`confidence=0.7`、`source_kind=file_share`）；
   `GET /api/v1/detections/146/evidence` 返回 `matches_returned=1`、
   `rule_id=manual-97d1c75a…`、`rule_source=manual`、`field_name=姓名`、
   `matches=[{value:"张三", context:"张三 李四"}]`。
2. **网络防泄密（真实抓包）**：`tcpdump -i eth0` 抓取 192.168.191.1 → 192.168.191.130:8099 的明文 HTTP
   上传（multipart，文件名 `客户名单.csv`，259 字节负载，含姓名/身份证/手机/邮箱），
   `POST /api/v1/pcaps/upload` 后分析任务 #5230 `Success`（12 包）。对象
   `客户名单.csv POST http://192.168.191.130:8099/upload` 的 `matches` 同时含 email/phone/id_card 与
   手写规则 `测试`（`rule_ids=['manual-97d1c75a…']`、`rule_sources=['manual']`、`value='张三'`、
   `context='C0001,张三,110101199001010040,…'`）；finding #4443 的证据同样带原文。
3. **实时流量告警（探针链路端到端）**：在探针主机上做了一次真实明文外发（源 192.168.191.130 →
   目的 `93.184.216.34:8099`，463 字节，HTTP 200；该目的地址只在实验机本地接收、不路由出网，验证后已删除），
   探针 `-i any` 抓到该流并切片上传（pcap #5158 = 分片 `…000135`），平台自动分析出 finding #4452
   （`dlp_engine`/`DLP_TRANSFER_001`，`risk_model.exposure_basis=external_destination`、`risk=76.5`）
   并生成告警 **#606**（`probe_id=3`、`High`、`risk 76.5`）；`GET /api/v1/alerts/606` 的
   `detail.finding.evidence.matches` 带 email/phone/id_card 与手写规则 `value='张三'`。复现一次后新告警
   **#610**（finding #4471，pcap #5184）实时生成，Redis `security.alerts` 订阅端在告警创建同一秒收到
   `alert.created` 事件——`/network/live`（LiveTraffic）的 SSE 推送链路真实可用。

未做 / 需要用户决策：

- **内部互传不会告警（设计边界）**：同一次上传换成实验网内互传（192.168.191.1 → 192.168.191.130）时，
  finding #4443 的 `risk_model.exposure_basis=internal_only`、`exposure_factor=2.0`、`risk=51.0`，
  低于告警策略 `high_finding_min_risk=60`，因此**不产生告警**，只有网络防泄密页能看到命中与原文。
  即：手写规则在三条链路都能命中，但「目的地址是公网」才越过告警阈值。是否对人工规则命中单独放行
  （或下调阈值）属于策略决定，本轮未擅自改动风险模型。
- 手写规则已同步到规则集工作副本，但**探针侧生效仍需人工发布规则集版本**。

## 本轮交付：v2.14.0 离线包（2026-09-20，已完成）

用户要求「整理当前版本、只保留必须文件、可在银河麒麟 V10 SP1（x86_64）离线一键部署」，随后追加
「Ubuntu 22.04 LTS 也要部署到该环境」。已完成：

- **版本**：平台 2.14.0（`backend/app/main.py`、`frontend/package.json` 与 lock）、探针 3.6.0
  （`probe/probe.py`、`backend/app/core/config.py`、`scripts/build_probe_packages.py`、`.env`、
  `.env.example`、`docker-compose.yml` 的 `${PROBE_AGENT_VERSION:-3.6.0}` 四处），迁移 head
  `0017_file_sources`。文档已补 `CHANGELOG.md` v2.14.0、`docs/versioning.md`、`docs/releases/v2.14.0.md`、
  `docs/offline-package.md`。**未创建 Git 标签、未提交**（用户要求）。
- **探针分发包**：已重建 `probe_packages/probe-3.6.0/{amd64,arm64}`，覆盖同名旧包；未升级任何真实主机。
- **离线包**：`dst-toolbox-2.14.0-linux-x86_64/` 与 `dst-toolbox-2.14.0-linux-x86_64.tar.gz`，由工作区
  （仓库外）`dist-linux-build/` 下三个脚本依序生成：`make_bundle.py` → `save_images.py` →
  `finalize_bundle.py`。`make_bundle.py` 改为**保留 `images/`**，可反复重跑；`deploy.sh` 在目标机缺
  Compose v2 时会自动安装随包插件；`install-probe-offline.sh` 的探针版本占位符已修正为 3.6.0。
  制品名由 `...-kylin-x86_64` 改为 **`...-linux-x86_64`**：镜像与发行版无关，同一套包同时覆盖麒麟与 Ubuntu。
- **包内容**：8 个镜像（5 个应用镜像 + postgres 16.6 / redis 7.4 / flower 2.0.1，归档 2689.1 MB）、
  探针包、探针离线 wheel（amd64/cp311）、Compose v2 插件、同源源码快照、`VERSION` 与
  `CHECKSUMS.sha256`；含 `deploy.sh`/`undeploy.sh`/`load-images.sh` 与 `README-离线部署.md`。
- **交付物指纹（修掉可执行位 + 端口预检的那一版；已被下节 r2 取代）**：`dst-toolbox-2.14.0-linux-x86_64.tar.gz`
  = 2.65 GB，sha256 `d00f9c62076855aaedeac8b1c9a4774317175c3e01d23969f963819842d6b622`（**作废**：
  真机部署时发现它仍固定 8080/8000、不会自动避让，见下节）；
  末次解包复校 939/939 文件通过（`sha256sum -c` exit 0、0 失败）、`config -q` 通过、
  归档内 10 个 `.sh` 与 `tools/` 均为 `0755`、`bash -n` 通过、`.env.example` 已归一为 LF。
  （先前四个版本的 sha256 `a022e1bf…`/`61880f71…`/`3c6a2e7a…`/`ecee8492…` 均已作废并删除，请以本条为准。）

### 真机发现的缺陷与修复（2026-09-20，Ubuntu 22.04 实测）

- **现象**：用户在 Ubuntu 22.04 上 `sudo ./deploy.sh`，执行到加载镜像时报
  `line 48: .../load-images.sh: Permission denied`。
- **根因**：`make_bundle.py` 里的 `chmod(0o755)` 在 **Windows 上只改只读属性**，不存在 POSIX 可执行位；
  随后 `finalize_bundle.py` 调用的 `tar`（bsdtar）把每个条目都写成 **`0666`**，解包后按 umask 变
  `0644`，包内所有脚本都没有执行权限。（校验和只覆盖内容，所以 `sha256sum -c` 曾经一直是通过的，
  这个缺陷逃过了此前所有检查。）
- **修复**：`finalize_bundle.py` **不再调用系统 `tar`**，改用 Python `tarfile`（PAX 格式）逐条写入并
  **显式设置权限**——`*.sh` 与 `tools/` 下文件为 `0755`、目录 `0755`、其余 `0644`，uid/gid 归 0；
  写完后新增 `verify_modes()` 回读归档断言可执行位（本轮输出：`10 .sh entries are executable`）。
  `verify_bundle.py` 也增加了同一项归档权限检查，避免回归。
- **同时加固**：`deploy.sh` 改为用 `bash "${ROOT}/load-images.sh"` 调用子脚本（即使解包丢了可执行位
  也能继续）；README 的探针安装命令改用 `sudo bash probe-offline/install-probe-offline.sh`，
  并在排错表新增「`Permission denied` 指向包内某个 `.sh`」一行（给出 `chmod +x` 与 `sudo bash deploy.sh` 两种做法）。

### 真机发现的第二个缺陷：端口（2026-09-20，Ubuntu 22.04 实测）

- **现象**：可执行位修好后继续部署，`up -d` 报
  `failed to bind host port 0.0.0.0:8080/tcp: address already in use`（compose 项目名取自目录名，
  容器名形如 `dst-toolbox-2140-linux-x86_64-frontend-1`）。
- **根因（两个）**：
  1. **`--port` 在 `.env` 已存在时被静默忽略**——原脚本把端口设置写在 `else`（首次生成 `.env`）
     分支里，重复执行或改目录重试时参数完全不生效，用户会以为「换了端口还是同样的错」。
  2. **API 端口写死**：`docker-compose.yml` 里 backend 是 `"8000:8000"`，宿主机 8000 被占用时无解，
     脚本也没有任何端口预检，只能等 Docker 报错。
- **修复**：
  - `deploy.sh` 新增 `--api-port`，并把端口覆盖逻辑提到 `.env` 分支之外：显式传入的
    `--port` / `--api-port` **无论 `.env` 是否存在都会写入**；未显式传入时才保留 `.env` 原值。
  - `docker-compose.yml` 的 backend 端口改为 `${API_PORT:-8000}:8000`（默认值不变，向后兼容）；
    `.env.example` 增补 `API_PORT=8000`。
  - 新增**端口预检**：仅当本项目尚无容器时执行（避免破坏重复执行的幂等性），用 `ss -ltn` 检测
    `HTTP_PORT`/`API_PORT`，被占用则列出占用进程并 `die`，不再让用户撞 Docker 的报错。
  - README 排错表新增两行（端口占用怎么查/怎么换；换端口仍报占用时先找旧目录的实例）。
- **验证**：从生成的 `deploy.sh` 里抽出函数与 `.env` 逻辑，用真实 bash 跑了 5 个场景——
  ①`.env` 已存在 + `--port 8443 --api-port 8001` → `.env` 变成 `8443/8001`、无重复键、无 CR；
  ②`.env` 已存在且不带参数 → 保持 `8080/8000`、不覆盖管理员口令占位符；
  ③全新部署带参数 → `8443/8001` 且密钥已随机生成；
  ④端口探测（stub `ss`：8080 v4 / 8000 loopback / 9001 v6）→ 8080/8000/9001 判为占用，
  8081 与 80800 判为空闲（无前缀误判）；
  ⑤预检决策：本项目无容器且端口被占 → 输出占用者并 `die`；本项目已有容器 → 跳过预检继续执行。
  另用 `docker compose config` 确认 `API_PORT=8001` 时 backend 的 `published` 为 `8001`、
  `HTTP_PORT=8443` 时 frontend 的 `published` 为 `8443`。
- **验证（均为真实执行）**：①镜像归档导出后回读 `manifest.json`，8 个标签齐全（归档 2689.1 MB）；
  ②`docker compose -f docker-compose.yml -f docker-compose.offline.yml config -q` 通过，8 个服务全部
  解析到包内镜像标签（无 build、无 registry 拉取）；③外层交付包 2.65 GB，解包后 **939/939 文件**
  通过 `sha256sum -c CHECKSUMS.sha256`（GNU coreutils，exit 0、无失败），归档 1102 个条目文件名全部
  是合法 UTF-8、无绝对路径或 `..`（中文文件名不会乱码）；④`deploy.sh` / `undeploy.sh` /
  `load-images.sh` / `install-probe-offline.sh` 与探针包内 `install.sh`/`uninstall.sh` 全部 `bash -n`
  通过；⑤`tools/docker-compose-linux-x86_64` 为 ELF 64-bit LSB x86-64 可执行文件；
  ⑥本机运行栈 `/api/v1/health` 全绿、`openapi.json` 版本 2.14.0、`alembic current` =
  `0017_file_sources (head)`。
- **打包期修掉的两个缺陷**：`install-probe-offline.sh` 的探针版本占位符 `__PROBE_VERSION__` 未被替换
  （现由 `make_bundle.py` 注入）；`CHECKSUMS.sha256` 原先被 Windows 的 `write_text` 写成 CRLF，
  会使 GNU `sha256sum -c` 把行尾 CR 当成文件名（现按字节以 LF 写出）。
- **未做**：目标机（麒麟 / Ubuntu）实际安装未执行——现场需要 Docker Engine 20.10+；浏览器点选验收未自动化。

### Ubuntu 22.04 LTS 适配（2026-09-20，已完成）

- **镜像无需重建**：交付包内是 `linux/amd64` 镜像，与发行版无关，Ubuntu 22.04 直接复用同一套镜像与
  `docker-compose.yml`；相同 compose 文件、相同迁移 head。
- **Compose v1 兼容性（本轮修掉）**：`docker-compose.yml` 没有顶层 `version:` 键（Compose Spec），
  Ubuntu 上 `apt install docker-compose` 装的是 **v1**，会直接解析失败。`deploy.sh` 原先在找不到
  `docker compose` 时会回退到 `docker-compose`（v1），现**已删除该回退**：只接受 v2，缺失时安装随包
  插件，否则报错并说明原因。
- **探针 Python 版本（Ubuntu 默认不满足）**：探针源码 `probe/probe.py` 导入 `tomllib`，**要求 Python 3.11+**，
  而 Ubuntu 22.04 默认是 3.10。已核实 jammy universe 提供 `python3.11` 与 `python3.11-venv`
  （版本 `3.11.0~rc1-1~22.04.1`，amd64 deb 共 8 个：`python3.11`、`-minimal`、`-stdlib`、`-venv`、
  `-dev`、`-full`、`-dbg`、`-nopie`）。`install-probe-offline.sh` 现会按
  `python3.12 → python3.11 → python3.10 → python3` 探测解释器，低于 3.11 直接报错并给出 Ubuntu/麒麟做法，
  新增 `--python <路径>` 与 `--wheels <目录>` 选项（wheel 目录按解释器 cp tag 自动选择）。
- **防火墙**：Ubuntu 用 ufw（`ufw allow 8080/tcp 8000/tcp`）；注意 Docker 自行下发 iptables 规则，
  ufw 默认策略对已发布端口不生效，放行后建议 `ufw status` 复核。包内 README 已按发行版分别给出命令。
- **仅跑平台时不需要主机 Python**：平台组件全在容器内，Ubuntu 上不装 Python 3.11 也能部署；
  Python 3.11 只在“要在该主机上跑探针”时才需要。

### Ubuntu 22.04 真机部署成功，以及第三个缺陷：端口冲突没有自动规避（2026-09-20）

- **真机环境**：用户提供的 Ubuntu 22.04 LTS 主机 `192.168.110.90`（主机名 `user`；Docker Engine 29.2.1 与
  compose 插件 5.0.2 来自 Docker 官方 apt 源，非 snap）。本轮已直接 SSH 上去排障（口令不落库、不打印）。
- **现象**：`docker compose up` 报 `failed to bind host port 0.0.0.0:8080/tcp: address already in use`，
  随后 `Bind for 0.0.0.0:8000 failed: port is already allocated`；`frontend` / `backend` 停在 `Created`，
  先前起来的那次 `backend` 反复重启（`Restarting (1)`）。
- **根因（宿主端口被占）**：8080 被**主机进程 `console-gateway`（pid 1288613）**占用；8000 被**另一个产品的
  容器 `llmsec-protected`**（`0.0.0.0:8000->8000/tcp`）占用；8088 / 8443 / 8002 / 9090 也各有占用。
  本包默认固定 8080 / 8000，于是必然相撞。
- **为什么它看起来像 DNS 故障**：端口绑定失败会让容器的**网络端点**建不起来——容器里
  `python -c "socket.gethostbyname('postgres')"` 报 `Temporary failure in name resolution`、
  `docker inspect` 显示 backend 未挂网络或 IP 为空、`compose ps` 里 backend 不在 `_default` 网络上。
  **根因是端口而不是 DNS**（本轮一度按 DNS 排查，记在这里避免重走）。
- **第二个诱因：用户手上是旧包**。目标机 `deploy.sh` 只有 4737 B、既无 `--api-port` 也无端口预检
  （19:00 那一版），而端口修复 19:25 才进包——**修复从未到达目标机**。为此引入 `deploy_rev`：
  `VERSION` 与 `deploy.sh` 启动日志都会打印（当前 `r2`），README 常见问题要求部署前先核对修订号。
- **本轮修复（`deploy.sh` r2；模板在 `dist-linux-build/make_bundle.py::deploy_sh`）**：
  ① **默认端口被占用时自动改用空闲端口**：管理台依次试 `18080–18120`，API 依次试 `18000–18040`，
  选中的端口写进 `.env`，结尾按实际端口打印访问地址；
  ② **自己占用不算冲突**：`own_port()` 读 `docker compose ps --format '{{.Ports}}'`，重复执行沿用
  `.env` 里已选定的端口，不会每次漂移；
  ③ 显式 `--port` / `--api-port` 时冲突**直接报错并列出占用进程**，不悄悄改端口；
  ④ `up` 失败与健康检查超时都先打印 `ps` 与 `backend` 日志现场再 `die`（此前只给一行警告就继续跑迁移，
  用户看到的是迁移阶段报 `is restarting`，根因被掩盖）。
- **验证（全部真实执行）**：
  ① 从生成的 `deploy.sh` 抽出端口段，在真机 bash 与桩 `ss` / `docker` 上跑 7 个场景——全新且
  8080/8000/18080 被占 → `18081/18000` 并写入 `.env`；`.env=18088/8001` 且全空闲 → 保持；
  自己容器发布 18088/8001 → 保持；显式 `--port 8080` 冲突 → exit 1 且列出占用者；显式 `9999/18005` →
  采用；仅 8080 被占 → `18080` 与 `8000`（两个端口互不影响）；备选端口全被占 → exit 1。
  ①′ **真机端到端复验自动选端口**（同样真实执行）：临时用 `python3 -m http.server 8080` 占住 8080、
  8000 仍被 `llmsec-protected` 占用，在**独立 compose 项目**（`COMPOSE_PROJECT_NAME=dst-autotest`，不触碰
  已部署实例）里删掉 `.env` 跑 `./deploy.sh`：脚本打印「提示：管理台端口 8080 已被占用，自动改用 18080」
  与「API/探针接入端口 8000 已被占用，自动改用 18000」，写入 `.env`，8 个容器全部起到 18080/18000 上，
  `http://127.0.0.1:18080/` 与 `http://127.0.0.1:18000/api/v1/health` 均 200；随后 `down -v` 清掉测试
  容器/网络/卷，恢复原 `.env`，原实例未受影响（10 次连续 curl 18088/8001 全 200）。
  ② 真机端到端：`./deploy.sh --port 18088 --api-port 8001` 成功（后端健康 → 迁移 → seed → 汇总），
  `/api/v1/health` 200、`openapi.json` 2.14.0、`alembic current` = `0017_file_sources (head)`，
  管理台 `http://192.168.110.90:18088` 与 `http://192.168.110.90:8001/docs` 均 200。
  ③ 幂等重跑 `./deploy.sh`（不带参数）exit 0、端口保持 18088/8001、8 个容器全部 Running/Healthy 未重建。
  ④ 目标机解包后 `sha256sum -c CHECKSUMS.sha256` 939/939 通过。
- **过程中确认的两点事实**：包内生成的 `.sh`、`VERSION`、`README-离线部署.md` 都是**合法 UTF-8**
  （SSH 输出里看到的乱码是 Windows 侧控制台按 GBK 解码所致，不是包的问题）；`deploy.sh > 文件` 才能拿到
  完整输出，`./deploy.sh | tail` 会因 SIGPIPE 打断部署并留下半启动状态。
- **交付物**：已按 r2 重新出包。`deploy.sh` 自身 sha256 =
  `25e0e3dcef9cb618d6e05b75f822e8de9c67836327decfb4269765f45c0d2cc5`；最终交付物
  `dst-toolbox-2.14.0-linux-x86_64.tar.gz` = 2 848 039 111 字节（2.65 GB），sha256
  `e42e7c84f7083a2cecba37b95cf91c310e099907f1b6c54d4f23748358af1ee3`。`verify_bundle.py` 端到端复校 PASS
  （939/939 校验和、0 个非法 UTF-8 名、0 个缺可执行位、8 个镜像标签齐全、归档内 10 个 `.sh` 为 `0755`），
  目标机解包后 `sha256sum -c CHECKSUMS.sha256` 939/939 亦通过。旧指纹 `d00f9c62…`、`a022e1bf…`、
  `61880f71…`、`3c6a2e7a…`、`ecee8492…` 全部作废，请以本条为准。
