# 数据安全工具箱 — 端到端实测报告

> 日期：2026-09-04
> 分支：`develop`
> 环境：单机 Docker Compose（PostgreSQL / Redis / Celery / FastAPI / Vue3）+ 宿主机探针（loopback 仿真受监控主机）

## 1. 测试结论

| 维度 | 结论 |
|------|------|
| 系统部署 | 通过：docker 栈全部 healthy，backend ok，worker ready |
| 分析引擎 | tshark 4.4.18 / zeek 8.2.2 / suricata 7.0.10 全部可用 |
| 探针注册与持久化 | 注册成功、身份持久化、重启不轮换 token |
| 实时捕获与上传 | 探针在 lo 上真实抓包、分片、上传、spool 归零 |
| 攻击行为检测 | 实时分片检出 NETWORK_PORT_SCAN、PROTO_HTTP_UA_001 |
| 敏感数据检测 | 目标文件上传后检出 DATA_SECRET_001(Critical)、DATA_PII_001、DATA_YARA_001 |
| 弱口令/弱认证检测 | 资产分析检出 ASSET_DB_WEAK_AUTH_001 |
| 前端对齐 | packet-detail / stream-follow / live / flows / protocols / sensitive / rules / incident-trend / probe-metrics 全部可用 |
| 前端构建 | vue-tsc --noEmit 通过，vite build 通过 |

**核心链路真实可用，无 mock。** 检测结果均来自真实 tshark 解析、规则解释器、正则/熵/YARA 与资产引擎。

## 2. 部署与拓扑

```
Security Platform  127.0.0.1:8080(前端) / :8000(API)
  FastAPI + Celery(2 worker) + PostgreSQL + Redis
  tshark / zeek / suricata / nmap
Monitored Host (仿真)  probe 采集接口 = lo（loopback）
  目标服务：http.server :8090、redis 弱认证 :16379
  目标文件：/tmp/dst-target-files（敏感 CSV/SQL/JSON/密钥/eicar）
Attack Client (仿真)  本机 nmap / curl
```

### 部署步骤（实测通过）
1. cp .env.example .env 并填强口令。
2. docker compose build（backend api + analysis-worker + beat + frontend）。
3. docker compose up -d；backend 启动时 alembic upgrade head 自动建表。
4. docker compose exec backend python scripts/seed.py。
5. 探针：sudo python3 probe/probe.py --config /etc/data-security-toolbox/probe.toml。

## 3. 探针测试

### 3.1 注册与持久化
- 探针以 hostname 注册，返回 probe_id + token，写入 /etc/data-security-toolbox/probe.identity.json(0600)。
- 重启后读取身份文件，probe_id 不变、token 不轮换（ProbeIdentity.exists() 短路）。

### 3.2 实时捕获与上传
- 捕获：dumpcap(优先) / tcpdump(回退) 分片 .pcapng 原子改名 + manifest。
- 上传：/api/v1/pcaps/upload（X-Probe-ID/X-Probe-Token），spool 归零。
- 实测：探针在 lo 上持续抓包，后端累计 184 个实时分片并全部分析。

### 3.3 目标文件采集 + 敏感检测
- 探针 file_loop 将目标文件内容上传至 /api/v1/files/upload，后端 metadata_task 跑 data_engine。
- 实测检出：DATA_SECRET_001(Critical)×18、DATA_PII_001(High)×14、DATA_YARA_001×16。
- 样本已脱敏，密钥不展示。

### 3.4 资产/弱口令
- 探针 asset_loop 上报开放端口 + banner；后端 asset_task 走 asset_engine。
- 实测：带 noauth / Authentication not required banner 的 redis/mysql 命中 ASSET_DB_WEAK_AUTH_001(High)。

## 4. 攻击行为模拟与检测结果

| 场景 | 动作 | 检测结果 | 状态 |
|------|------|----------|------|
| 端口扫描 | nmap -sT -Pn -p 1-200 127.0.0.1 | NETWORK_PORT_SCAN(High)、NET_SCAN_001(High) | 通过 |
| 可疑 UA | curl -A sqlmap/1.7.2 到目标 | PROTO_HTTP_UA_001(Medium) | 通过 |
| 可疑 UA | curl -A DST-E2E-TEST-2026 sqlmap-test | PROTO_HTTP_UA_001(Medium) | 通过 |
| 弱口令 Redis/MySQL | banner 含 noauth | ASSET_DB_WEAK_AUTH_001(High) | 通过 |
| 敏感文件泄露 | 上传含身份证/手机号/银行卡/密钥/病历文件 | DATA_SECRET_001 / DATA_PII_001 | 通过 |
| 恶意文件 | eicar / 伪装图片 | DATA_YARA_001 | 通过 |
| C2 周期心跳 | 周期 curl | NET_C2_BEACON_001（需 >=10 包且周期稳定；仿真未稳定触发） | 边界 |

## 5. 前端对齐（后端补齐后全部可用）

| 端点 | 说明 | 实测 |
|------|------|------|
| GET /pcaps/{id}/packets/{pid} | 原始字节 + 协议树 | raw=108B，4 层（Frame/Ethernet/IPv4/TCP） |
| GET /pcaps/{id}/streams/{sid} | TCP 流 ASCII+Hex 跟踪 | 节点/方向解析 |
| GET /flows | 全局会话流 | 2509 条 |
| GET /protocols | 全局协议分布 | TCP/HTTP/JSON/RESP/TLSv1.2/MySQL |
| GET /network/live | 实时指标 | 探针心跳驱动 |
| GET /sensitive/findings | 敏感类目聚合 | yara/secret/pii |
| GET /dashboard/incident-trend | 事件趋势 | 可用 |
| GET /rules | Sigma/YARA/Suricata 规则 | 11 条 |
| GET /probes/{id}/metrics | 探针指标 | 可用 |
| GET /alerts/{id} | 关联 assets/iocs/data_assets | 可用 |
| GET /assets/{id} | 漏洞列表 | 可用 |
| GET /health | 各引擎规则数 | 可用 |
| GET /integrations | Sigma 引擎状态 | 可用 |
| Task worker / ATT&CK 字段 | 检测/任务序列化 | 可用 |

## 6. 修复的关键问题

| # | 问题 | 修复 |
|---|------|------|
| 1 | alembic 迁移非幂等：0001 create_all + 0005/0006 显式 create_table 新库 DuplicateTable | 存在即跳过（_create_table_if_missing / _create_index_if_missing；0006 唯一索引改为检查） |
| 2 | zeek/zeek:5.0.0 拉取 401 | 改用 zeek/zeek:latest，并 COPY Debian trixie 共享库（libnode/ICU 等） |
| 3 | 后端(api)容器无 tshark，packet-detail/stream-follow 空/500 | base 阶段安装 tshark |
| 4 | 探针 capture_once 把 capture_command 三元组当命令传给 Popen，捕获从未运行 | 解包 tool, ext, command |
| 5 | Presidio 首次调用下载 spaCy 模型（400MB+）阻塞 worker | 新增 PRESIDIO_ENABLED 开关，默认 true，测试关闭 |
| 6 | set_admin_cookie 强制生产模式 Secure 导致 HTTP 登录失效 | 以 cookie_secure 为唯一开关 |
| 7 | 后端 :8000 未暴露，探针无法访问 | compose 暴露 8000:8000 |
| 8 | 探针多循环心跳互相覆盖 probe.extra | 已定位（见 7.1 遗留） |

## 7. 遗留问题 / 边界

### 7.1 探针 heartbeat 覆盖
heartbeat_loop / asset_loop / file_loop 各自把不同 metadata 写入 probe.extra，后者覆盖前者，导致 /probes/{id}/metrics 的 capture_tool/cpu 有时为空、services/file_inventory 丢失。建议后端 heartbeat 改为合并 metadata 而非整体替换。

### 7.2 HTTPS 解密
未实现 TLS 解密（无 SSLKEYLOGFILE/密钥日志）。仅采集 TLS 握手元数据（SNI/cipher/JA3）。HTTPS 通道内的 C2/外传不可见。

### 7.3 MD5
探针仅计算 SHA256，未生成 MD5（file_records 已带 md5 字段，后端 FileRecord 未存 md5）。

### 7.4 队列背压
探针在高流量接口（如 lo）上捕获会产生大量分片，触发后端 429 背压（QUEUE_PENDING_MAX / QUEUE_OLDEST_PENDING_SECONDS）。设计上正确，但需按目标主机实际流量调整参数。

### 7.5 探针降权写目录
探针以 root 运行时 dumpcap 会降权，spool 目录需为世界可写（或由运行用户拥有）。生产用 dstprobe 用户 + CAP_NET_RAW 时由用户属主解决。

## 8. 指标（本次实测）

- 检测链路：攻击到告警在正常流量下秒级；大分片受 tshark/zeek/suricata 串行影响。
- 探针 RSS：<100MB（低流量）。
- 队列：排空后 pending=0, running=0，无卡死任务。
- 无告警风暴：正常 loopback 流量下未见大量误报告警（背压生效）。

## 9. 复现方法

```bash
# 平台
cd /home/gb/work/0901-工具箱开发
cp .env.example .env  # 填强口令
docker compose build && docker compose up -d
docker compose exec backend python scripts/seed.py

# 探针（受监控主机）
sudo mkdir -p /etc/data-security-toolbox
sudo tee /etc/data-security-toolbox/probe.toml <<'CFG'
[server] url="http://<平台IP>:8000" verify_tls=false
[capture] interface="lo" segment_seconds=10 segment_max_mb=64
[spool] path="/var/lib/data-security-toolbox/spool" max_mb=2048
[agent] bootstrap_token="<token>" identity_path="/etc/data-security-toolbox/probe.identity.json"
  ports=[22,80,443,8080,6379,3306] paths=["/tmp/dst-target-files"] file_interval_seconds=15
CFG
sudo python3 /home/gb/miniconda3/bin/python3 probe/probe.py --config /etc/data-security-toolbox/probe.toml

# 攻击仿真
nmap -sT -Pn -p 1-200 127.0.0.1
curl -A "sqlmap/1.7.2" http://127.0.0.1:8090/test.csv
```
