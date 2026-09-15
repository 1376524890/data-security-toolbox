# v2.6.0 网络扫描修复与探针数据资产采集

## 版本

- 平台：`2.6.0`（`backend/app/main.py`，接口 `GET /api/v1/health` 中 `service` 版本一致）
- 探针：`3.3.0`（`probe/probe.py` 中 `AGENT_VERSION`，平台侧 `PROBE_AGENT_VERSION`）
- 探针部署包：`probe_packages/probe-3.3.0/{amd64,arm64}/`，含 `probe-3.3.0-<arch>.tar.gz` 与 `manifest.json`（SHA256）
- 数据库迁移：`0009_probe_data_assets`（新增 `probe_deployments.data_config`）

## 变更摘要

### 网络扫描（资产中心）

- 扫描一律使用 `nmap -Pn -sT`：ICMP/ARP 被拦截的主机上 `nmap -sn` 会判定 `0 hosts up` 从而跳过端口扫描，
  之前因此扫不到任何资产。
- 新增零依赖的 Python TCP-connect 扫描引擎（无需 root / `NET_RAW` / nmap），用于存活发现，并在 nmap 缺失、
  被拒绝或返回空结果时自动接管整个扫描。
- 支持显式端口列表、多主机并发、每主机 `--host-timeout` 上限、非标准端口被动 banner 与 HTTP/TLS 指纹识别。
- 扫描路径自检：若保留地址（如 `192.0.2.1`）被应答，说明链路存在透明代理/NAT 拦截，任务结果会带告警，
  提示改用探针扫描。

### 数据资产（探针）

- 探针枚举所在服务器的数据资产：目录遍历、文件身份（大小/类型/摘要）、字段推断（csv / sql / json）、
  敏感类目统计（手机号、身份证、邮箱、银行卡、密钥令牌等）与本机数据库服务登记。
- **仅上传文件名、字段、类目计数与汇总证据，不上传原始数据**。
- 采集方式：平台下发任务 `POST /probes/{id}/data-assets/jobs`，或探针按 `[data] interval_seconds` 定时采集；
  回传 `POST /probes/{id}/data-assets`（按 `probe_id + 名称` 幂等）。
- 平台侧查看：`GET /data/assets?probe_id=<id>`，「数据资产」页可按探针筛选并查看来源探针、主机、路径、
  敏感类目、状态与字段明细。
- 部署表单可配置采集目录、周期、文件上限、目录深度与数据库服务开关，生成的 `probe.toml` 包含：

```toml
[scan]
allow_remote = true
poll_seconds = 30

[data]
enabled = true
interval_seconds = 1800
paths = ["/srv/data"]
max_files = 300
max_depth = 4
include_databases = true
allow_remote = true
poll_seconds = 30
```

## 升级步骤

### 平台

```bash
docker compose build backend worker beat deployment-worker frontend
docker compose up -d
docker compose exec backend alembic upgrade head   # 0009_probe_data_assets
```

### 探针

1. 在「探针部署」页重新部署（自动下发 `probe-3.3.0` 包），或手工升级：
   ```bash
   tar -xzf probe-3.3.0-amd64.tar.gz -C /tmp/probe-3.3.0
   sudo bash /tmp/probe-3.3.0/install.sh          # 覆盖 /opt/data-security-toolbox/probe
   sudo systemctl restart data-security-toolbox-probe
   ```
2. 校验 `manifest.json` 中的 `sha256` 与包一致。
3. 3.3.0 以下版本无 `data_assets.py`，`probe.py` 会因 ImportError 启动失败，请勿只替换 `probe.py`。

## 验证要点

- 平台扫描：`POST /api/v1/scan` 指定 `target` 与 `ports`，任务结果应显示 `engine=nmap`（或 `tcp-connect` 兜底）、
  `alive_hosts`、`assets` 与 `scanned_assets` 明细。
- 探针扫描：`POST /api/v1/probes/{id}/scan-jobs`，任务 `location=probe`、`engine=tcp-connect`。
- 探针数据资产：`POST /api/v1/probes/{id}/data-assets/jobs` 后，`GET /api/v1/data/assets?probe_id={id}` 应返回
  文件/表/数据库条目及敏感类目与字段。

## 注意事项

- 若扫描主机所在链路存在透明代理/NAT 拦截（Docker Desktop、部分云主机网络），平台侧扫描结果不可信，
  会触发拦截告警；此类环境请使用部署在目标网段的探针执行扫描。
- 探针数据资产目录必须是绝对 Linux 路径且不含 `..`，最多 32 条。
