# Probe 服务端下发部署：可行性检查与修订方案

检查日期：2026-09-15。范围：当前 source 项目源码与配置的只读审查。

## 1. 结论

Deployment Plane 架构可行，FastAPI、SQLAlchemy/Alembic、Celery、Vue 和现有 Probe 能承接此能力。但原方案不能不经调整直接实现：安装包不完整、安装脚本立即启动服务、注册鉴权不是一次性、注册与首次心跳未区分，HTTPS 回连与提权前提也未定义。

本次只新增本文档；未实现部署模块、未修改业务代码、未执行数据库 migration、未连接或安装任何目标主机。以下均为待实现设计，不能视为已通过部署验收。

“仅输入 IP、端口、用户名、密码”可作为日常操作目标，但必须先由平台管理员配置可信 HTTPS 回连地址、CA、安装包、SSH 主机信任策略与可部署网络。目标账户必须具备受支持的提权方式。

## 2. 源码证据与不兼容点

| 位置 | 当前行为 | 必要调整 |
|---|---|---|
| `probe/install.sh` | 要求 root；复制 probe.py、scanner.py、requirements.txt；不安装依赖；立即 enable/restart | 包含 scanner.py；提供依赖准备；增加仅安装不启动选项，先原子写配置再启动 |
| `probe/probe.py` | 导入 tomllib、datetime.UTC；AGENT_VERSION=3.2.0 | 现有源码要求 Python 3.11+；包版本从源码生成，不能标成 3.0.0 |
| `probe/probe.py`、`probe/requirements.txt` | psutil 可选导入；requirements 包含 psutil/requests | 缺依赖可能降级而非正常提供资源指标；确定 venv 与双架构依赖安装方案 |
| `probe/probe.toml.example` | 默认 eth0；存在 capture.enabled、paths、file_interval_seconds | 自动检测并展示网卡，文件扫描需明确可读目录；不能只生成 server/agent 两段 |
| `backend/app/schemas.py` | ProbeRegister 要求 name，使用 ip_address，无 deployment_id | 保留 name/hostname/ip_address/metadata，新增可选 deployment_id；原请求 hostname/ip 无法直接替换 |
| `backend/app/api/v1.py` register | 生产模式校验全局 bootstrap token；按 name 查找并可能轮换身份；设置 online 和 last_seen | 独立的一次性 enrollment 校验；同名主机不能覆盖；注册不等于健康上线 |
| 同文件 heartbeat | 验证 Probe token，合并指标，更新 last_seen | 首次真实 heartbeat 推进部署终态；避免仅注册即 ONLINE |
| `probe/probe.py` register | 已有身份直接复用；name 来自 hostname | 部署名与 hostname 分离；透传部署 ID；处理目标已有身份，禁止静默覆盖 |
| `backend/app/workers/celery_app.py` | 仅 include app.workers.tasks | 新增任务模块注册、deployment 队列及专用 Worker |
| `backend/app/core/security.py`、`main.py` | 部分 helper 开发环境绕过鉴权；全局中间件主要检查登录，helper 可接受 operator | 部署 API 在所有环境强制 active admin，不依赖现有宽松 helper |
| `frontend/nginx.conf`、`docker-compose.yml` | 项目内 nginx 监听 HTTP；未定义目标可达 HTTPS 部署地址 | 明确 TLS 入口及 CA；外部可能已有 TLS 代理，本次不能由仓库判断 |
| requirements、models、router | 无完整 Deployment Manager、SSH/AES-GCM 直接依赖、部署模型/路由 | 新增实现与锁定依赖，不能仅增加一个 Web 表单 |

## 3. 修订后的职责与流程

Frontend → Backend API → Deployment Manager → Celery deployment Worker → SSH/SFTP → 目标安装脚本/systemd。

服务启动后关闭 SSH：Probe → HTTPS register → HTTPS heartbeat → PCAP/spool/upload。后台通过数据库观察回调，不通过 SSH 轮询运行状态；register 是 Probe 发起的 POST，不是 Worker 可以轮询的查询接口。

1. 严格管理员鉴权、输入校验、检查部署地址/包/主机信任配置。
2. 创建 deployment，AES-GCM 加密凭据；事务提交后投递仅包含 deployment_id 的任务。
3. Worker 获取任务租约，连接 SSH，校验 host key；检查 root 或 sudo -n 权限。
4. preflight 检查 OS、架构、Python、systemd 实际运行状态、依赖、资源、网卡、目标到后端 HTTPS 的 DNS/TCP/TLS/HTTP 连通性。
5. 选择包并验证可信摘要；创建每任务随机临时目录，通过 SFTP 上传，再在目标校验 SHA256。
6. 安装文件/依赖及 systemd，暂不启动；创建绑定 deployment 的一次性 enrollment，生成完整 TOML 与 CA，原子安装，设置最小权限。
7. 先持久化 WAIT_CALLBACK/回调截止时间，再执行固定的 systemctl 启动操作，防止快速回调被后续状态覆盖。STARTING 进度由事件表示。
8. 清理目标临时包和配置副本，关闭 SSH，销毁服务端 SSH 凭据；失败也执行 finally 清理，不保留用于无限重试。
9. register 原子消费 enrollment 并绑定 probe_id；首次持久化身份之后的有效 heartbeat 才达到 ONLINE。
10. 定时轻量任务检查回调超时与失联 Worker，不用长时间占据 Celery 执行槽。展示历史部署结果及当前 Probe 在线状态，两者分开。

标准支持 root 或已有免密 sudo 的受限部署账户。普通 SSH 密码不必然等于 sudo 密码；若需密码 sudo，必须另外设计加密 sudo_secret 与 stdin 传递，不能默认为可用。禁止密码放入命令参数。

## 4. 状态与数据模型 / migration 设计

主流程保留 CREATED、CONNECTING、PREFLIGHT、UPLOADING、INSTALLING、STARTING、WAIT_CALLBACK、ONLINE。

保留失败状态 CONNECT_FAILED、AUTH_FAILED、PREFLIGHT_FAILED、INSTALL_FAILED、CALLBACK_TIMEOUT；安装后启动失败归 INSTALL_FAILED 并提供明确 error_code。额外建议 PACKAGE_FAILED、DISPATCH_FAILED、CANCELLED；若暂不扩枚举，需在已有状态中保留细分错误码。

ONLINE 的条件：enrollment 已消费、probe_id 已绑定、首次身份认证 heartbeat 已到达、上报版本符合安装包、没有 auth_error。Standard/Sensor 还要通过实际采集状态与测试分段上传验收；Lite 的 capture=disabled 为正常。不要把 initial capture_status=online 视为成功采集证据。

拟新增 `0008_probe_deployments.py`，down_revision=`0007_file_md5`（根据当前源码迁移链；实施前再核对运行数据库 head）。

- ProbeDeployment：保留请求列出的全部字段，另加 profile、package_version/digest、created_by、task_id、progress、current_stage、error_code、updated_at、callback_deadline、registered_at、first_heartbeat_at、credential_destroyed_at、lease/version、idempotency_key。probe_id 外键 SET NULL，保留历史。
- ProbeDeploymentCredential：deployment_id 唯一外键、encrypted_secret（二进制密文含 tag）、nonce、key_id、expires_at。secret 包含 password 或 private_key 与可选 passphrase；不将凭据写入 deployment JSON。
- ProbeEnrollment：deployment_id、token_hash 唯一、expires_at、consumed_at、probe_id；用事务/条件更新保证一次性消费，禁止仅根据客户端 deployment_id 绑定。
- 建议 ProbeDeploymentEvent：deployment_id、递增序号、stage、脱敏 message、created_at，用游标分页代替无限追加 deployment_log；deployment_log 可保留受限摘要。
- 唯一幂等键和每主机活动部署锁，避免 Celery 重复投递重复安装；阶段更新使用 CAS/租约，终态不被迟到 Worker 覆盖。
- upgrade 创建表/索引/外键；downgrade 先删除依赖表，不删 probes。迁移测试覆盖空库和现有数据库。

## 5. 凭据、注册与 SSH 安全契约

AES-GCM 使用独立的 256-bit 部署密钥，通过 secret 挂载注入 API 与 deployment Worker；不与数据库同存，不直接复用登录 SECRET_KEY。每次加密使用唯一 nonce，以 deployment_id/auth_type/key_id 为 AAD，支持 key_id 轮换。

API 请求体、Pydantic 校验错误、SSH 异常、Celery 参数/结果、日志均不能输出 password/private_key/passphrase/bootstrap token。现有浅层 redact 不足，部署模块使用白名单事件结构与受限输出。前端提交后清空凭据，禁止 localStorage 保存。

成功、失败、取消、超时均删除凭据行；定时任务兜底清理过期凭据。删除数据库行不等于物理擦除历史备份/WAL，需配合短保留策略与密钥生命周期，不能承诺无法保证的物理销毁。

预检查请求不持久化凭据。完整部署独立重新检查，不能信任浏览器回传的 compatible=true。

一次性 token 随机生成、只存 hash、短时有效、绑定 deployment。首次 register 和消费在同一事务；保留旧手工 bootstrap 路径，但有 deployment_id 的请求必须走新校验，失败不能回退旧 token。

注册响应丢失必须有明确处理：最小实现拒绝 token 重放并显示需要重新部署/重新授权，不能再次消费创建第二个 Probe。若要自动恢复，需要另行设计客户端身份公钥或安全幂等响应机制，不能让一次性 token 无限换取身份。注册成功后 Probe 清理本地 bootstrap 字段，保留现有 identity 文件用于后续运行。

SSH host key 通过预置 known_hosts 或管理员明确登记指纹校验，禁止 AutoAddPolicy 默认盲信。IP/端口严格类型检查，目标网络限制由平台配置。SFTP 路径由服务端生成，不使用共享固定 /tmp 文件名，防止并发覆盖与链接攻击。

SSH command 只允许枚举操作和固定脚本模板：探测、创建临时目录、校验、安装、启动、清理。用户不能传入 shell 片段；动态路径与参数强类型验证并正确引用，密钥/密码走内存与 stdin。压缩包拒绝绝对路径、.. 和逃逸链接；SHA256 对照来自可信发布目录，不能只信包内自带 manifest。

## 6. 包与环境检查

建议目录：`source/probe_packages/probe-<源码版本>/<amd64|arm64>/`，包内包含 install.sh、probe.py、scanner.py、requirements.txt、systemd 模板及依赖清单/所需 wheels。Python 源码可共用，但 psutil 等依赖需匹配架构、Python ABI 与目标系统。

归档旁放 manifest.json：version、arch、python_min、supported_os、artifact、sha256、文件清单。sha256 指归档摘要，manifest 不在自身摘要内循环引用。服务端上传前和目标执行前双重校验，版本必须和 AGENT_VERSION 一致。

首次支持 Linux/systemd、amd64/arm64、Python>=3.11 的明确发行版矩阵；旧 Python 返回 PREFLIGHT_FAILED，不自动执行未经设计的系统升级。依赖使用 venv 或受支持的系统依赖方案，与 systemd ExecStart 保持一致。离线目标需完整依赖包。

preflight 返回 compatible、checks[]（actual/required/pass/reason）、os、arch、python、cpu、memory、disk、capture_tool、interfaces、backend_connectivity、sudo、capability_score、recommended_profile、estimated_spool_time。

资源分数是版本化启发式建议，不是性能保证。可先设置明确的最低门槛并经实机压测校准。spool 时间=可用 spool 字节/假设或测得捕获字节每秒；没有流量速率时返回 null 和估算前提，不能仅凭 8GB 内存推算 2h。Network 检查只访问平台配置的回连地址。

## 7. Profile 与现有配置映射

| Profile | 配置与限制 |
|---|---|
| Lite | capture.enabled=false；heartbeat/asset inventory 开启；当前 file_loop 会上传文件正文，若要求“仅 metadata”，需新增仅元数据模式，不可假称已经支持 |
| Standard | capture.enabled=true；有界分段/spool；file_interval_seconds>0 且配置获授权的可读 paths |
| Sensor | capture.enabled=true；持续采集；配置采集网卡、spool/速率/磁盘上限与 systemd 资源限制；默认不扫描任意文件目录 |

当前 Standard 和 Sensor 都复用同一个连续分段 capture_loop。若要 Standard 只按需/周期采集，需要额外调度开关；仅改变 profile 标签不会产生不同运行模式。systemd ProtectHome/ProtectSystem 和 dstprobe 权限限制扫描路径，不应为文件扫描直接关闭全部保护。

## 8. API 与前端建议

- `POST /api/v1/probe-deployments/preflight`：host、port、username、auth_type、password 或 private_key、可选 key_passphrase、profile。凭据互斥验证；短超时同步检查，耗时检查可升级为异步任务；不保存秘密。
- `POST /api/v1/probe-deployments`：以上字段加 name、idempotency_key；202 返回 deployment_id/status。backend_url 取平台配置，不接受任意命令或安装 URL。
- `GET /api/v1/probe-deployments`：分页历史（原方案遗漏，历史页面必须补充）。
- `GET /api/v1/probe-deployments/{id}`：status/progress/current_stage/logs/probe_id/error_code/error_message、credential_destroyed、profile、preflight_result、probe 最新运行指标。
- 可选 `GET /{id}/events?after=<seq>`；重试创建新 attempt 并重新提交凭据，不复用已销毁秘密。
- 保留 `/api/v1/probes/register`，添加可选 deployment_id；保留 hostname/ip_address/name/metadata 原字段。heartbeat 继续使用现有 X-Probe-ID/X-Probe-Token。

前端新增 `/probe-deployments` 路由及菜单，复用当前 Operations 页面布局。表单支持 Password/Private Key 两种方式与 key passphrase，展示系统预配的后端回连地址和主机信任结果。

进度显示 SSH、环境、包上传、安装、启动、注册、首次心跳；注册成功只勾注册步骤，不提前勾心跳。历史展示时间、目标、profile、部署结果、Probe ID、错误、凭据销毁状态。完成后链接 ProbeCenter，展示 hostname/IP/version/heartbeat/capture/upload；后续失联由 Probe 状态体现。

## 9. 拟修改文件清单（本次未执行）

- 新增 backend/app/deployment/{service,ssh_client,preflight,package,credential,enrollment}.py 及 __init__.py。
- 新增 backend/app/api/deployments.py、backend/app/workers/deployment_tasks.py。
- 修改 backend/app/{models,schemas,main}.py、api/v1.py、core/config.py、workers/celery_app.py。
- 新增 backend/alembic/versions/0008_probe_deployments.py。
- 修改 backend/requirements.txt 或独立部署依赖锁文件、backend/Dockerfile、docker-compose.yml：独立 deployment Worker/queue、网络连通、密钥和只读包目录挂载。
- 修改 probe/install.sh、probe/probe.py、probe/probe.toml.example、service 模板：安装顺序、依赖、deployment_id、token 清理、必要 profile 能力；复用 capture/spool/upload 核心。
- 新增 probe_packages 发布产物与可重复构建脚本。
- 新增 frontend/src/api/probeDeployments.ts、types/probeDeployment.ts、modules/operations-admin/ProbeDeployment.vue；修改 router/index.ts、router/menu.ts。
- 新增 backend/tests/deployment/、前端相关测试、Linux 实机验收脚本及运维文档。

## 10. 测试报告与实施验收计划

本次已完成源码检查：安装脚本、配置、Probe register/heartbeat、模型/schema、鉴权、Celery 配置、迁移链文件、前端路由与部署配置。

本次未运行新 Deployment API、SSH mock、加密、状态机或端到端测试：这些模块尚未实现。未验证目标主机网络、真实 root/sudo、TLS 证书或 Linux 安装结果，不报告模拟通过。

实施必须增加：

1. API：所有环境 admin-only、密码/私钥互斥、输入边界、日志/响应无凭据、分页、幂等、投递失败。
2. AES-GCM：往返、随机 nonce、错误 key/AAD、篡改拒绝、全部终态及 TTL 销毁。
3. SSH mock：成功、网络失败、密码错误、host key 不匹配、sudo 失败、命令注入、SFTP/命令超时。
4. preflight：Python 过旧、无 systemd/非 PID1、磁盘不足、捕获工具缺失、网卡不存在、HTTPS DNS/TLS/HTTP 失败、两种架构。
5. 包：hash 不匹配、版本/ABI 不匹配、路径穿越与符号链接、并发临时目录隔离。
6. 状态机：重复投递、Worker 崩溃/恢复、回调先于启动任务结束、超时与迟到回调竞争、只有注册没有 heartbeat 不能 ONLINE。
7. enrollment：过期、重放、错误 deployment_id、并发消费、同名主机、已有 identity、注册响应丢失。
8. 集成：SSH→安装→注册→首次心跳→真实分段上传；关闭 SSH 后持续 heartbeat/upload；三种 profile 分别验证。
9. 双架构真实 Linux/systemd 验收：hostname/IP/version/heartbeat/capture/upload 正确，凭据行已删除，服务重启复用身份，重试行为可预测。

完成上述调整后，该目标可以在当前项目增量实现，无需重写 Probe 核心；在这些条件落实前，不应承诺任意 Linux 主机仅凭 SSH 密码即可部署成功。
