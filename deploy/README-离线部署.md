# 数据安全工具箱 v3.0.0 · arm64 离线部署

平台 **3.0.0** ／ 探针 **3.7.0** ／ 镜像架构 **arm64(linux)**。
目标机 `uname -m` 必须是 `aarch64`。整包**不需要外网，也不需要目标机装 Python/Node/编译器等任何本地环境**
（镜像、探针运行时、前端依赖都在包里）。

## 一、最快路径（一条命令）

```bash
tar -xzf dst-toolbox-3.0.0-linux-arm64.tar.gz
cd dst-toolbox-3.0.0-linux-arm64
sudo ./deploy.sh
```

`deploy.sh` 会依次完成：环境自检（docker / compose v2 / 架构）→ 载入镜像 →
按 `deploy.conf` 生成 `.env`（口令自动生成一次并沿用）→ 修好数据目录权限 → 端口预检 →
`docker compose up -d --no-build --pull never` → 等待 backend 健康 → 打印访问地址与管理员口令。

常用变体：

```bash
./deploy.sh --dry-run                       # 只看会写入的 .env 和参数，不动系统
./deploy.sh --http-port 8443 --api-port 8001  # 换端口
./deploy.sh --backend-url http://192.168.1.20:8000   # 指定探针回连地址
./deploy.sh --force                         # 重新生成 .env 里的 auto 口令（慎用）
sudo ./undeploy.sh                          # 停栈，数据保留
```

## 二、全部参数都在 `deploy.conf`

`deploy.conf` 是**唯一配置入口**（根目录 `.env` 是它的生成物，不要手改 `.env`）。
每一项都有中文注释，按段落分组：部署位置、端口、数据库、平台凭据、探针下发、采集与存储、
DLP、通知、威胁情报、主机审计、运行环境、镜像标签。

两条规则：

- 取值 `auto` = **首次生成、以后沿用**（口令/密钥用它可以避免每次部署都换钥）；
  `DEPLOYMENT_SECRET_KEY` 一旦生成**不可更换**，换掉会让已存凭据全部失效。
- 优先级：命令行参数 > `deploy.conf` > 脚本内置默认值。

改完配置重新执行 `sudo ./deploy.sh` 即生效（`auto` 项保持原值，其余按新值写回 `.env`）。

## 三、包内容

| 条目 | 说明 |
| --- | --- |
| `dist-offline/security-toolbox-images.tar` | 6 个 arm64 镜像：`source-backend`、`source-worker`、`source-frontend`、`postgres:16.6-alpine`、`redis:7.4-alpine`、`mher/flower:2.0.1`（worker/beat/deployment-worker 共用 `source-worker`） |
| `dist-offline/data/` | 离线规则 / IOC / CVE / 模型样例 |
| `deploy.sh`、`deploy.conf`、`undeploy.sh` | 一键部署、参数文件、停栈 |
| `docker-compose*.yml` | 生产编排 / 覆盖 / 可选集成组件 / 开发覆盖（挂载源码热重载） |
| `probe_packages/` | 探针 3.7.0 arm64 分发包（自带 CPython 与依赖），compose 挂进 backend 供下发 |
| `data_security_toolbox_manual_testpack/` | 可选手工测试样例数据（只读挂载） |
| `backend/` `frontend/` `probe/` `shared/` `scripts/` `docs/` `.git/` | 同源源码与 git 历史，供在服务器上继续开发 |
| `frontend/node_modules/` | 前端完整依赖，服务器有 Node 时可直接 `npm run dev` |
| `VERSION`、`SHA256SUMS.txt` | 版本与关键制品校验和 |

## 四、上线前确认

| 项 | 说明 |
| --- | --- |
| `DEPLOYMENT_BACKEND_URL` | 必须改成**目标机能访问到**的平台地址；`auto` 会取本机第一个 IP |
| `HTTP_PORT` / `API_PORT` | 控制台 / API 端口；冲突用 `--http-port/--api-port` 覆盖 |
| `DLP_SELF_ENDPOINTS` | 默认自动取 `<HTTP_PORT>,<API_PORT>,5432,6379,5555`；改过端口或平台与别的系统同机时按需调整 |
| `COOKIE_SECURE` | compose 里固定 `false`（HTTP 部署）；上 HTTPS 需改 `docker-compose.yml` |
| `APP_ENV` | 交付环境保持 `production`（此时 `/test/import` 一律拒绝） |

## 五、数据与持久化

`postgres` / `redis` / `backend` 的数据都在宿主机目录 `deploy-data/`（没有匿名卷），
`--force-recreate`、换镜像都不会丢数据，**备份这个目录即可**。
数据库结构随 API 容器启动执行 `alembic upgrade head`，不需要手工迁移。

## 六、在服务器上继续开发

- **后端（完全离线）**：`docker compose -p source -f docker-compose.yml -f docker-compose.dev.yml up -d backend`
  —— 挂载 `backend/{app,alembic,scripts}`，改代码后 uvicorn `--reload` 自动重启。
  注意 dev 覆盖不含 `shared/`，改共享引擎需要重建镜像。
- **前端**：服务器装了 Node 18+ 时 `cd frontend && npm run dev`（依赖已随包）。
- **重建镜像需要外网**（pip/npm 要拉包）：离线环境请用"源码挂载 + 重启"的方式迭代，
  需要新镜像时在有外网的构建机上执行：

  ```bash
  DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target api             -t source-backend:latest .
  DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target analysis-worker -t source-worker:latest  .
  DOCKER_BUILDKIT=0 docker build -t source-frontend:latest ./frontend
  python3 scripts/offline_bundle.py --save        # 重新生成镜像归档
  python3 scripts/make_offline_release.py         # 重新出交付包
  ```

  （`docker compose build` 在本机会因挂起的 buildx 进程卡住，务必用上面的 legacy builder 形式。）

## 七、探针

探针 3.7.0 分发包在 `probe_packages/probe-3.7.0/arm64/`，自带运行时，目标机不需要 Python/tcpdump。

1. **控制台下发**：`探针部署` 页填 SSH 信息，平台推包并安装；
2. **手工安装**（SSH 不通时）：同页"手工安装"给一次性令牌与包下载入口，拷到目标机后
   `sudo bash probe/install.sh`。

安装路径固定：代码 `/opt/data-security-toolbox`、配置 `/etc/data-security-toolbox`、
数据 `/var/lib/data-security-toolbox`，systemd 单元 `data-security-toolbox-probe`。

## 八、排错

| 现象 | 处理 |
| --- | --- |
| `docker load` 报架构不匹配 | 目标机不是 aarch64，换匹配架构的包 |
| 端口被占用 | `ss -ltnp \| grep :8080` 看占用者，再 `./deploy.sh --http-port ... --api-port ...` |
| backend 反复重启，日志 `PermissionError: '/app/data/storage'` | `deploy-data/backend` 没授权给容器用户 10001（docker 建目录时是 root）。重跑 `./deploy.sh` 会自动处理；手工修 `chown -R 10001:10001 deploy-data/backend` |
| 探针一直离线 | 核对 `deploy.conf` 的 `DEPLOYMENT_BACKEND_URL`、目标机到平台 `API_PORT` 的连通性、`PROBE_BOOTSTRAP_TOKEN` |
| 某个容器起不来 | `docker compose -p source -f docker-compose.yml logs --tail=200 <service>` |
| 集成组件显示不可用 | Zeek/Suricata/MISP/Wazuh 是可选 profile，默认不启动，不影响主流程 |
