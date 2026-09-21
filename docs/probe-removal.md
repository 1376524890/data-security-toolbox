# 探针卸载（从目标主机回收探针）

平台可以把探针从目标主机上完整回收：停止服务、删除 systemd 单元、删除探针在主机上产生的全部生产文件，并在成功后删除平台记录。卸载与下发共用同一条 SSH 通道、同一套凭据加密、事件日志和状态机，所以控制台能看到实时进度，以及「到底删了什么」的审计结果。

## 控制台操作

「探针管理 → 删除」默认勾选**卸载主机探针**：填写目标主机、SSH 端口、用户名和密码（或私钥）后，平台先清理主机，成功后再删除平台记录。取消勾选则只删除平台记录，主机上的文件全部保留 —— 探针会再次注册。

「探针部署」页把每次安装和卸载都列为一条记录，用「动作」列区分；点开卸载记录的详情可以看到：

- 已删除 / 本就不存在 / 按选项保留 / 未能删除 的路径清单
- 释放的空间与文件数
- 退出码、失败原因，以及卸载前后探针的在线状态

## 卸载选项

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| 保留采集数据 | 否 | 保留 `/var/lib/data-security-toolbox`（采集分段、规则与扫描缓存） |
| 保留 dstprobe 账号 | 否 | 强制保留系统账号 |
| 强制删除 dstprobe 账号 | 否 | 即使账号并非本探针创建也删除 |
| 同时删除平台记录 | 一键删除时为是 | 主机清理成功后才删除平台探针记录 |

默认行为是最严格的一种：删除安装器创建的一切，但 `dstprobe` 系统账号只在安装器留下的 `.created-user` 标记证明该账号由本探针创建时才删除，避免误删共用账号。卸载前脚本会一次性读出全部标记，因此删除应用目录不会影响这些判断。

## 目标主机上被删除的路径

卸载脚本 `probe/uninstall.sh` 使用固定白名单，删除目标**不来自命令行参数，也不来自目标机上的文件**：它以 root 运行，从可变文件读取删除目标等于一个提权原语。

| 路径 | 内容 |
| --- | --- |
| `/etc/systemd/system/data-security-toolbox-probe.service` | systemd 单元 |
| `/var/lib/data-security-toolbox/spool` | 采集分段（生产数据，占空间最大，单独统计） |
| `/var/lib/data-security-toolbox/rules`、`cache` | 规则集与扫描缓存 |
| `/var/lib/data-security-toolbox` | 数据目录根 |
| `/usr/local/bin/dumpcap`、`/usr/local/bin/tcpdump` | 仅当安装器写下的标记证明是探针自带并安装的；标记指向其他路径时只报告、不删除 |
| `/opt/data-security-toolbox/runtime`、`probe`、`shared`、`venv` | 自带运行时（解释器/依赖/抓包工具）与运行时代码；`venv` 仅为 3.6.0 及更早版本的遗留 |
| `/etc/data-security-toolbox` | `probe.toml`、`probe.token`、`ca.pem` |
| `/opt/data-security-toolbox` | 应用目录（含安装标记） |
| `dstprobe` 用户 | 仅在证明由本探针创建，或被 `--remove-user` 强制指定，且没有进程仍属该账号时 |

符号链接只删除链接本身，不跟随进入其他目录；非绝对路径、根路径和过短路径一律拒绝执行。服务在删除文件前先 `stop`、`disable`、`reset-failed`，并清理仍在运行的探针进程，避免它在删除过程中继续写回 spool。

## 命令行（主机本地 / 离线）

安装时 `install.sh` 会把卸载脚本复制一份到 `/opt/data-security-toolbox/uninstall.sh`，也可以直接从探针包内运行：

```bash
sudo bash uninstall.sh --dry-run      # 只报告将删除什么，不改动磁盘
sudo bash uninstall.sh                # 完整卸载
sudo bash uninstall.sh --keep-data    # 保留采集数据
sudo bash uninstall.sh --keep-user    # 保留 dstprobe 账号
sudo bash uninstall.sh --remove-user  # 强制删除 dstprobe 账号
```

脚本以 root 运行、幂等（重复执行仍然返回 0），并总是以一行机器可读的汇总结束：

```
DST_UNINSTALL {"ok":true,"dry_run":0,"removed":["systemd-unit","spool","probe-dir","config-dir"],"absent":["venv"],"kept":[],"failed":[],"bytes_freed":41021,"files_freed":19}
```

退出码：`0` 全部成功；`1` 非 root 或参数错误；`2` 有路径未能删除（`failed` 非空）。

## API

```bash
# 一键：清理主机成功后删除平台记录
curl -X DELETE -b /tmp/cookie.txt http://<平台>:8000/api/v1/probes/<probe_id> \
  -H 'Content-Type: application/json' \
  -d '{"remove_remote":true,"auth_type":"password","password":"<SSH密码>","keep_data":false}'

# 只删除平台记录（主机不做任何改动）
curl -X DELETE -b /tmp/cookie.txt http://<平台>:8000/api/v1/probes/<probe_id>

# 独立卸载任务（默认保留平台记录，可用 probe_id 关联）
curl -X POST -b /tmp/cookie.txt http://<平台>:8000/api/v1/probe-deployments/removal \
  -H 'Content-Type: application/json' \
  -d '{"host":"10.0.0.5","port":22,"username":"root","auth_type":"password","password":"<SSH密码>",
       "probe_id":3,"keep_data":false,"keep_user":false,"remove_user":false,
       "delete_record":false,"idempotency_key":"<唯一值>"}'
```

卸载任务与安装任务共用队列和任务名，由记录的 `action` 字段区分（`install` / `uninstall`），进度与事件通过 `GET /api/v1/probe-deployments/{id}/events` 轮询。`idempotency_key` 相同的请求返回同一条记录，不会开启第二条 SSH 会话；同一主机存在未结束的记录时请求返回 409。

## 状态与语义

| 状态 | 含义 |
| --- | --- |
| `REMOVING` | SSH 已连接，正在执行卸载脚本 |
| `REMOVED` | 脚本报告成功且退出码为 0，文件已从主机删除 |
| `FAILED` + `REMOVAL_PARTIAL` | 有路径未能删除，`error_message` 与 `result` 列出残留项；脚本幂等，重新发起一次卸载即可重试 |
| `FAILED` + `REMOVAL_FAILED` | 脚本没有输出汇总行（bash 中止、sudo 拒绝、连接中断），主机状态未知，平台不做任何断言 |

其他语义：

- 卸载成功后平台立即作废该探针的 token（`token`/`token_hash` 清空、状态置 `offline`）：文件已经删除，凭据不应再有效。
- 记录只在勾选「同时删除平台记录」且清理成功时删除；若记录仍被未完成任务占用，记录会保留并在事件里说明，此时主机已经清理完毕。
- 记录删除是历史清理（`DELETE /api/v1/probe-deployments/{id}`），永远不会改动目标主机；只有未结束的记录不能删除。
- 卸载凭据只用于本次任务，任务结束（含失败）后立即销毁，平台不留存明文或可再次使用的凭据。

## 覆盖「安装失败」的主机

卸载不依赖目标机上存在任何探针文件，只需要一条 SSH 连接和一个 shell，因此同样适用于安装失败的主机（预检不通过、安装中断、等待注册超时）：这类主机上往往已经留下一个正在运行的服务，正是最需要回收的对象。

## 升级

新增迁移 `0014_probe_removal`（`probe_deployments.action`、`probe_deployments.removal_options` 及索引，可重复执行且有 downgrade），探针包版本 3.5.0（新增 `uninstall.sh`，`install.sh` 写入 `.created-user` / `.installed-capture-tool` 标记）。重建 backend、worker、beat、deployment-worker、frontend 镜像并重启后迁移自动执行。用旧版本探针包部署的主机由新版卸载脚本清理：目录布局未变，未命中的路径计为 `absent`。
