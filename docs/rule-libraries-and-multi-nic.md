# 多网卡与规则库更新

## 探针 3.2.1

- 部署表单的「平台回连地址」可填写平台任一可达网卡的 IPv4、IPv6 或域名；留空沿用 `DEPLOYMENT_BACKEND_URL`。预检与安装使用同一地址。
- 平台 Docker 端口仍绑定所有主机接口。IPv6 地址写作 `http://[IPv6]:8000`，实际连通性取决于网络路由与防火墙。
- Linux 探针默认 `capture.interface = "any"`，覆盖所有网卡及后续新增网卡。可指定 `"eth0,eth1"` 或 `["eth0", "eth1"]`；多选需 dumpcap。
- 注册和心跳上报全部网卡、启用状态和 IPv4/IPv6 地址，探针中心展示。回连由操作系统路由选择源接口，不绑定第一张采集网卡。
- 已安装探针需升级到 3.2.1；原有显式单网卡配置需改为 `any` 后重启。新部署默认全部网卡。部署包提供 amd64 / arm64 两种架构及 SHA256 清单。

## 网络防泄密

- 「现有规则库」展示内置规则、Presidio 规则和手工规则，可逐条启停。
- 「下载 / 更新 Presidio 规则库并导入」从官方 PyPI 发行包下载并校验 SHA256，静态解析规则，不执行下载的 Python 源码。
- 导入范围为可直接解析的正则模式，不包含 NLP、上下文评分或 Python 校验器。原模式分数低于 0.5 的规则默认停用；升级保留已有启停选择。
- 手工添加名称、敏感类别和正则，保存时校验；新分析任务读取最新规则。历史 PCAP 可重新分析。
- 匹配样本脱敏；单规则超时记录在覆盖范围中，不当成命中。旁路模式不解密 HTTPS、不直接阻断。

## CVE 漏洞库

- 支持下载 / 更新官方 Grype DB v6；支持 `.tar.zst`、`.tar.gz`、tar 或原始 SQLite DB 离线导入。
- 在线下载校验官方 SHA256；检查 SQLite schema 与完整性，流式读取，分批写入，数据库事务失败时回滚。
- 按 CVE ID 去重；多来源优先 NVD；计算 CVSS 2 / 3 / 4 向量分数。更新 Grype 来源记录，保留已有手工或其他来源记录。
- 保留原生数据库中的软件包和 CPE 数据。平台列表查询导入的 CVE 目录；这不等于已运行 Grype 软件包版本匹配扫描。
- 提供 CVE 手动添加及 JSON / CSV / YAML 导入；例如：

```json
[{"cve_id":"CVE-2026-12345","severity":"High","cvss_score":8.1,"description":"漏洞说明"}]
```

- 大库操作在后台运行，页面显示下载 / 导入进度，刷新页面后可继续查看。服务进程重启会中断任务，需要重新发起；数据库事务不会留下部分导入，进程锁会自动释放。
- 上传限制 2 GB，解压限制 12 GB；导入期间需要原始包、临时数据库和目录存储空间。

## Suricata / YARA 检查规则

- 检测规则页面提供「添加 / 导入检查规则」，可粘贴规则或选择 `.rules` / `.yar` / `.yara` 文件。
- Suricata 校验每一行、SID 完整性及冲突；运行时可用时执行 `suricata -T`。生产镜像已包含 Suricata。
- YARA 必须通过 yara-python 编译，禁用 include；保存后文件检测引擎读取已导入规则并进行有时限的匹配。

## 数据源

- [Presidio 官方发行包](https://pypi.org/project/presidio-analyzer/)
- [Grype DB 架构与格式](https://oss.anchore.com/docs/architecture/grype-db/)
- [Grype v6 最新版本清单](https://grype.anchore.io/databases/v6/latest.json)
