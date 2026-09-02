# 测试

后端：

```bash
cd backend
python -m pytest -q
```

当前测试规模：79 个，其中原有 35 个，新增 Integration Adapter 测试 44 个。

新增覆盖：

- Zeek：DNS、TLS、HTTP、files、weird
- Suricata：alert、flow、dns、http、fileinfo、ET Open 规则导入
- Presidio：身份证、手机号、银行卡、医疗数据、Secret
- MISP：IP、Domain、Hash、URL 离线导入与匹配
- Host Audit：osquery、Wazuh 资产/进程/用户/配置/日志
- OpenSCAP：XCCDF/ARF、CIS/等保结果
- Incident Engine：时间、资产、IOC、攻击链关联
- Offline Bundle：规则、IOC、CVE、模型导入

前端：

```bash
cd frontend
npm ci
npm test
npm run build
```

PCAP 解析使用真实 tshark 或 dpkt，测试数据在 `backend/tests/fixtures` 中生成。

Benchmark：

```bash
cd backend
python scripts/benchmark.py
```

覆盖正常流量、扫描流量、C2 流量、敏感数据文件。

在已构建的后端镜像中运行测试：

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/backend:/app" -w /app -e PYTHONPATH=/app \
  security-toolbox-backend pytest -q
```
