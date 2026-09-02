# 测试

后端：

```bash
cd backend
python -m pytest -q
```

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
