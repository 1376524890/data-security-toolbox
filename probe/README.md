# Probe Agent

单进程低资源采集端，负责采集系统信息、文件、端口服务和可选 PCAP，并上传到后端。

```bash
pip install -r requirements.txt
python probe.py --base http://backend:8000 --name server-01 --paths /data --capture
```

