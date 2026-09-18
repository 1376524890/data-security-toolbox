-- 平台下发的主机审计查询（osqueryi --json 执行）。
-- 每条查询对应一个资产/基线检查项，修改后无需重新构建镜像。

-- 敏感数据文件位置：家目录与临时目录中的可疑文档
SELECT path, size, mtime FROM file WHERE (path LIKE "/home/%/%.docx" OR path LIKE "/home/%/%.xlsx" OR path LIKE "/tmp/%") AND size > 0;

-- 明文凭据文件
SELECT path, size FROM file WHERE path LIKE "/%.env" OR path LIKE "%credentials%" OR path LIKE "%id_rsa%";

-- 对外监听的高风险数据库端口
SELECT p.name, p.pid, l.port, l.address FROM listening_ports l JOIN processes p ON p.pid = l.pid WHERE l.port IN (3306, 5432, 6379, 27017, 9200, 1521, 1433);

-- 磁盘未加密的挂载点
SELECT device, path, type, encrypted FROM mounts WHERE type NOT IN ("proc", "sysfs", "cgroup", "tmpfs", "devtmpfs");

-- 近期新增的本地账户
SELECT username, directory, shell, uid FROM users WHERE uid >= 1000;

-- 采集探针自身状态（只读，便于交付核验）
SELECT version, install_time FROM osquery_info;
