# 数据对象领域

从 [数据资产开发入口](../../../../docs/数据资产开发入口.md) 按需求选择模块。

- definitions / values：稳定词汇与上报值规范化。
- identity / coverage：文件身份、范围和时间顺序。
- persistence / evidence：数据库原语与检测证据合并。
- ingestion：一次报告的写入编排；调用方拥有事务。
- projection：旧 data_assets 展示投影及维护操作。
- queries：类型、对象和实例的查询统计。
- progress：采集进度估算与阶段显示。

不要把函数加回旧 data_object_service.py 兼容门面；不要从这里导入 API 或 worker。
