# 版本与分支管理

## 分支

- `main`：稳定发布分支，只接受经过验收的合并
- `develop`：集成开发分支
- `feature/*`：功能分支，从 `develop` 创建，完成后合并回 `develop`

## 版本

- `v0.1` 基础框架
- `v0.2` Probe
- `v0.3` 任务系统
- `v0.4` 资产 + 元数据
- `v0.5` PCAP 分析
- `v0.6` 流量分析
- `v1.0` 完整系统

发布时创建 `vX.Y.Z` 注释标签。

## 提交信息

使用 Conventional Commits：`feat:`、`fix:`、`docs:`、`test:`、`chore:`。

