<template>
  <el-container class="layout">
    <el-aside width="220px" class="aside">
      <div class="brand">🔐 数据安全检测工具箱</div>
      <el-menu :default-active="$route.path" router class="menu">
        <el-menu-item index="/dashboard">📊 总览仪表盘</el-menu-item>
        <el-menu-item index="/probes">🖥 探针管理</el-menu-item>
        <el-sub-menu index="tasks-menu" title="任务管理">
          <el-menu-item index="/tasks">任务列表</el-menu-item>
          <el-menu-item index="/tasks/new" disabled>创建检测任务</el-menu-item>
        </el-sub-menu>
        <el-sub-menu index="results-menu" title="检测结果">
          <el-menu-item index="/results/asset">数据资产识别</el-menu-item>
          <el-menu-item index="/results/metadata">元数据分析</el-menu-item>
          <el-menu-item index="/results/algo">算法评估</el-menu-item>
          <el-menu-item index="/results/protocol">协议分析</el-menu-item>
          <el-menu-item index="/results/traffic">流量分析</el-menu-item>
        </el-sub-menu>
        <el-menu-item index="/tools/regex-gen">🧰 正则生成器</el-menu-item>
        <el-menu-item index="/reports">📄 报告中心</el-menu-item>
        <el-menu-item index="/settings">⚙️ 系统设置</el-menu-item>
      </el-menu>
    </el-aside>
    <el-main class="main">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup>
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: "PingFang SC", "Microsoft YaHei", system-ui, sans-serif; background: var(--bg-app); color: var(--text-primary); }
.layout { height: 100vh; }
.aside { background: var(--bg-aside); color: var(--text-on-dark); display: flex; flex-direction: column; }
.brand { padding: 18px 16px; font-weight: 700; font-size: 14px; color: #fff; border-bottom: 1px solid var(--border-dark); }
.menu { border-right: none; background: var(--bg-aside); flex: 1; overflow-y: auto; }
.menu :deep(.el-menu-item), .menu :deep(.el-sub-menu__title) { color: var(--text-on-dark); }
.menu :deep(.el-menu-item.is-active) { color: var(--text-on-dark-active); background: var(--color-primary); }
.menu :deep(.el-menu-item:hover) { background: var(--color-primary-hover); color: var(--text-on-dark-active); }
.menu :deep(.el-sub-menu .el-menu-item) { background: var(--bg-aside-sub); color: var(--text-on-dark-sub); }
.menu :deep(.el-sub-menu .el-menu-item.is-active) { color: var(--text-on-dark-active); background: var(--color-primary); }
.main { background: var(--bg-app); padding: 20px; }
</style>