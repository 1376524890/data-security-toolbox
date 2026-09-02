<template>
  <el-container class="layout">
    <el-aside width="220px" class="aside">
      <div class="logo">数据安全检测工具箱</div>
      <el-menu :default-active="$route.path" router background-color="#0f172a" text-color="#cbd5e1" active-text-color="#38bdf8">
        <el-menu-item index="/">总览</el-menu-item>
        <el-menu-item index="/assets">资产识别</el-menu-item>
        <el-menu-item index="/files">元数据</el-menu-item>
        <el-menu-item index="/pcaps">协议与流量</el-menu-item>
        <el-menu-item index="/algorithms">算法评估</el-menu-item>
        <el-menu-item index="/tasks">任务</el-menu-item>
        <el-menu-item index="/reports">报告</el-menu-item>
        <el-menu-item index="/audit">安全审计</el-menu-item>
        <el-menu-item index="/probes">探针</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">企业内网数据安全检测平台</el-header>
      <el-main><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<style>
html, body, #app { margin: 0; height: 100%; background: #f1f5f9; }
.layout { min-height: 100vh; }
.aside { background: #0f172a; color: #fff; }
.logo { color: #38bdf8; font-size: 18px; font-weight: 700; padding: 20px 16px; }
.header { background: #fff; border-bottom: 1px solid #e2e8f0; line-height: 60px; font-weight: 600; color: #1e293b; }
</style>

