<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import FileSources from './FileSources.vue'
import DatabaseConnections from './DatabaseConnections.vue'
const active = ref('files')
const router = useRouter()
</script>
<template><div>
  <div class="toolbar"><strong>来源管理</strong><div class="toolbar-spacer" /><el-button @click="router.push('/data-asset-jobs')">采集任务</el-button><el-button @click="router.push('/scan-profiles')">探针扫描配置</el-button><el-button @click="router.push('/rule-versions')">检测规则版本</el-button></div>
  <el-tabs v-model="active">
    <el-tab-pane label="共享文件" name="files"><FileSources v-if="active === 'files'" /></el-tab-pane>
    <el-tab-pane label="数据库" name="database"><DatabaseConnections v-if="active === 'database'" /></el-tab-pane>
    <el-tab-pane label="主机探针" name="probe"><div class="soc-card">主机目录由探针采集，卸载后仍保留历史资产和证据。<el-button type="primary" @click="router.push('/probes')">管理探针</el-button><el-button @click="router.push('/data-asset-jobs')">下发目录采集</el-button></div></el-tab-pane>
    <el-tab-pane label="手动文件" name="manual"><div class="soc-card">临时检查本地文件并查看分析结果。<el-button @click="router.push('/files')">上传与分析</el-button></div></el-tab-pane>
  </el-tabs>
</div></template>
