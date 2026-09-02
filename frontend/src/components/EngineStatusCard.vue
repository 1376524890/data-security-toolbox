<script setup lang="ts">
import type { IntegrationStatus } from '../types/integration'
import StatusBadge from './StatusBadge.vue'

defineProps<{ item: IntegrationStatus }>()
</script>

<template>
  <el-card shadow="never" class="engine-card">
    <div class="engine-head">
      <div class="engine-name">{{ item.name }}</div>
      <StatusBadge :value="item.status" />
    </div>
    <el-descriptions :column="1" size="small">
      <el-descriptions-item label="Adapter">{{ item.adapter_version }}</el-descriptions-item>
      <el-descriptions-item label="Runtime">{{ item.runtime_version || '-' }}</el-descriptions-item>
      <el-descriptions-item label="Installed">{{ item.installed ? '是' : '否' }}</el-descriptions-item>
      <el-descriptions-item label="Healthy">{{ item.healthy ? '是' : '否' }}</el-descriptions-item>
    </el-descriptions>
    <div v-if="item.message" class="message">{{ item.message }}</div>
    <div class="tags">
      <el-tag v-for="cap in item.capabilities.slice(0, 4)" :key="cap" size="small">{{ cap }}</el-tag>
    </div>
  </el-card>
</template>

<style scoped>
.engine-card { height: 100%; }
.engine-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.engine-name { font-size: 16px; font-weight: 700; }
.message { color: #64748b; font-size: 12px; margin-top: 8px; }
.tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
</style>
