<script setup lang="ts">
defineProps<{ label: string; value: number | string; tone?: 'default' | 'danger' | 'warning' | 'info' | 'success' }>()
</script>

<template>
  <el-card shadow="never" class="stat-card">
    <div class="stat-label">{{ label }}</div>
    <div class="stat-value" :class="tone">{{ value }}</div>
  </el-card>
</template>

<style scoped>
.stat-card { min-height: 96px; }
.stat-label { color: #64748b; font-size: 13px; }
.stat-value { font-size: 28px; font-weight: 700; color: #0f172a; margin-top: 10px; }
.stat-value.danger { color: #b91c1c; }
.stat-value.warning { color: #d97706; }
.stat-value.info { color: #2563eb; }
.stat-value.success { color: #16a34a; }
</style>
