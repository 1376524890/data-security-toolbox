<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  label: string
  value: number | string
  sub?: string
  tone?: 'default' | 'danger' | 'warning' | 'info' | 'success' | 'primary'
  icon?: string
}>(), { tone: 'default' })

const colors: Record<string, string> = { danger: '#ef4444', warning: '#f59e0b', info: '#3b82f6', success: '#22c55e', primary: '#38bdf8' }
const color = computed(() => colors[props.tone] || 'var(--soc-text-strong)')
</script>

<template>
  <div class="stat-card">
    <div class="stat-top">
      <div class="stat-label">{{ label }}</div>
      <el-icon v-if="icon" :size="16" :style="{ color }"><component :is="icon" /></el-icon>
    </div>
    <div class="stat-value" :style="{ color }">{{ value }}</div>
    <div v-if="sub" class="stat-sub">{{ sub }}</div>
  </div>
</template>

<style scoped>
.stat-card { background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 14px 16px; min-height: 84px; }
.stat-top { display: flex; align-items: center; justify-content: space-between; }
.stat-label { color: var(--soc-text-muted); font-size: 12px; }
.stat-value { font-size: 28px; font-weight: 700; margin-top: 8px; line-height: 1.1; }
.stat-sub { color: var(--soc-text-dim); font-size: 11px; margin-top: 4px; }
</style>
