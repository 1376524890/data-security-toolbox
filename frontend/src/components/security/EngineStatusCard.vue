<script setup lang="ts">
import StatusBadge from './StatusBadge.vue'

export interface EngineStatus {
  name: string
  status: string
  version: string
  adapter_version: string
  runtime_version: string
  rule_count?: number
  capabilities: string[]
  supported_types: string[]
  installed: boolean
  enabled: boolean
  healthy: boolean
  last_check: string
  message: string
}

defineProps<{ item: EngineStatus }>()
</script>

<template>
  <div class="engine-card">
    <div class="ec-head">
      <div class="ec-name">{{ item.name }}</div>
      <StatusBadge :value="item.installed && item.enabled ? item.status : item.enabled ? 'ready' : 'disabled'" />
    </div>
    <div class="ec-version">
      <span class="ec-label">版本</span>
      <span class="mono">{{ item.runtime_version || item.version || item.adapter_version || '-' }}</span>
    </div>
    <div class="ec-version">
      <span class="ec-label">规则数</span>
      <span class="mono">{{ item.rule_count ?? '-' }}</span>
    </div>
    <div class="ec-tags">
      <el-tag v-for="cap in item.capabilities.slice(0, 4)" :key="cap" size="small" effect="plain">{{ cap }}</el-tag>
    </div>
    <div v-if="item.last_check" class="ec-check">最近检测: {{ item.last_check }}</div>
    <div v-if="item.message" class="ec-msg">{{ item.message }}</div>
  </div>
</template>

<style scoped>
.engine-card { background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 14px; }
.ec-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.ec-name { font-size: 16px; font-weight: 700; color: var(--soc-text-strong); }
.ec-version { display: flex; justify-content: space-between; color: var(--soc-text-muted); font-size: 12px; padding: 2px 0; }
.ec-label { color: var(--soc-text-dim); }
.ec-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
.ec-check, .ec-msg { color: var(--soc-text-dim); font-size: 11px; margin-top: 8px; }
.ec-msg { color: var(--soc-warning); }
</style>
