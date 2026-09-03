<script setup lang="ts">
import type { Asset } from '../../types/asset'
import RiskBadge from './RiskBadge.vue'

defineProps<{ asset: Asset }>()
defineEmits<{ select: [] }>()
</script>

<template>
  <div class="asset-card" @click="$emit('select')">
    <div class="ac-head">
      <div class="ac-ip mono">{{ asset.ip }}</div>
      <RiskBadge :level="asset.risk_level" />
    </div>
    <div class="ac-hostname">{{ asset.hostname || '未知主机' }}</div>
    <div class="ac-meta">
      <el-tag size="small" :type="asset.asset_type === 'server' ? 'info' : 'warning'">{{ asset.asset_type || 'unknown' }}</el-tag>
      <el-tag v-if="asset.service" size="small">{{ asset.service }}</el-tag>
      <el-tag v-if="asset.os" size="small" type="info">{{ asset.os }}</el-tag>
    </div>
    <div class="ac-foot">
      <span v-if="asset.port" class="mono">:{{ asset.port }}/{{ asset.protocol }}</span>
      <span class="ac-cats" v-if="asset.sensitive_categories?.length">{{ asset.sensitive_categories.length }} 敏感类目</span>
    </div>
  </div>
</template>

<style scoped>
.asset-card { background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; cursor: pointer; transition: border-color 0.15s, background 0.15s; }
.asset-card:hover { border-color: var(--soc-primary); background: var(--soc-panel-hover); }
.ac-head { display: flex; align-items: center; justify-content: space-between; }
.ac-ip { font-weight: 700; font-size: 15px; color: var(--soc-text-strong); }
.ac-hostname { color: var(--soc-text-muted); font-size: 12px; margin-top: 2px; }
.ac-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
.ac-foot { display: flex; justify-content: space-between; color: var(--soc-text-dim); font-size: 11px; margin-top: 8px; }
.ac-cats { color: var(--soc-warning); }
</style>
