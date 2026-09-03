<script setup lang="ts">
import type { DataAsset } from '../../types/dataAsset'
import RiskBadge from './RiskBadge.vue'

defineProps<{ asset: DataAsset }>()
defineEmits<{ select: [] }>()
</script>

<template>
  <div class="data-risk-card" @click="$emit('select')">
    <div class="drc-head">
      <div class="drc-name">{{ asset.name }}</div>
      <RiskBadge :level="asset.sensitivity" />
    </div>
    <div class="drc-type">{{ asset.asset_type }}</div>
    <div class="drc-source mono">{{ asset.source || '-' }}</div>
    <div class="drc-cols">
      <el-tag v-for="col in asset.columns?.slice(0, 3)" :key="col.name" size="small" type="warning">{{ col.name }}</el-tag>
      <span v-if="(asset.columns?.length || 0) > 3" class="drc-more">+{{ asset.columns!.length - 3 }}</span>
    </div>
  </div>
</template>

<style scoped>
.data-risk-card { background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; cursor: pointer; transition: border-color 0.15s, background 0.15s; }
.data-risk-card:hover { border-color: var(--soc-warning); background: var(--soc-panel-hover); }
.drc-head { display: flex; align-items: center; justify-content: space-between; }
.drc-name { font-weight: 700; color: var(--soc-text-strong); }
.drc-type { color: var(--soc-text-muted); font-size: 12px; margin-top: 2px; }
.drc-source { color: var(--soc-text-dim); font-size: 11px; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.drc-cols { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
.drc-more { color: var(--soc-text-dim); font-size: 11px; align-self: center; }
</style>
