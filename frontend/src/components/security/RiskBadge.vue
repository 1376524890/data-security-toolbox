<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ level?: string; score?: number }>()
const labelMap: Record<string, string> = { Critical: '严重', High: '高危', Medium: '中危', Low: '低危' }
const normalized = computed(() => {
  if (props.score != null && props.score >= 80) return 'Critical'
  if (props.score != null && props.score >= 60) return 'High'
  if (props.score != null && props.score >= 35) return 'Medium'
  return props.level || 'Low'
})
const color = computed(() => ({ Critical: 'var(--risk-critical)', High: 'var(--risk-high)', Medium: 'var(--risk-medium)', Low: 'var(--risk-low)' }[normalized.value] || 'var(--risk-low)'))
const bg = computed(() => ({ Critical: 'rgba(239,68,68,0.15)', High: 'rgba(249,115,22,0.15)', Medium: 'rgba(234,179,8,0.15)', Low: 'rgba(59,130,246,0.15)' }[normalized.value] || 'rgba(59,130,246,0.15)'))
const label = computed(() => labelMap[normalized.value] || normalized.value)
</script>

<template>
  <span class="risk-badge" :style="{ color, background: bg }">
    <span class="dot" :style="{ background: color }" />
    {{ label }}
  </span>
</template>

<style scoped>
.risk-badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.02em; }
.dot { width: 6px; height: 6px; border-radius: 50%; }
</style>
