<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ value: string }>()
const labelMap: Record<string, string> = { Critical: '严重', High: '高危', Medium: '中危', Low: '低危' }
const color = computed(() => ({ Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6' }[props.value] || '#3b82f6'))
const label = computed(() => labelMap[props.value] || props.value)
</script>

<template>
  <span class="sev-tag" :style="{ background: `${color}1f`, color, borderColor: `${color}66` }">{{ label }}</span>
</template>

<style scoped>
.sev-tag { display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid; min-width: 52px; justify-content: center; }
</style>
