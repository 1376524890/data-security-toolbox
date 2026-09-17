<script setup lang="ts">
import { computed } from 'vue'
import { severityLabels, severityTagColors } from '../../utils/mapping'

const props = defineProps<{ value: string }>()
const color = computed(() => severityTagColors[props.value] || '#3b82f6')
const label = computed(() => severityLabels[props.value] || props.value)
</script>

<template>
  <span class="sev-tag" :style="{ background: `${color}1f`, color, borderColor: `${color}66` }">{{ label }}</span>
</template>

<style scoped>
.sev-tag { display: inline-flex; align-items: center; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid; min-width: 52px; justify-content: center; }
</style>
