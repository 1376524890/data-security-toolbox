<script setup lang="ts">
import { computed } from 'vue'
import { severityColors } from '../utils/mapping'

const props = defineProps<{ value: string }>()
const color = computed(() => severityColors[props.value] || severityColors.Low)
</script>

<template>
  <el-tag :color="color" class="severity-badge" effect="dark" size="small">{{ value }}</el-tag>
</template>

<style scoped>
.severity-badge { color: #fff; border: none; min-width: 68px; text-align: center; }
</style>
