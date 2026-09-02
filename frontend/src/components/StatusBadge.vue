<script setup lang="ts">
import { computed } from 'vue'
import { statusColors } from '../utils/mapping'

const props = defineProps<{ value: string }>()
const color = computed(() => statusColors[props.value] || '#64748b')
</script>

<template>
  <el-tag :color="color" class="status-badge" effect="dark" size="small">{{ value }}</el-tag>
</template>

<style scoped>
.status-badge { color: #fff; border: none; min-width: 72px; text-align: center; }
</style>
