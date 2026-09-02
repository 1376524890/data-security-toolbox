<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ score: number; level?: string }>()
const color = computed(() => {
  if (props.score >= 80) return '#b91c1c'
  if (props.score >= 60) return '#ea580c'
  if (props.score >= 35) return '#d97706'
  return '#2563eb'
})
</script>

<template>
  <el-progress type="circle" :percentage="Math.min(100, Math.max(0, score))" :width="56" :stroke-width="6" :color="color">
    <template #default><span class="score">{{ score.toFixed(0) }}</span></template>
  </el-progress>
  <span v-if="level" class="level">{{ level }}</span>
</template>

<style scoped>
.score { font-size: 13px; font-weight: 700; }
.level { margin-left: 8px; font-size: 12px; color: #64748b; }
</style>
