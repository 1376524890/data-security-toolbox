<script setup lang="ts">
import { computed } from 'vue'

export interface TimelineItem {
  time?: string
  title: string
  description?: string
  status?: string
  color?: string
}

const props = defineProps<{ items: TimelineItem[] }>()
const colors = computed(() => {
  const map: Record<string, string> = { success: '#22c55e', warning: '#eab308', danger: '#ef4444', info: '#3b82f6' }
  return props.items.map((item) => item.color || (item.status ? map[item.status] : undefined) || '#38bdf8')
})
</script>

<template>
  <el-timeline v-if="items.length">
    <el-timeline-item v-for="(item, i) in items" :key="i" :timestamp="item.time" :color="colors[i]">
      <div class="tl-title">{{ item.title }}</div>
      <div v-if="item.description" class="tl-desc">{{ item.description }}</div>
    </el-timeline-item>
  </el-timeline>
  <div v-else class="tl-empty">暂无时间线记录</div>
</template>

<style scoped>
.tl-title { font-weight: 600; color: var(--soc-text-strong); font-size: 13px; }
.tl-desc { color: var(--soc-text-muted); font-size: 12px; margin-top: 2px; }
.tl-empty { color: var(--soc-text-dim); font-size: 12px; padding: 12px 0; }
</style>
