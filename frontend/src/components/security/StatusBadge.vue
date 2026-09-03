<script setup lang="ts">
import { computed } from 'vue'
import { statusColors } from '../../utils/mapping'

const props = defineProps<{ value: string }>()
const labelMap: Record<string, string> = {
  new: '新增', acknowledged: '已确认', resolved: '已解决', suppressed: '已抑制',
  open: '待处理', investigating: '调查中', contained: '已遏制', closed: '已关闭',
  running: '运行中', pending: '等待中', success: '成功', failed: '失败',
  ready: '就绪', disabled: '已禁用', error: '错误', online: '在线', offline: '离线',
  degraded: '降级', analyzed: '已分析', imported: '已导入', retained_analysis: '保留分析',
}
const color = computed(() => statusColors[props.value] || '#64748b')
const label = computed(() => labelMap[props.value] || props.value)
</script>

<template>
  <span class="status-badge" :style="{ color, background: `${color}1f`, borderColor: `${color}66` }">
    <span class="dot" :style="{ background: color }" />{{ label }}
  </span>
</template>

<style scoped>
.status-badge { display: inline-flex; align-items: center; gap: 5px; padding: 1px 9px; border-radius: 4px; font-size: 11px; font-weight: 600; border: 1px solid; }
.dot { width: 6px; height: 6px; border-radius: 50%; }
</style>
