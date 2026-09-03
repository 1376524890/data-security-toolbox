<script setup lang="ts">
import { computed } from 'vue'
import JsonViewer from './JsonViewer.vue'
import { isPasswordLikeKey, maskSensitiveValue } from '../../utils/mask'

const props = defineProps<{ evidence?: Record<string, unknown> | null }>()
const commonKeys = ['src_ip', 'dst_ip', 'dest_ip', 'ip', 'domain', 'url', 'uri', 'hash', 'protocol', 'filename', 'signature', 'entity_type', 'query', 'value', 'host', 'server_name', 'method', 'user_agent']
const common = computed(() => {
  const source = props.evidence || {}
  return commonKeys.filter((key) => source[key] !== undefined && source[key] !== null && source[key] !== '').map((key) => ({ key, value: maskSensitiveValue(String(source[key])) }))
})
const raw = computed(() => {
  const source = props.evidence || {}
  const rest: Record<string, unknown> = {}
  Object.entries(source).forEach(([key, value]) => {
    if (!commonKeys.includes(key) && !isPasswordLikeKey(key)) rest[key] = value
  })
  return rest
})
</script>

<template>
  <div class="evidence-viewer">
    <el-descriptions v-if="common.length" :column="2" border size="small">
      <el-descriptions-item v-for="item in common" :key="item.key" :label="item.key"><span class="mono">{{ item.value }}</span></el-descriptions-item>
    </el-descriptions>
    <JsonViewer :value="raw" title="原始证据 JSON" :height="260" />
  </div>
</template>

<style scoped>
.evidence-viewer { display: flex; flex-direction: column; gap: 10px; }
</style>
