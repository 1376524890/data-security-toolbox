<script setup lang="ts">
import { computed, ref } from 'vue'
import { maskRecord } from '../utils/mask'

const props = defineProps<{ value: unknown; title?: string; masked?: boolean }>()
const expanded = ref(false)
const text = computed(() => JSON.stringify(props.masked ? maskRecord(props.value) : props.value, null, 2))
</script>

<template>
  <el-collapse-transition>
    <div v-if="expanded" class="json-viewer"><pre>{{ text }}</pre></div>
  </el-collapse-transition>
  <el-button link type="primary" @click="expanded = !expanded">{{ expanded ? '收起' : title || '查看 JSON' }}</el-button>
</template>

<style scoped>
.json-viewer { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-top: 8px; max-height: 360px; overflow: auto; }
pre { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 12px; }
</style>
