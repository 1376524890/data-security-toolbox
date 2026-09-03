<script setup lang="ts">
import { computed } from 'vue'
import { maskRecord } from '../../utils/mask'
import RawViewer from './RawViewer.vue'

const props = withDefaults(defineProps<{
  value: unknown
  title?: string
  masked?: boolean
  height?: number
}>(), { height: 320 })

const text = computed(() => JSON.stringify(props.masked ? maskRecord(props.value) : props.value, null, 2))
</script>

<template>
  <RawViewer :value="text" language="json" :height="height" :title="title" />
</template>
