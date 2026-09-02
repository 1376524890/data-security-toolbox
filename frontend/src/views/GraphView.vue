<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get } from '../api'
const graph = ref<Record<string, unknown>>({})
onMounted(async () => { graph.value = await get('/graph') })
</script>
<template>
  <el-card>
    <template #header>资产关系图</template>
    <pre>{{ graph }}</pre>
  </el-card>
</template>

