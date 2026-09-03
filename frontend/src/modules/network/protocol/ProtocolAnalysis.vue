<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { getGlobalProtocols } from '../../../api/network'
import StateBox from '../../../components/common/StateBox.vue'
import BarChart from '../../../components/charts/BarChart.vue'
import DonutChart from '../../../components/charts/DonutChart.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'

const loading = ref(true)
const error = ref('')
const protocols = ref<Array<Record<string, unknown>>>([])

const protocolDistribution = computed(() => {
  return protocols.value.map((node: any) => ({ name: node.name, value: node.count }))
})
const protocolSummary = computed(() => {
  const out: Record<string, number> = {}
  protocols.value.forEach((node: any) => {
    out[node.name] = Number(node.count || 0)
  })
  return out
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    await loadProtocols()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function loadProtocols(): Promise<void> {
  try {
    protocols.value = await getGlobalProtocols()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <span class="text-dim">全局协议分布（跨全部捕获）</span>
      <div class="toolbar-spacer" />
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="grid cols-2" style="margin-bottom: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />协议分布</div>
          <DonutChart :data="protocolDistribution" :height="300" />
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />协议包计数</div>
          <BarChart :x-data="Object.keys(protocolSummary)" :data="Object.values(protocolSummary)" :height="300" />
        </div>
      </div>
      <div class="soc-card">
        <div class="soc-card-title"><span class="dot" />协议分层树</div>
        <JsonViewer :value="protocols" title="协议树" :height="360" />
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
