<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { listPcaps, getPcapProtocols, getTraffic } from '../../../api/pcaps'
import type { PcapRecord, TrafficOverview } from '../../../types/pcap'
import StateBox from '../../../components/common/StateBox.vue'
import BarChart from '../../../components/charts/BarChart.vue'
import DonutChart from '../../../components/charts/DonutChart.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'

const loading = ref(true)
const error = ref('')
const pcaps = ref<PcapRecord[]>([])
const selectedId = ref<number | null>(null)
const protocols = ref<Array<Record<string, unknown>>>([])
const traffic = ref<TrafficOverview | null>(null)

const protocolDistribution = computed(() => {
  const dist = traffic.value?.protocols || {}
  return Object.entries(dist).map(([name, value]) => ({ name, value }))
})
const protocolSummary = computed(() => {
  const out: Record<string, number> = {}
  protocols.value.forEach((node: any) => {
    const name = node.name || node.protocol || 'unknown'
    const count = node.count || node.packets || 0
    out[name] = (out[name] || 0) + Number(count)
  })
  return out
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listPcaps({ page: 1, page_size: 100 })
    pcaps.value = result.items
    if (!selectedId.value && result.items.length) selectedId.value = result.items[0].id
    if (selectedId.value) await loadProtocols()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function loadProtocols(): Promise<void> {
  if (!selectedId.value) return
  try {
    const [p, t] = await Promise.all([getPcapProtocols(selectedId.value), getTraffic(selectedId.value)])
    protocols.value = p
    traffic.value = t
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-select v-model="selectedId" placeholder="选择 PCAP" style="width: 320px" @change="loadProtocols">
        <el-option v-for="p in pcaps" :key="p.id" :label="p.filename" :value="p.id" />
      </el-select>
      <div class="toolbar-spacer" />
      <span class="gap-note">全局协议分析未提供，当前按 PCAP 维度展示</span>
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
