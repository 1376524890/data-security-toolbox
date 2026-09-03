<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { listPcaps, getPcapFlows, getTraffic } from '../../../api/pcaps'
import type { PcapRecord, Flow, TrafficOverview } from '../../../types/pcap'
import StateBox from '../../../components/common/StateBox.vue'
import FlowTable from '../../../components/network/FlowTable.vue'
import { formatBytes, formatDuration } from '../../../utils/format'

const loading = ref(true)
const error = ref('')
const pcaps = ref<PcapRecord[]>([])
const selectedId = ref<number | null>(null)
const flows = ref<Flow[]>([])
const traffic = ref<TrafficOverview | null>(null)
const flowsLoading = ref(false)

const selected = computed(() => pcaps.value.find((p) => p.id === selectedId.value) || null)
const topHosts = computed(() => (traffic.value?.hosts || []).slice(0, 10))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listPcaps({ page: 1, page_size: 100 })
    pcaps.value = result.items
    if (!selectedId.value && result.items.length) selectedId.value = result.items[0].id
    if (selectedId.value) await loadFlows()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function loadFlows(): Promise<void> {
  if (!selectedId.value) return
  flowsLoading.value = true
  try {
    const [f, t] = await Promise.all([getPcapFlows(selectedId.value, 1, 200), getTraffic(selectedId.value)])
    flows.value = f.items
    traffic.value = t
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    flowsLoading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-select v-model="selectedId" placeholder="选择 PCAP" style="width: 320px" @change="loadFlows">
        <el-option v-for="p in pcaps" :key="p.id" :label="p.filename" :value="p.id" />
      </el-select>
      <span class="text-dim" v-if="selected">共 {{ flows.length }} 条流 · {{ formatBytes(selected.size) }}</span>
      <div class="toolbar-spacer" />
      <span class="gap-note">全局会话流端点未提供，当前按 PCAP 维度浏览</span>
    </div>
    <StateBox :loading="loading" :error="error" :empty="!flows.length" @retry="load">
      <div class="grid cols-2" style="margin-bottom: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />会话流</div>
          <FlowTable :flows="flows" />
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />主机行为</div>
          <el-table :data="topHosts" size="small">
            <el-table-column v-for="(key, i) in Object.keys(topHosts[0] || {})" :key="key" :prop="key" :label="key" min-width="110" show-overflow-tooltip />
          </el-table>
          <div v-if="!topHosts.length" class="text-dim">无数据</div>
        </div>
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
