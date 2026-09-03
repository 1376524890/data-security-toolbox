<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { getGlobalFlows } from '../../../api/network'
import type { Flow } from '../../../types/pcap'
import StateBox from '../../../components/common/StateBox.vue'
import FlowTable from '../../../components/network/FlowTable.vue'
import { formatBytes, formatDuration } from '../../../utils/format'

const loading = ref(true)
const error = ref('')
const flows = ref<Flow[]>([])
const flowsLoading = ref(false)
const search = ref('')
const total = ref(0)

const topHosts = computed(() => {
  const byIp: Record<string, { ip: string; bytes: number; packets: number; destinations: Set<string>; protocols: Set<string> }> = {}
  for (const f of flows.value) {
    for (const [ip, role] of [[f.src_ip, 'src'], [f.dst_ip, 'dst']] as Array<[string, string]>) {
      const entry = (byIp[ip] = byIp[ip] || { ip, bytes: 0, packets: 0, destinations: new Set<string>(), protocols: new Set<string>() })
      entry.bytes += f.bytes
      entry.packets += f.packets
      entry.destinations.add(role === 'src' ? f.dst_ip : f.src_ip)
      entry.protocols.add(f.protocol)
    }
  }
  return Object.values(byIp).sort((a, b) => b.bytes - a.bytes).slice(0, 10).map((e) => ({ ip: e.ip, bytes: e.bytes, packets: e.packets, destinations: e.destinations.size, protocols: Array.from(e.protocols).join(', ') }))
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    await loadFlows()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function loadFlows(): Promise<void> {
  flowsLoading.value = true
  try {
    const result = await getGlobalFlows({ search: search.value || undefined, page: 1, page_size: 200 })
    flows.value = result.items
    total.value = result.total
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
      <el-input v-model="search" placeholder="按源/目的 IP 搜索" clearable style="width: 320px" @keyup.enter="loadFlows" />
      <el-button @click="loadFlows">查询</el-button>
      <span class="text-dim">全局会话流 · 共 {{ total }} 条</span>
      <div class="toolbar-spacer" />
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
