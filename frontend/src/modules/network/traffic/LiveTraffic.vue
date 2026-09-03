<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { getHealth, type HealthResponse } from '../../../api/health'
import { listProbes, type Probe } from '../../../api/probes'
import { getLiveNetwork, type LiveNetwork } from '../../../api/network'
import { listPcaps } from '../../../api/pcaps'
import type { PcapRecord } from '../../../types/pcap'
import { getAlertSummary, alertStreamUrl } from '../../../api/alerts'
import StateBox from '../../../components/common/StateBox.vue'
import StatCard from '../../../components/common/StatCard.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import StatusBadge from '../../../components/security/StatusBadge.vue'
import { formatDateTime, formatBytes } from '../../../utils/format'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const health = ref<HealthResponse | null>(null)
const probes = ref<Probe[]>([])
const recentPcaps = ref<PcapRecord[]>([])
const live = ref<LiveNetwork | null>(null)
const summary = ref<{ total: number; unhandled_critical_high: number } | null>(null)
const liveAlerts = ref<Array<{ id: number; severity: string; title: string; time: string }>>([])
let eventSource: EventSource | null = null

const onlineProbes = computed(() => probes.value.filter((p: Probe) => p.status === 'online'))
// Derive a real capture rate from the most recently analyzed capture (no dedicated live endpoint).
const captureRate = computed(() => {
  if (!live.value) return { pps: null as number | null, bps: null as number | null, source: null as string | null }
  return { pps: Math.round(live.value.pps), bps: Math.round(live.value.bps), source: `实时窗口 ${live.value.window_seconds}s` }
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [h, p, s, pcaps, lv] = await Promise.all([
      getHealth(),
      listProbes({ page: 1, page_size: 100 }),
      getAlertSummary(),
      listPcaps({ page: 1, page_size: 5 }),
      getLiveNetwork(),
    ])
    health.value = h
    probes.value = p.items
    summary.value = s
    recentPcaps.value = pcaps.items
    live.value = lv
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function connect(): void {
  eventSource = new EventSource(alertStreamUrl())
  eventSource.addEventListener('alert', (event) => {
    try {
      const data = JSON.parse(event.data)
      liveAlerts.value.unshift({ id: data.alert_id, severity: data.severity || 'Medium', title: data.title || '新告警', time: new Date().toISOString() })
      liveAlerts.value = liveAlerts.value.slice(0, 50)
    } catch { /* ignore */ }
  })
}

onMounted(() => { load(); connect() })
onBeforeUnmount(() => { eventSource?.close() })
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="stat-grid cols-4">
        <StatCard label="在线探针" :value="onlineProbes.length" :sub="`共 ${health?.probe?.count || 0}`" tone="success" />
        <StatCard label="包/秒 (最近捕获)" :value="captureRate.pps ?? '—'" tone="primary" />
        <StatCard label="字节/秒 (最近捕获)" :value="captureRate.bps ? formatBytes(captureRate.bps) : '—'" tone="info" />
        <StatCard label="未处理高危告警" :value="summary?.unhandled_critical_high || 0" tone="danger" />
      </div>

      <div class="grid cols-3" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />在线探针</div>
          <div v-for="p in onlineProbes" :key="p.id" class="probe-item">
            <div>
              <div class="mono">{{ p.ip_address || p.name }}</div>
              <div class="text-dim">{{ p.hostname }}</div>
            </div>
            <StatusBadge :value="p.status" />
          </div>
          <div v-if="!onlineProbes.length" class="text-dim">无在线探针</div>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />最近捕获</div>
          <div v-if="captureRate.source" class="text-dim mono" style="word-break: break-all">{{ captureRate.source }}</div>
          <div v-else class="text-dim">无已分析捕获</div>
          <div class="top-list">
            <div class="top-head">Top 源</div>
            <div v-for="t in (live?.top_src || []).slice(0, 5)" :key="t.ip" class="top-item"><span class="mono">{{ t.ip }}</span><span class="text-dim">{{ formatBytes(t.bytes) }}</span></div>
            <div class="top-head" style="margin-top: 8px">Top 目的</div>
            <div v-for="t in (live?.top_dst || []).slice(0, 5)" :key="t.ip" class="top-item"><span class="mono">{{ t.ip }}</span><span class="text-dim">{{ formatBytes(t.bytes) }}</span></div>
            <div class="top-head" style="margin-top: 8px">Top 端口</div>
            <div v-for="t in (live?.top_port || []).slice(0, 5)" :key="t.port" class="top-item"><span class="mono">:{{ t.port }}</span><span class="text-dim">{{ formatBytes(t.bytes) }}</span></div>
          </div>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot danger" />实时告警</div>
          <div v-if="liveAlerts.length" class="live-alerts">
            <div v-for="a in liveAlerts" :key="a.id" class="live-alert" @click="router.push('/alerts')">
              <SeverityTag :value="a.severity" />
              <span class="live-title">{{ a.title }}</span>
              <span class="text-dim">{{ formatDateTime(a.time) }}</span>
            </div>
          </div>
          <div v-else class="text-dim">等待实时告警…</div>
        </div>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />队列 / 工作进程</div>
        <el-descriptions :column="4" border size="small">
          <el-descriptions-item label="分析工作进程">{{ health?.analysis_worker || '-' }}</el-descriptions-item>
          <el-descriptions-item label="队列待处理">{{ health?.queue?.pending || 0 }}</el-descriptions-item>
          <el-descriptions-item label="队列运行中">{{ health?.queue?.running || 0 }}</el-descriptions-item>
          <el-descriptions-item label="Celery 工作进程">{{ health?.celery?.workers || 0 }}</el-descriptions-item>
        </el-descriptions>
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.probe-item { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 0; border-bottom: 1px dashed var(--soc-border); }
.live-alert { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px dashed var(--soc-border); cursor: pointer; }
.live-alert:hover { background: var(--soc-panel-hover); }
.live-title { flex: 1; color: var(--soc-text); font-size: 12px; }
.live-alerts { display: flex; flex-direction: column; }
.gap-note { color: var(--soc-warning); font-size: 11px; margin-top: 10px; }
.top-list { margin-top: 8px; }
.top-head { font-size: 11px; font-weight: 700; color: var(--soc-text-muted); margin-bottom: 4px; }
.top-item { display: flex; justify-content: space-between; gap: 8px; font-size: 12px; padding: 2px 0; }
</style>
