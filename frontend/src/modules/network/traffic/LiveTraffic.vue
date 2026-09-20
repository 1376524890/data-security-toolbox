<script setup lang="ts">
import { useRouter } from 'vue-router'
import StateBox from '../../../components/common/StateBox.vue'
import StatCard from '../../../components/common/StatCard.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import StatusBadge from '../../../components/security/StatusBadge.vue'
import { formatDateTime, formatBytes } from '../../../utils/format'
import { useLiveTraffic } from './composables/useLiveTraffic'

// The live window, the online probes and the alert stream live in the
// composable (the EventSource is opened on mount and closed on unmount); this
// view keeps the router and binds the state into the template below.
const router = useRouter()
const {
  loading, error, health, live, summary, liveAlerts, onlineProbes, captureRate, load,
} = useLiveTraffic()
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
