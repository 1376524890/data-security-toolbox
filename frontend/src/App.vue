<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElNotification } from 'element-plus'
import { apiGet } from './api/client'
import { getAlert, getAlertSummary, alertStreamUrl } from './api/alerts'
import type { HealthResponse } from './types/common'
import type { IntegrationStatus } from './types/integration'
import type { AlertSummary } from './types/alert'

const route = useRoute()
const router = useRouter()
const health = ref<HealthResponse | null>(null)
const integrations = ref<IntegrationStatus[]>([])
const alertSummary = ref<AlertSummary | null>(null)
const now = ref(new Date())
let timer = 0
let refreshTimer = 0
let eventSource: EventSource | null = null

const currentTitle = computed(() => String(route.meta.title || '安全平台'))
const healthyIntegrations = computed(() => integrations.value.filter((item) => item.healthy).length)
const unhandledAlerts = computed(() => alertSummary.value?.unhandled_critical_high || 0)

async function refresh(): Promise<void> {
  const [healthResult, integrationResult, alertResult] = await Promise.allSettled([
    apiGet<HealthResponse>('/health'),
    apiGet<IntegrationStatus[]>('/integrations'),
    getAlertSummary(),
  ])
  if (healthResult.status === 'fulfilled') health.value = healthResult.value
  if (integrationResult.status === 'fulfilled') integrations.value = integrationResult.value
  if (alertResult.status === 'fulfilled') alertSummary.value = alertResult.value
}

function openAlerts(): void {
  router.push('/alerts')
}

function connectAlertStream(): void {
  if (eventSource) eventSource.close()
  eventSource = new EventSource(alertStreamUrl())
  eventSource.addEventListener('alert', async (event) => {
    try {
      const data = JSON.parse(event.data)
      const detail = await getAlert(data.alert_id)
      const alert = detail.alert
      ElNotification({
        title: `${alert.severity} ${alert.title}`,
        message: `${detail.probe?.ip_address || alert.probe_id || ''} Risk ${alert.risk_score}`,
        type: alert.severity === 'Critical' ? 'error' : alert.severity === 'High' ? 'warning' : 'info',
        duration: 8000,
        onClick: openAlerts,
      })
      alertSummary.value = await getAlertSummary()
    } catch {
      // SSE payload may arrive before a database read is visible; next summary refresh fixes the badge.
    }
  })
}

onMounted(() => {
  refresh()
  connectAlertStream()
  timer = window.setInterval(() => { now.value = new Date() }, 1000)
  refreshTimer = window.setInterval(refresh, 30000)
})
onBeforeUnmount(() => {
  window.clearInterval(timer)
  window.clearInterval(refreshTimer)
  eventSource?.close()
})
</script>

<template>
  <el-container class="layout">
    <el-aside width="240px" class="aside">
      <div class="logo">Data Security Toolbox</div>
      <el-menu :default-active="route.path" router background-color="#0f172a" text-color="#cbd5e1" active-text-color="#38bdf8">
        <el-menu-item-group title="安全态势">
          <el-menu-item index="/">总览</el-menu-item>
        </el-menu-item-group>
        <el-menu-item-group title="安全调查">
          <el-menu-item index="/alerts">告警中心</el-menu-item>
          <el-menu-item index="/incidents">安全事件</el-menu-item>
          <el-menu-item index="/detections">检测结果</el-menu-item>
          <el-menu-item index="/risk">风险分析</el-menu-item>
        </el-menu-item-group>
        <el-menu-item-group title="资产与数据">
          <el-menu-item index="/assets">IT资产</el-menu-item>
          <el-menu-item index="/data-assets">数据资产</el-menu-item>
          <el-menu-item index="/graph">资产关系图</el-menu-item>
          <el-menu-item index="/files">文件分析</el-menu-item>
        </el-menu-item-group>
        <el-menu-item-group title="网络分析">
          <el-menu-item index="/pcaps">PCAP分析</el-menu-item>
        </el-menu-item-group>
        <el-menu-item-group title="威胁与检测">
          <el-menu-item index="/intelligence">威胁情报</el-menu-item>
          <el-menu-item index="/integrations">检测组件</el-menu-item>
          <el-menu-item index="/audit">安全审计</el-menu-item>
          <el-menu-item index="/algorithms">算法评估</el-menu-item>
        </el-menu-item-group>
        <el-menu-item-group title="运行管理">
          <el-menu-item index="/tasks">任务中心</el-menu-item>
          <el-menu-item index="/probes">探针管理</el-menu-item>
          <el-menu-item index="/reports">报告中心</el-menu-item>
        </el-menu-item-group>
        <el-menu-item-group title="系统">
          <el-menu-item index="/offline-resources">离线资源</el-menu-item>
        </el-menu-item-group>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-title">{{ currentTitle }}</div>
        <div class="header-meta">
          <el-tag :type="health?.status === 'ok' ? 'success' : 'danger'">{{ health?.status || 'checking' }}</el-tag>
          <el-tag type="info">Integrations {{ healthyIntegrations }}/{{ integrations.length }}</el-tag>
          <el-badge :value="unhandledAlerts" :hidden="!unhandledAlerts" class="bell"><el-button size="small" @click="openAlerts">告警</el-button></el-badge>
          <span class="clock">{{ now.toLocaleString('zh-CN', { hour12: false }) }}</span>
          <el-button size="small" @click="refresh">刷新</el-button>
        </div>
      </el-header>
      <el-main class="workspace"><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<style>
:root {
  --color-bg: #f1f5f9;
  --color-surface: #ffffff;
  --color-border: #e2e8f0;
  --color-text: #0f172a;
  --color-muted: #64748b;
  --color-primary: #2563eb;
  --color-danger: #b91c1c;
  --radius: 8px;
}

html, body, #app { margin: 0; height: 100%; background: var(--color-bg); color: var(--color-text); }
.layout { min-height: 100vh; }
.aside { background: #0f172a; color: #fff; }
.aside .el-menu-item-group__title { color: #64748b; font-size: 11px; letter-spacing: .08em; padding-left: 18px; }
.logo { color: #38bdf8; font-size: 18px; font-weight: 700; padding: 20px 16px; }
.header { background: #fff; border-bottom: 1px solid var(--color-border); display: flex; align-items: center; justify-content: space-between; height: 56px; }
.header-title { font-weight: 700; color: var(--color-text); }
.header-meta { display: flex; align-items: center; gap: 10px; }
.clock { color: var(--color-muted); font-size: 13px; }
.workspace { background: var(--color-bg); padding: 16px; }
.page-card { background: var(--color-surface); border-radius: var(--radius); padding: 16px; }
.toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
</style>
