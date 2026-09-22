<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElNotification } from 'element-plus'
import { activeMenuEntry, activeMenuIndex, menuGroups, menuIndex } from './router/menu'
import { useAuthStore } from './stores/auth'
import { useSystemStore } from './stores/system'
import { importTestData, clearTestData, getTestStatus, markTestImported, consumeTestImported, type TestStatus } from './api/test'
import type { IntegrationStatus } from './types/integration'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const system = useSystemStore()
const collapsed = ref(false)
const theme = ref<'dark' | 'light'>(
  document.documentElement.classList.contains('light') ? 'light' : 'dark')

function toggleTheme(): void {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  document.documentElement.classList.toggle('dark', theme.value === 'dark')
  document.documentElement.classList.toggle('light', theme.value === 'light')
  localStorage.setItem('dst-theme', theme.value)
}
const now = ref(new Date())
let clock = 0
const testStatus = ref<TestStatus | null>(null)
const testBusy = ref(false)

const currentTitle = computed(() => String(route.meta.title || 'Dashboard'))
// The six sections are the top level of the sidebar, so the header reads the
// section straight from the menu entry rather than from per-route metadata.
const currentGroup = computed(() =>
  activeMenuEntry(route.path, route.query as Record<string, unknown>)?.group ||
  String(route.meta.group || ''))
// Two sub-items can share a route and differ only by their ``view`` query, so the
// highlighted entry is resolved from path + query, never path alone.
const activeKey = computed(() => activeMenuIndex(route.path, route.query as Record<string, unknown>))
const healthyIntegrations = computed(() => system.integrations.filter((item: IntegrationStatus) => item.healthy).length)
const unhandledAlerts = computed(() => system.alertSummary?.unhandled_critical_high || 0)
const healthStatus = computed(() => system.health?.status || 'checking')
// The test-data entry is a server capability: the delivery build ships without
// it, so the menu must not render (or call) the import/clear endpoints.
const testDataImportEnabled = computed(() => system.health?.features?.test_data_import === true)

const menuVisible = computed(() => !route.meta.public)

function isActive(path: string): boolean {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

// Popups are coalesced: a probe analysing traffic every 30 s produces alerts
// continuously, and one toast per alert buries the console. At most one popup
// per window, summarising what arrived in it, with a mute switch beside the bell
// (the badge keeps counting either way).
const ALERT_POPUP_WINDOW_MS = 15000
const alertsMuted = ref(localStorage.getItem('dst-alert-mute') === '1')
const pendingAlerts = ref<{ title: string; severity: string; id: number }[]>([])
let alertWindow: number | null = null

function flushAlerts(): void {
  const items = pendingAlerts.value.splice(0)
  if (!items.length) return
  const worst = items.some((a) => a.severity === 'Critical') ? 'Critical'
    : items.some((a) => a.severity === 'High') ? 'High' : 'Medium'
  ElNotification({
    title: items.length === 1 ? `${items[0].severity} ${items[0].title}`
      : `${items.length} 条新告警（最高 ${worst}）`,
    message: items.length === 1 ? `Alert #${items[0].id}`
      : items.slice(0, 3).map((a) => `#${a.id} ${a.title}`).join('；').slice(0, 200),
    type: worst === 'Critical' ? 'error' : worst === 'High' ? 'warning' : 'info',
    duration: 6000,
    onClick: () => { router.push('/data-assets') },
  })
}

function onAlert(alert: { title: string; severity: string; id: number }): void {
  pendingAlerts.value.push(alert)
  if (alertsMuted.value) return       // muted: the badge still counts, nothing pops
  if (alertWindow !== null) return    // one popup per window; the rest queue behind it
  flushAlerts()
  alertWindow = window.setTimeout(() => { alertWindow = null; flushAlerts() },
                                  ALERT_POPUP_WINDOW_MS)
}

function toggleAlertMute(): void {
  alertsMuted.value = !alertsMuted.value
  localStorage.setItem('dst-alert-mute', alertsMuted.value ? '1' : '0')
  if (!alertsMuted.value) flushAlerts()
}

function openAlerts(): void {
  // The alert centre was merged into 数据资产; the risk list there is where an
  // alert is acted on now.
  router.push(activeMenuEntry('/data-assets', {}) ? '/data-assets' : '/')
}

async function loadTestStatus(): Promise<void> {
  try { testStatus.value = await getTestStatus() } catch { testStatus.value = null }
}

async function onImportTest(): Promise<void> {
  if (testBusy.value) return
  testBusy.value = true
  try {
    const r = await importTestData()
    markTestImported()
    ElMessage.success(`已导入测试数据：${r.files} 文件 / ${r.pcaps} PCAP（刷新页面将自动清除）`)
    await loadTestStatus()
  } catch (err) {
    ElMessage.error(`导入失败：${err instanceof Error ? err.message : String(err)}`)
  } finally { testBusy.value = false }
}

async function onClearTest(): Promise<void> {
  if (testBusy.value) return
  testBusy.value = true
  try {
    await clearTestData()
    ElMessage.success('已清除测试数据')
    await loadTestStatus()
  } catch (err) {
    ElMessage.error(`清除失败：${err instanceof Error ? err.message : String(err)}`)
  } finally { testBusy.value = false }
}

onMounted(async () => {
  clock = window.setInterval(() => { now.value = new Date() }, 1000)
  if (!route.meta.public) {
    system.start()
    system.connect(onAlert)
    // 刷新页面后恢复原样：若上一会话导入了测试数据，则本次自动清除
    if (testDataImportEnabled.value && consumeTestImported()) {
      try { await clearTestData() } catch { /* ignore */ }
    }
    if (testDataImportEnabled.value) loadTestStatus()
  }
})
onBeforeUnmount(() => {
  window.clearInterval(clock)
  system.stop()
})
</script>

<template>
  <el-config-provider>
    <div v-if="auth.user || route.meta.public" class="app-shell">
      <aside v-if="menuVisible" class="app-aside" :class="{ collapsed }">
        <div class="brand">
          <div class="brand-logo">D</div>
          <div v-if="!collapsed">
            <div class="brand-name">Data Security Toolbox</div>
            <div class="brand-sub">SOC · NDR · 数据安全</div>
          </div>
        </div>
        <nav class="side-menu">
          <template v-for="section in menuGroups" :key="section.group">
            <div class="menu-group-title">{{ collapsed ? '···' : section.group }}</div>
            <el-menu :default-active="activeKey" router :collapse="collapsed" :collapse-transition="false">
              <el-menu-item v-for="item in section.items" :key="menuIndex(item)" :index="menuIndex(item)">
                <el-icon><component :is="item.icon" /></el-icon>
                <template #title>{{ item.title }}</template>
              </el-menu-item>
            </el-menu>
          </template>
        </nav>
      </aside>

      <div class="app-main">
        <header class="app-header">
          <el-button v-if="menuVisible" text @click="collapsed = !collapsed">
            <el-icon :size="18"><component :is="collapsed ? 'Expand' : 'Fold'" /></el-icon>
          </el-button>
          <div class="header-title">{{ currentTitle }}</div>
          <div v-if="currentGroup && !collapsed" class="header-crumb">{{ currentGroup }}</div>
          <div class="header-spacer" />
          <div class="header-chip">
            <span class="status-dot" :class="healthStatus" />
            <span class="text-muted">API {{ healthStatus }}</span>
          </div>
          <div class="header-chip">
            <span class="text-muted">集成组件 {{ healthyIntegrations }}/{{ system.integrations.length }}</span>
          </div>
          <el-badge :value="unhandledAlerts" :hidden="!unhandledAlerts" :max="99">
            <el-button size="small" text @click="openAlerts"><el-icon><Bell /></el-icon></el-button>
          </el-badge>
          <el-button size="small" text :title="alertsMuted ? '告警弹窗已静音（计数仍在）' : '告警弹窗开启'"
                     @click="toggleAlertMute">
            <el-icon><component :is="alertsMuted ? 'MuteNotification' : 'BellFilled'" /></el-icon>
          </el-button>
          <el-button size="small" text :title="theme === 'dark' ? '切换到浅色主题' : '切换到深色主题'"
                     @click="toggleTheme">
            <el-icon><component :is="theme === 'dark' ? 'Sunny' : 'Moon'" /></el-icon>
          </el-button>
          <span class="header-clock mono">{{ now.toLocaleTimeString('zh-CN', { hour12: false }) }}</span>
          <el-dropdown v-if="testDataImportEnabled" trigger="click" @command="(cmd: string) => { if (cmd === 'import') onImportTest(); if (cmd === 'clear') onClearTest() }">
            <el-button size="small" text :loading="testBusy">
              <el-icon><MagicStick /></el-icon>
              <span v-if="testStatus?.present" class="test-badge">测试数据</span>
              <span v-else>测试数据</span>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="import">导入测试数据</el-dropdown-item>
                <el-dropdown-item command="clear" :disabled="!testStatus?.present">清除测试数据</el-dropdown-item>
                <el-dropdown-item disabled>
                  状态：{{ testStatus?.present ? `已导入（${testStatus.files} 文件 / ${testStatus.pcaps} PCAP）` : '未导入' }}
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <el-button size="small" text @click="system.refresh()"><el-icon><Refresh /></el-icon></el-button>
          <el-dropdown v-if="auth.user">
            <span class="text-muted" style="cursor: pointer">{{ auth.user.username }}</span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="auth.logout(); router.push('/login')">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </header>
        <main class="app-content"><router-view /></main>
      </div>
    </div>
    <div v-else-if="!route.meta.public" class="app-shell"><router-view /></div>
  </el-config-provider>
</template>

<style>
@import './styles/theme.css';
@import './styles/main.css';

.test-badge { color: var(--soc-warning); }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--soc-warning); display: inline-block; }
.status-dot.ok { background: var(--soc-success); }
.status-dot.degraded { background: var(--soc-warning); }
</style>
