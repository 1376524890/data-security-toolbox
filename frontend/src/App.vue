<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElNotification } from 'element-plus'
import { menuGroups } from './router/menu'
import { useAuthStore } from './stores/auth'
import { useSystemStore } from './stores/system'
import type { IntegrationStatus } from './types/integration'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const system = useSystemStore()
const collapsed = ref(false)
const now = ref(new Date())
let clock = 0

const currentTitle = computed(() => String(route.meta.title || 'Dashboard'))
const currentGroup = computed(() => String(route.meta.group || ''))
const healthyIntegrations = computed(() => system.integrations.filter((item: IntegrationStatus) => item.healthy).length)
const unhandledAlerts = computed(() => system.alertSummary?.unhandled_critical_high || 0)
const healthStatus = computed(() => system.health?.status || 'checking')

const menuVisible = computed(() => !route.meta.public)

function isActive(path: string): boolean {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

function onAlert(alert: { title: string; severity: string; id: number }): void {
  ElNotification({
    title: `${alert.severity} ${alert.title}`,
    message: `Alert #${alert.id}`,
    type: alert.severity === 'Critical' ? 'error' : alert.severity === 'High' ? 'warning' : 'info',
    duration: 6000,
    onClick: () => router.push('/alerts'),
  })
}

function openAlerts(): void {
  router.push('/alerts')
}

onMounted(() => {
  clock = window.setInterval(() => { now.value = new Date() }, 1000)
  if (!route.meta.public) {
    system.start()
    system.connect(onAlert)
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
          <template v-for="node in menuGroups" :key="'group' in node ? node.group : node.path">
            <div v-if="'group' in node" class="menu-group-title">{{ collapsed ? '···' : node.group }}</div>
            <el-menu :default-active="route.path" router :collapse="collapsed" :collapse-transition="false">
              <template v-if="'group' in node">
                <el-menu-item v-for="item in node.items" :key="item.path" :index="item.path">
                  <el-icon><component :is="item.icon" /></el-icon>
                  <template #title>{{ item.title }}</template>
                </el-menu-item>
              </template>
              <el-menu-item v-else :index="node.path">
                <el-icon><component :is="node.icon" /></el-icon>
                <template #title>{{ node.title }}</template>
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
          <span class="header-clock mono">{{ now.toLocaleTimeString('zh-CN', { hour12: false }) }}</span>
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

.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--soc-warning); display: inline-block; }
.status-dot.ok { background: var(--soc-success); }
.status-dot.degraded { background: var(--soc-warning); }
</style>
