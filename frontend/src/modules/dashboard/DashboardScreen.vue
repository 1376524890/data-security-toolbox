<script setup lang="ts">
/**
 * 数据安全态势大屏 — the wall view.
 *
 * The view owns layout, routing, the node drawer and nothing else: state and
 * API calls live in ``composables/useDashboardScreen.ts``, and each panel is its
 * own component. Every figure on the page comes from the server aggregates in
 * that composable, so a number here and the same number in the console are the
 * same query.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../../stores/auth'
import { useSystemStore } from '../../stores/system'
import { formatBytes, formatDateTime } from '../../utils/format'
import { severityLabels } from '../../utils/mapping'
import AssetChart from './components/AssetChart.vue'
import ClosedLoop from './components/ClosedLoop.vue'
import EngineStatus from './components/EngineStatus.vue'
import EventStream from './components/EventStream.vue'
import GeoMap from './components/GeoMap.vue'
import MetricCards from './components/MetricCards.vue'
import ProbeHealth from './components/ProbeHealth.vue'
import RiskChart from './components/RiskChart.vue'
import SecurityHeader from './components/SecurityHeader.vue'
import TrafficMap from './components/TrafficMap.vue'
import TrendPanel from './components/TrendPanel.vue'
import { directionColors, directionLabels } from './chartTheme'
import { useDashboardScreen, type DetectionMetric } from './composables/useDashboardScreen'
import { useScreenScale } from './composables/useScreenScale'
import type { FlowNode } from '../../types/dashboard'

const router = useRouter()
const auth = useAuthStore()
const system = useSystemStore()
const { frameStyle } = useScreenScale()

const {
  loading, error, overview, traffic, geo, risk, events, probes, loop, now,
  riskSlices, assetSlices, nodes, detectionX, detectionValues, detectionLabel,
  detectionColor, flowX, engineRows, engineSummary, metric, centerView, updatedAt,
  refresh,
} = useDashboardScreen()

// Both views answer "where did the data go?": the topology says through which
// sessions, the geographic view says to which places. They are alternatives,
// not companions, so the centre column shows one at a time.
const centerTabs: Array<{ key: 'traffic' | 'geo'; label: string }> = [
  { key: 'traffic', label: '数据流动' },
  { key: 'geo', label: '地理位置态势' },
]

const selected = ref<FlowNode | null>(null)
const drawerOpen = ref(false)

// The tab title is chrome a projector still shows, and index.html carries the
// console's generic one. Set it here so leaving the screen restores it.
const consoleTitle = document.title
onMounted(() => { document.title = '数据安全态势大屏 · 数据安全监测检测工具箱' })
onBeforeUnmount(() => { document.title = consoleTitle })

const flowSeries = computed(() => (['internal', 'external', 'unknown'] as const).map((key) => ({
  name: directionLabels[key],
  data: (traffic.value?.trend || []).map((item) => Number(item[key] || 0)),
  color: directionColors[key],
})))

const detectionSeries = computed(() => [{
  name: detectionLabel.value,
  data: detectionValues.value,
  color: detectionColor.value,
}])

const metrics: Array<{ key: DetectionMetric; label: string }> = [
  { key: 'alerts', label: '告警' },
  { key: 'findings', label: '检测' },
  { key: 'incidents', label: '安全事件' },
]

const updatedText = computed(() =>
  updatedAt.value ? formatDateTime(updatedAt.value.toISOString()) : '—')
const probeCounts = computed(() =>
  overview.value?.probes || { total: 0, online: 0, degraded: 0, offline: 0 })
const integrationCounts = computed(() =>
  overview.value?.integrations || { total: 0, healthy: 0 })
const staleError = computed(() => (overview.value && error.value ? error.value : ''))

function openNode(node: FlowNode): void {
  selected.value = node
  drawerOpen.value = true
}

function toggleFullscreen(): void {
  const root = document.documentElement
  if (document.fullscreenElement) document.exitFullscreen().catch(() => undefined)
  else root.requestFullscreen?.().catch(() => undefined)
}

const sensitiveText = computed(() => {
  const node = selected.value
  if (!node) return '—'
  const categories = node.sensitive_categories || []
  return categories.length ? categories.join('、') : '未识别'
})
</script>

<template>
  <div class="ds-viewport">
    <div class="ds-frame" :style="frameStyle">
      <SecurityHeader
        :api-status="system.health?.status || ''"
        :integrations="integrationCounts"
        :probes="probeCounts"
        :username="auth.user?.username || ''"
        :now="now"
        @fullscreen="toggleFullscreen"
        @console="router.push('/cockpit')"
      />

      <MetricCards class="ds-kpis" :overview="overview" />

      <div class="ds-middle">
        <div class="ds-column">
          <TrendPanel
            title="数据流动态势"
            :x="flowX"
            :series="flowSeries"
            footnote="近 7 天会话数（按采集入库日期，未抓到的流量不在范围内）"
            empty-text="暂无会话数据"
          />
          <TrendPanel
            title="检测趋势"
            :x="detectionX"
            :series="detectionSeries"
            :footnote="`近 7 天 ${detectionLabel} 按天汇总`"
            empty-text="暂无检测数据"
          >
            <template #actions>
              <button
                v-for="item in metrics"
                :key="item.key"
                class="ds-switch"
                type="button"
                :class="{ active: metric === item.key }"
                @click="metric = item.key"
              >
                {{ item.label }}
              </button>
            </template>
          </TrendPanel>
        </div>

        <div class="ds-center">
          <div class="ds-center-tabs">
            <button
              v-for="tab in centerTabs"
              :key="tab.key"
              class="ds-switch"
              type="button"
              :class="{ active: centerView === tab.key }"
              @click="centerView = tab.key"
            >
              {{ tab.label }}
            </button>
          </div>
          <TrafficMap v-if="centerView === 'traffic'" :traffic="traffic" @select="openNode" />
          <GeoMap v-else :geo="geo" />
        </div>

        <div class="ds-column">
          <RiskChart :risk="risk" :slices="riskSlices" />
          <AssetChart :risk="risk" :slices="assetSlices" />
        </div>
      </div>

      <div class="ds-bottom">
        <EngineStatus :rows="engineRows" :summary="engineSummary" />
        <ProbeHealth :counts="probeCounts" :probes="probes" />
        <ClosedLoop :loop="loop" />
        <EventStream :events="events" />
      </div>

      <footer class="ds-footer">
        <span>数据安全监测检测工具箱 · 让数据更安全 · 让业务更可信</span>
        <span v-if="loading" class="ds-foot-note">数据加载中…</span>
        <span v-else-if="staleError" class="ds-foot-note bad">刷新失败：{{ staleError }}</span>
        <span v-else class="ds-foot-note">数据更新于 {{ updatedText }} · 每 30 秒自动刷新</span>
      </footer>

      <div v-if="error && !overview" class="ds-overlay">
        <div class="ds-overlay-card">
          <div class="ds-overlay-title">态势数据不可用</div>
          <div class="ds-overlay-text">{{ error }}</div>
          <button class="ds-switch active" type="button" @click="refresh">重新加载</button>
        </div>
      </div>
    </div>

    <el-drawer v-model="drawerOpen" size="420px" :with-header="false" class="ds-drawer">
      <div v-if="selected" class="ds-drawer-body">
        <div class="ds-drawer-head">
          <div>
            <div class="ds-drawer-name">{{ selected.name }}</div>
            <div class="ds-drawer-ip">{{ selected.ip }}</div>
          </div>
          <span class="ds-drawer-kind" :class="selected.kind">
            {{ selected.kind === 'external' ? '外部端点' : selected.kind === 'asset' ? '纳管资产' : '内网节点' }}
          </span>
        </div>

        <div class="ds-drawer-section">
          <div class="ds-drawer-title">资产信息</div>
          <dl class="ds-drawer-list">
            <div><dt>主机名</dt><dd>{{ selected.hostname || '—' }}</dd></div>
            <div><dt>资产类型</dt><dd>{{ selected.asset_type || '未纳管' }}</dd></div>
            <div><dt>服务 / 端口</dt><dd>{{ selected.service || '—' }}{{ selected.port ? ` : ${selected.port}` : '' }}</dd></div>
            <div><dt>操作系统</dt><dd>{{ selected.os || '—' }}</dd></div>
            <div><dt>风险等级</dt><dd>{{ severityLabels[selected.risk_level] || selected.risk_level || '未评级' }}</dd></div>
            <div><dt>敏感数据</dt><dd>{{ sensitiveText }}</dd></div>
          </dl>
        </div>

        <div class="ds-drawer-section">
          <div class="ds-drawer-title">流量数量</div>
          <div class="ds-drawer-metrics">
            <div><span>{{ selected.sessions }}</span>会话</div>
            <div><span>{{ formatBytes(selected.bytes) }}</span>流量</div>
            <div><span>{{ selected.packets }}</span>数据包</div>
            <div><span>{{ selected.external_sessions }}</span>外发会话</div>
          </div>
        </div>

        <div class="ds-drawer-section">
          <div class="ds-drawer-title">风险事件</div>
          <div class="ds-drawer-metrics">
            <div><span>{{ selected.findings }}</span>检测发现</div>
            <div><span>{{ selected.high_risk_findings }}</span>高危发现</div>
            <div><span>{{ selected.incidents }}</span>关联事件</div>
            <div><span>{{ selected.data_assets }}</span>数据资产</div>
          </div>
        </div>

        <button class="ds-drawer-action" type="button" @click="router.push('/data-assets')">
          进入资产中心查看详情
        </button>
        <div v-if="nodes.length" class="ds-drawer-note">
          拓扑中当前展示 {{ nodes.length }} 个节点 · {{ traffic?.links.length || 0 }} 条会话链路
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<style scoped>
.ds-viewport {
  width: 100%; height: 100%; overflow: hidden; background: #071426;
  display: flex; align-items: center; justify-content: center;
}
.ds-frame {
  transform-origin: center center; flex-shrink: 0;
  display: flex; flex-direction: column; gap: 10px; padding: 12px 14px 8px;
  background:
    radial-gradient(1200px 520px at 50% -10%, rgba(28, 82, 140, 0.42), transparent 70%),
    radial-gradient(900px 500px at 50% 115%, rgba(18, 62, 108, 0.35), transparent 70%),
    linear-gradient(180deg, #071426, #0B1930 55%, #071426);
  color: #d7e6f7; font-family: 'Microsoft YaHei', 'PingFang SC', system-ui, sans-serif;
}
.ds-kpis { height: 108px; flex-shrink: 0; }
.ds-middle {
  flex: 1; min-height: 0; display: grid; grid-template-columns: 430px minmax(0, 1fr) 420px; gap: 10px;
}
.ds-column { display: flex; flex-direction: column; gap: 10px; min-height: 0; }
.ds-column > * { flex: 1; min-height: 0; }
/* The centre column switches between the flow topology and the geographic map:
   they answer the same question, and stacked they halved each other - a map too
   short to read its own links. One at a time gives the active map full height. */
.ds-center { display: flex; flex-direction: column; gap: 8px; min-height: 0; }
.ds-center-tabs { display: flex; gap: 6px; flex-shrink: 0; }
.ds-center-tabs .ds-switch { font-size: 12px; padding: 3px 14px; }
.ds-center > section { flex: 1; min-height: 0; }
.ds-bottom {
  height: 250px; flex-shrink: 0;
  display: grid; grid-template-columns: 1.25fr 0.95fr 0.9fr 1.5fr; gap: 10px;
}
.ds-footer {
  height: 24px; flex-shrink: 0; display: flex; align-items: center; justify-content: space-between;
  font-size: 11px; color: #4f6b8a; border-top: 1px solid rgba(53, 160, 255, 0.14); padding: 0 4px;
}
.ds-foot-note { color: #5b7799; }
.ds-foot-note.bad { color: #ff7b86; }
.ds-switch {
  padding: 2px 9px; border-radius: 4px; cursor: pointer; font-size: 11px;
  color: #8aa6c6; background: rgba(20, 52, 88, 0.6); border: 1px solid rgba(53, 160, 255, 0.2);
}
.ds-switch.active { color: #06182c; background: linear-gradient(180deg, #6dc6ff, #35a0ff); border-color: transparent; }
.ds-overlay {
  position: absolute; inset: 0; display: grid; place-items: center; background: rgba(4, 12, 24, 0.82);
}
.ds-overlay-card {
  padding: 26px 34px; border-radius: 8px; text-align: center;
  border: 1px solid rgba(255, 77, 94, 0.4); background: rgba(11, 30, 54, 0.95);
}
.ds-overlay-title { font-size: 16px; font-weight: 700; color: #ff7b86; }
.ds-overlay-text { margin: 10px 0 16px; font-size: 12px; color: #9ec2e6; max-width: 420px; }

.ds-drawer-body { color: #d7e6f7; padding: 4px 2px; }
.ds-drawer-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.ds-drawer-name { font-size: 16px; font-weight: 700; }
.ds-drawer-ip { font-size: 12px; color: #7f9bc0; margin-top: 4px; font-variant-numeric: tabular-nums; }
.ds-drawer-kind {
  padding: 2px 10px; border-radius: 12px; font-size: 11px;
  border: 1px solid rgba(53, 160, 255, 0.35); color: #6dc6ff;
}
.ds-drawer-kind.external { color: #ff7b86; border-color: rgba(255, 77, 94, 0.45); }
.ds-drawer-kind.asset { color: #2ee6a8; border-color: rgba(46, 230, 168, 0.45); }
.ds-drawer-section { margin-top: 18px; }
.ds-drawer-title { font-size: 12px; color: #9ec2e6; margin-bottom: 8px; }
.ds-drawer-list { margin: 0; font-size: 12px; }
.ds-drawer-list > div { display: flex; justify-content: space-between; gap: 12px; padding: 5px 0; border-bottom: 1px dashed rgba(53, 160, 255, 0.14); }
.ds-drawer-list dt { color: #7f9bc0; }
.ds-drawer-list dd { margin: 0; color: #dbeaf9; text-align: right; word-break: break-all; }
.ds-drawer-metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.ds-drawer-metrics > div {
  padding: 8px 10px; border-radius: 6px; font-size: 11px; color: #7f9bc0;
  background: rgba(20, 52, 88, 0.5); border: 1px solid rgba(53, 160, 255, 0.14);
}
.ds-drawer-metrics span {
  display: block; font-size: 18px; font-weight: 700; color: #eaf4ff; font-variant-numeric: tabular-nums;
}
.ds-drawer-action {
  margin-top: 20px; width: 100%; padding: 8px 0; border-radius: 6px; cursor: pointer;
  font-size: 12px; color: #06182c; border: none;
  background: linear-gradient(180deg, #6dc6ff, #35a0ff);
}
.ds-drawer-note { margin-top: 10px; font-size: 11px; color: #5b7799; text-align: center; }
</style>

<style>
/* The drawer is teleported out of the frame, so its dark surface is set here
   rather than through the scoped block. */
.ds-drawer { background: #0b1e36 !important; border-left: 1px solid rgba(53, 160, 255, 0.25); }
.ds-drawer .el-drawer__body { padding: 18px; }
</style>
