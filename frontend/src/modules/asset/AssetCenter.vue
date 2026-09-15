<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { listAssets, getAsset } from '../../api/assets'
import { listProbes } from '../../api/probes'
import { startScan, getScan, type ScanResult } from '../../api/scan'
import type { Asset, AssetDetail } from '../../types/asset'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import AssetCard from '../../components/security/AssetCard.vue'
import AttackGraph from '../../components/security/AttackGraph.vue'
import EvidenceViewer from '../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import { formatDateTime, formatRiskScore } from '../../utils/format'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const items = ref<Asset[]>([])
const total = ref(0)
const detail = ref<AssetDetail | null>(null)
const drawer = ref(false)
const detailLoading = ref(false)
const activeTab = ref('basic')
const filters = reactive({ risk: '', asset_type: '', search: '', page: 1, page_size: 50 })
const scanTarget = ref('')
const scanTopPorts = ref(200)
const scanPorts = ref('')
const scanSource = ref<'platform' | 'probe'>('platform')
const scanProbeId = ref<number | null>(null)
const scanNuclei = ref(false)
const scanNucleiTags = ref('')
const scanning = ref(false)
const scanProgress = ref(0)
const scanStage = ref('')
const scanResult = ref<ScanResult | null>(null)
const probes = ref<Array<{ id: number; name: string; ip_address: string; status: string }>>([])

const scanSummary = computed(() => {
  const info = (scanResult.value?.result || {}) as { assets?: number; alive_hosts?: number; engine?: string; hosts?: string[] }
  return {
    assets: info.assets ?? 0,
    hosts: info.alive_hosts ?? info.hosts?.length ?? 0,
    engine: info.engine || '',
  }
})

function parsePorts(): number[] {
  return scanPorts.value
    .split(/[,\s]+/)
    .map((item) => Number.parseInt(item, 10))
    .filter((item) => Number.isInteger(item) && item > 0 && item <= 65535)
}

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索 IP/主机/服务', placeholder: '搜索 IP / 主机 / 服务', width: '240px' },
  { key: 'risk', label: '风险', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'asset_type', label: '类型', type: 'select', options: ['server', 'workstation', 'database', 'network', 'unknown'].map((v) => ({ label: v, value: v })), width: '130px' },
]

const graphNodes = computed(() => {
  if (!detail.value) return []
  const nodes = [{ id: `asset:${detail.value.asset.id}`, name: detail.value.asset.ip, type: 'host', risk: detail.value.asset.risk_level }]
  detail.value.data_assets.forEach((d) => nodes.push({ id: `data:${d.id}`, name: d.name, type: 'data_asset', risk: d.sensitivity }))
  detail.value.iocs.forEach((i) => nodes.push({ id: `ioc:${i.id}`, name: i.value, type: 'ioc', risk: 'High' }))
  detail.value.incidents.forEach((inc) => nodes.push({ id: `incident:${inc.id}`, name: inc.title, type: 'incident', risk: inc.risk_level }))
  return nodes
})
const graphEdges = computed(() => {
  if (!detail.value) return []
  const edges: Array<{ source: string; target: string; label?: string }> = []
  const root = `asset:${detail.value.asset.id}`
  detail.value.data_assets.forEach((d) => edges.push({ source: root, target: `data:${d.id}`, label: 'data' }))
  detail.value.iocs.forEach((i) => edges.push({ source: root, target: `ioc:${i.id}`, label: 'ioc' }))
  detail.value.incidents.forEach((inc) => edges.push({ source: root, target: `incident:${inc.id}`, label: 'incident' }))
  return edges
})

const TERMINAL_STATUSES = ['Success', 'Partial', 'Failed', 'Failure']

async function runScan(): Promise<void> {
  if (!scanTarget.value) { ElMessage.warning('请填写扫描目标'); return }
  if (scanSource.value === 'probe' && !scanProbeId.value) { ElMessage.warning('请选择执行扫描的探针'); return }
  scanning.value = true
  scanResult.value = null
  scanProgress.value = 0
  scanStage.value = '下发扫描任务'
  try {
    const task = await startScan({
      target: scanTarget.value.trim(),
      discovery: scanTarget.value.includes('/') || scanTarget.value.includes('-'),
      top_ports: scanTopPorts.value,
      ports: parsePorts(),
      probe_id: scanSource.value === 'probe' && scanProbeId.value ? scanProbeId.value : undefined,
      nuclei: scanSource.value === 'platform' && scanNuclei.value,
      nuclei_tags: scanNucleiTags.value,
    })
    // Probe jobs wait for the probe to poll (30s) and finish its own bounded scan.
    const maxPolls = scanSource.value === 'probe' ? 200 : 240
    for (let i = 0; i < maxPolls; i++) {
      await new Promise((r) => setTimeout(r, 3000))
      const cur = await getScan(task.id)
      scanProgress.value = cur.progress ?? scanProgress.value
      scanStage.value = cur.current_stage || scanStage.value
      if (TERMINAL_STATUSES.includes(cur.status)) {
        scanResult.value = cur
        break
      }
    }
    if (!scanResult.value) throw new Error('扫描超时，请稍后在任务中心查看结果')
    if (scanResult.value.status === 'Failed' || scanResult.value.status === 'Failure') {
      throw new Error(scanResult.value.error || '扫描失败')
    }
    if (scanSource.value === 'probe') {
      const info = scanResult.value.result as { assets?: number } | undefined
      ElMessage.success(`探针扫描完成：发现 ${info?.assets ?? 0} 个服务资产`)
    } else {
      const info = scanResult.value.result as { assets?: number; alive_hosts?: number } | undefined
      ElMessage.success(`扫描完成：${info?.alive_hosts ?? 0} 台存活主机，${info?.assets ?? 0} 个服务资产`)
    }
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    scanning.value = false
  }
}

async function loadProbes(): Promise<void> {
  try {
    const result = await listProbes({ page: 1, page_size: 200 })
    probes.value = result.items.map((item) => ({ id: item.id, name: item.name, ip_address: item.ip_address, status: item.status }))
  } catch {
    probes.value = []
  }
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listAssets({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Asset): Promise<void> {
  detailLoading.value = true
  activeTab.value = 'basic'
  drawer.value = true
  try {
    detail.value = await getAsset(row.id)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    detailLoading.value = false
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(() => { load(); loadProbes() })
</script>

<template>
  <div>
    <div class="soc-card" style="margin-bottom: 12px">
      <div class="soc-card-title"><span class="dot info" />网络扫描（存活发现 + 端口/服务枚举）</div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center">
        <el-select v-model="scanSource" style="width: 150px">
          <el-option value="platform" label="平台扫描" />
          <el-option value="probe" label="探针扫描" />
        </el-select>
        <el-select v-if="scanSource === 'probe'" v-model="scanProbeId" placeholder="选择探针" style="width: 200px" filterable>
          <el-option v-for="p in probes" :key="p.id" :value="p.id" :label="`${p.name} (${p.ip_address || '未知IP'})`" />
        </el-select>
        <el-input v-model="scanTarget" placeholder="目标：IP / 主机 / CIDR / 范围，如 192.168.110.0/24" style="width: 320px" clearable />
        <el-input-number v-model="scanTopPorts" :min="1" :max="65535" :step="50" style="width: 130px" />
        <el-input v-model="scanPorts" placeholder="指定端口（可选），如 22,80,443,3306" style="width: 220px" clearable />
        <el-switch v-if="scanSource === 'platform'" v-model="scanNuclei" active-text="Nuclei" />
        <el-input v-if="scanSource === 'platform' && scanNuclei" v-model="scanNucleiTags" placeholder="nuclei tags，如 tech,cve" style="width: 180px" clearable />
        <el-button type="primary" :loading="scanning" @click="runScan">开始扫描</el-button>
        <span class="text-muted" style="font-size: 12px">平台扫描使用 nmap（-Pn，带 TCP-connect 兜底）；探针扫描由目标网段内的探针执行</span>
      </div>
      <el-progress v-if="scanning" :percentage="scanProgress" :stroke-width="10" style="margin-top: 10px" />
      <div v-if="scanning" class="text-muted" style="font-size: 12px; margin-top: 4px">{{ scanStage }}</div>
      <div v-if="scanResult" style="margin-top: 8px">
        <el-tag v-if="scanResult.status === 'Success' || scanResult.status === 'Partial'" :type="scanResult.status === 'Success' ? 'success' : 'warning'" size="small">
          {{ scanResult.location === 'probe' ? '探针' : '平台' }}扫描{{ scanResult.status === 'Partial' ? '部分完成' : '完成' }}：
          存活主机 {{ scanSummary.hosts }} 台，服务资产 {{ scanSummary.assets }} 个
        </el-tag>
        <el-tag v-else type="danger" size="small">扫描失败：{{ scanResult.error }}</el-tag>
        <span v-if="scanSummary.engine" class="text-muted" style="font-size: 12px; margin-left: 8px">引擎 {{ scanSummary.engine }}</span>
        <div v-if="scanResult.scanned_assets?.length" style="margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap">
          <el-tag v-for="a in scanResult.scanned_assets" :key="a.id" size="small" effect="plain">{{ a.ip }}:{{ a.port }} {{ a.service }} ({{ a.asset_type }})</el-tag>
        </div>
      </div>
    </div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <div class="asset-cards" style="margin-bottom: 12px">
        <div v-for="a in items.slice(0, 8)" :key="a.id" class="asset-card-wrap" @click="open(a)">
          <AssetCard :asset="a" />
        </div>
      </div>
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="hostname" label="主机名" min-width="150" show-overflow-tooltip />
        <el-table-column prop="os" label="操作系统" width="130" />
        <el-table-column label="服务" min-width="140"><template #default="{ row }"><span class="mono">{{ row.service }}:{{ row.port }} ({{ row.protocol }})</span></template></el-table-column>
        <el-table-column prop="asset_type" label="类型" width="110" />
        <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :level="row.risk_level" /></template></el-table-column>
        <el-table-column label="敏感类目" width="110"><template #default="{ row }">{{ row.sensitive_categories?.length || 0 }}</template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="资产详情" width="66%">
      <StateBox v-if="detail" :loading="detailLoading" :empty="false">
        <el-tabs v-model="activeTab">
          <el-tab-pane label="基础" name="basic">
            <el-descriptions :column="3" border size="small">
              <el-descriptions-item label="IP"><span class="mono">{{ detail.asset.ip }}</span></el-descriptions-item>
              <el-descriptions-item label="主机名">{{ detail.asset.hostname }}</el-descriptions-item>
              <el-descriptions-item label="操作系统">{{ detail.asset.os }}</el-descriptions-item>
              <el-descriptions-item label="类型">{{ detail.asset.asset_type }}</el-descriptions-item>
              <el-descriptions-item label="风险"><RiskBadge :level="detail.asset.risk_level" /></el-descriptions-item>
              <el-descriptions-item label="首次发现">{{ formatDateTime(detail.asset.first_seen) }}</el-descriptions-item>
              <el-descriptions-item label="最近发现">{{ formatDateTime(detail.asset.last_seen) }}</el-descriptions-item>
            </el-descriptions>
          </el-tab-pane>
          <el-tab-pane label="服务 / 端口" name="services">
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="服务">{{ detail.asset.service }}</el-descriptions-item>
              <el-descriptions-item label="端口"><span class="mono">{{ detail.asset.port }}/{{ detail.asset.protocol }}</span></el-descriptions-item>
            </el-descriptions>
          </el-tab-pane>
          <el-tab-pane label="风险" name="risk">
            <div class="sec-title">关联检测</div>
            <el-table :data="detail.findings" size="small">
              <el-table-column prop="id" label="ID" width="70" />
              <el-table-column prop="engine" label="引擎" width="120" />
              <el-table-column prop="rule_id" label="规则" min-width="140" show-overflow-tooltip />
              <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
              <el-table-column label="风险" width="70"><template #default="{ row }"><span class="mono">{{ formatRiskScore(row.risk_score) }}</span></template></el-table-column>
            </el-table>
            <div class="sec-title" style="margin-top: 12px">关联事件</div>
            <el-table :data="detail.incidents" size="small">
              <el-table-column prop="id" label="ID" width="70" />
              <el-table-column prop="title" label="标题" min-width="180" />
              <el-table-column label="状态" width="110"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="数据" name="data">
            <el-table :data="detail.data_assets" size="small">
              <el-table-column prop="name" label="名称" min-width="160" />
              <el-table-column prop="asset_type" label="类型" width="120" />
              <el-table-column label="敏感度" width="90"><template #default="{ row }"><RiskBadge :level="row.sensitivity" /></template></el-table-column>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="IOC" name="ioc">
            <el-table :data="detail.iocs" size="small">
              <el-table-column prop="value" label="值" min-width="160" />
              <el-table-column prop="type" label="类型" width="100" />
              <el-table-column prop="source" label="来源" width="120" />
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="关系图" name="graph">
            <AttackGraph :nodes="graphNodes" :edges="graphEdges" :height="480" />
          </el-tab-pane>
        </el-tabs>
      </StateBox>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
.asset-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
@media (max-width: 1200px) { .asset-cards { grid-template-columns: repeat(2, 1fr); } }
</style>
