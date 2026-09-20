<script setup lang="ts">
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
import { useAssetCenter } from './composables/useAssetCenter'

// The list, the detail drawer and the network-scan console live in the
// composable; this view only keeps the filter fields and the formatting
// helpers the template binds to.
const {
  loading, error, items, total, detail, drawer, detailLoading, activeTab, filters,
  scanTarget, scanTopPorts, scanPorts, scanSource, scanProbeId, scanNuclei, scanNucleiTags,
  scanning, scanProgress, scanStage, scanResult, probes, scanSummary, graphNodes, graphEdges,
  load, open, runScan, reset,
} = useAssetCenter()

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索 IP/主机/服务', placeholder: '搜索 IP / 主机 / 服务', width: '240px' },
  { key: 'risk', label: '风险', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'asset_type', label: '类型', type: 'select', options: ['server', 'workstation', 'database', 'network', 'unknown'].map((v) => ({ label: v, value: v })), width: '130px' },
]
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
        <el-switch v-if="scanSource === 'platform'" v-model="scanNuclei" active-text="漏洞检测" />
        <el-input v-if="scanSource === 'platform' && scanNuclei" v-model="scanNucleiTags" placeholder="检测类别，如 tech,cve" style="width: 180px" clearable />
        <el-button type="primary" :loading="scanning" @click="runScan">开始扫描</el-button>
        <span class="text-muted" style="font-size: 12px">自动扫描指定网段，默认检查常用 200 个端口；探针扫描在探针所在网络执行</span>
      </div>
      <el-progress v-if="scanning" :percentage="scanProgress" :stroke-width="10" style="margin-top: 10px" />
      <div v-if="scanning" class="text-muted" style="font-size: 12px; margin-top: 4px">{{ scanStage }}</div>
      <div v-if="scanResult" style="margin-top: 8px">
        <el-tag v-if="scanResult.status === 'Success' || scanResult.status === 'Partial'" :type="scanResult.status === 'Success' ? 'success' : 'warning'" size="small">
          {{ scanResult.location === 'probe' ? '探针' : '平台' }}扫描{{ scanResult.status === 'Partial' ? '部分完成' : '完成' }}：
          存活主机 {{ scanSummary.hosts }} 台，服务资产 {{ scanSummary.assets }} 个
        </el-tag>
        <el-tag v-else type="danger" size="small">扫描失败：{{ scanResult.error }}</el-tag>
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
