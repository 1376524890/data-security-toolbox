<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import { formatDateTime } from '../../utils/format'
import { useNetworkAssets } from './composables/useNetworkAssets'

// 网络资产: the port scan result as a standing inventory. Every row is one
// scanned service with its fingerprint and the CVEs matched against it; the
// state (filters, paging, the CVE drawer and the honest "why is this empty"
// answer) lives in the composable.
const {
  loading, error, items, summary, total, page, pageSize, filters, drawer, selected,
  cves, emptyCveReason, load, search, setPage, open,
} = useNetworkAssets()

function confirmedLabel(row: { confirmed: boolean }): string {
  return row.confirmed ? '已确认' : '线索'
}
</script>

<template>
  <div>
    <div class="toolbar">
      <el-input v-model="filters.search" placeholder="IP / 服务 / 产品 / 版本" clearable
                style="width: 240px" @keyup.enter="search" @clear="search" />
      <el-select v-model="filters.severity" placeholder="漏洞等级" clearable style="width: 130px" @change="search">
        <el-option v-for="value in ['Critical', 'High', 'Medium', 'Low']" :key="value" :label="value" :value="value" />
      </el-select>
      <el-select v-model="filters.source" placeholder="来源" clearable style="width: 150px" @change="search">
        <el-option v-for="value in ['platform_scan', 'probe_scan', 'nmap_scan']" :key="value" :label="value" :value="value" />
      </el-select>
      <el-checkbox v-model="filters.only_vulnerable" @change="search">只看命中漏洞</el-checkbox>
      <el-button @click="search">查询</el-button>
      <div class="toolbar-spacer" />
      <span class="muted">扫描结果来自任务中心的「检查任务」下发</span>
      <el-button @click="load">刷新</el-button>
    </div>

    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="stat-grid cols-5">
        <StatCard label="扫描主机" :value="summary?.hosts ?? 0" sub="有开放服务的存活主机" />
        <StatCard label="开放服务" :value="summary?.services ?? 0" sub="端口级资产行" />
        <StatCard label="存在漏洞主机" :value="summary?.vulnerable_hosts ?? 0"
                  :sub="`分母 ${summary?.hosts ?? 0}`" tone="danger" />
        <StatCard label="匹配 CVE" :value="summary?.cves ?? 0" sub="去重后的漏洞编号" tone="warning" />
        <StatCard label="已确认命中" :value="summary?.confirmed_hits ?? 0"
                  sub="版本落在受影响范围内" tone="danger" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot danger" />端口扫描与漏洞匹配</div>
        <el-table :data="items" size="small" @row-click="open">
          <el-table-column prop="ip" label="IP" width="140" />
          <el-table-column prop="port" label="端口" width="80" />
          <el-table-column prop="service" label="服务" width="110" />
          <el-table-column label="指纹（产品 / 版本）" min-width="220">
            <template #default="{ row }">
              <span v-if="row.product || row.version">{{ row.product || '-' }} {{ row.version }}</span>
              <span v-else class="muted">未识别</span>
            </template>
          </el-table-column>
          <el-table-column prop="source" label="来源" width="130" />
          <el-table-column label="端口风险" width="100">
            <template #default="{ row }"><RiskBadge :level="row.risk_level" /></template>
          </el-table-column>
          <el-table-column label="CVE 命中" min-width="280">
            <template #default="{ row }">
              <el-tag v-for="cve in row.cves.slice(0, 4)" :key="cve.rule_id" size="small"
                      :type="cve.confirmed ? 'danger' : 'info'" style="margin: 2px">
                {{ cve.cve_id || cve.rule_id }}{{ cve.confirmed ? '' : '（线索）' }}
              </el-tag>
              <span v-if="row.cve_count > 4" class="muted">等 {{ row.cve_count }} 条</span>
              <span v-else-if="!row.cve_count" class="muted">未命中</span>
            </template>
          </el-table-column>
          <el-table-column prop="last_seen" label="最近发现" width="160">
            <template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!items.length"
                  description="尚无扫描结果；在任务中心新建「检查任务」后自动产生" />
        <div v-if="summary && !summary.cves && emptyCveReason" class="note">{{ emptyCveReason }}</div>
        <el-pagination v-if="total > pageSize" class="pagination" :current-page="page"
                       :page-size="pageSize" :total="total" layout="total, prev, pager, next"
                       @current-change="setPage" />
      </div>
    </StateBox>

    <el-drawer v-model="drawer" title="端口漏洞匹配详情" size="60%">
      <template v-if="selected">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="目标">{{ selected.ip }}:{{ selected.port }}</el-descriptions-item>
          <el-descriptions-item label="服务">{{ selected.service }} / {{ selected.protocol }}</el-descriptions-item>
          <el-descriptions-item label="产品">{{ selected.product || '-' }}</el-descriptions-item>
          <el-descriptions-item label="版本">{{ selected.version || '-' }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ selected.source }}</el-descriptions-item>
          <el-descriptions-item label="端口风险">{{ selected.risk_level }}</el-descriptions-item>
        </el-descriptions>
        <div v-if="selected.banner" class="section-title">服务横幅</div>
        <pre v-if="selected.banner" class="banner">{{ selected.banner }}</pre>

        <div class="section-title">CVE 匹配结果</div>
        <el-table :data="cves" size="small" empty-text="该端口未匹配到任何 CVE">
          <el-table-column label="CVE" width="190">
            <template #default="{ row }">
              <!-- A lead has no single CVE behind it; show the rule it came
                   from instead of an empty cell. -->
              {{ row.cve_id || row.rule_id }}
            </template>
          </el-table-column>
          <el-table-column label="判定" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.confirmed ? 'danger' : 'info'">{{ confirmedLabel(row) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="severity" label="等级" width="90" />
          <el-table-column prop="cvss_score" label="CVSS" width="80" />
          <el-table-column prop="match_reason" label="匹配依据" min-width="150" />
          <el-table-column prop="library_source" label="规则来源" width="110" />
          <el-table-column prop="recommendation" label="处置建议" min-width="220" show-overflow-tooltip />
        </el-table>
        <el-alert type="info" :closable="false" style="margin-top: 10px"
                  title="「线索」= 关键字命中但规则未声明受影响版本范围，不计入已确认漏洞；「已确认」= 版本落在规则声明的范围内。" />
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; }
.note { color: var(--soc-text-dim); font-size: 12px; margin-top: 8px; line-height: 1.6; }
.section-title { font-weight: 600; margin: 14px 0 8px; }
.banner { background: var(--soc-bg-soft, #1b1f27); padding: 8px; border-radius: 4px; font-size: 12px; white-space: pre-wrap; }
:deep(.el-table__row) { cursor: pointer; }
</style>
