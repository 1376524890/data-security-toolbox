<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import DonutChart from '../../components/charts/DonutChart.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import EvidenceViewer from '../../components/evidence/EvidenceViewer.vue'
import { useSensitiveDiscovery } from './composables/useSensitiveDiscovery'

// The findings, the pager and the chart projections live in the composable;
// this view only binds them into the template below.
const {
  loading, error, sensitive, page, pageSize, assets, totals, entityData,
  sensitivityData, sources, load, onPageChange,
} = useSensitiveDiscovery()
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="stat-grid cols-4">
        <StatCard label="数据资产（在位）" :value="assets?.observed.total ?? 0"
                  :sub="`历史未观测 ${assets?.not_observed.total ?? 0} 条，不计入在位`" />
        <StatCard label="敏感检测（文件/网络）" :value="totals?.findings ?? 0" tone="warning"
                  :sub="`全表聚合总数，当前页 ${sensitive?.details.length ?? 0} 条`" />
        <StatCard label="对象检测（探针）" :value="totals?.detections ?? 0" tone="primary"
                  :sub="`对象 ${totals?.objects ?? 0} · 实例 ${totals?.instances ?? 0}`" />
        <StatCard label="敏感实体（对象检测）" :value="totals?.entities ?? 0" tone="danger"
                  :sub="`引擎类目 ${totals?.categories ?? 0}`" />
      </div>
      <div class="grid cols-2" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />敏感实体分布（对象检测）</div>
          <DonutChart :data="entityData" :height="280" />
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />数据敏感度分布（含历史未观测）</div>
          <DonutChart :data="sensitivityData" :height="280" />
          <div class="gap-note">在位资产见上方卡片；此处按全量资产投影统计</div>
        </div>
      </div>
      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />检测来源（分别统计，不跨源相加）</div>
        <el-table :data="sources" size="small">
          <el-table-column prop="source" label="来源" width="170" />
          <el-table-column prop="kind" label="类型" min-width="180" />
          <el-table-column prop="count" label="数量" width="110" />
        </el-table>
        <div class="gap-note">{{ sensitive?.note }}</div>
      </div>
      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot danger" />敏感检测结果</div>
        <el-table :data="sensitive?.details || []" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="engine" label="引擎" width="110" />
          <el-table-column prop="rule_id" label="规则" min-width="150" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
          <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
          <el-table-column label="证据" min-width="200"><template #default="{ row }"><EvidenceViewer :evidence="row.evidence" /></template></el-table-column>
        </el-table>
        <el-pagination background layout="prev, pager, next, total" :current-page="page"
                       :page-size="pageSize" :total="totals?.findings ?? 0"
                       style="margin-top: 8px" @current-change="onPageChange" />
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
