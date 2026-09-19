<script setup lang="ts">
import { computed } from 'vue'
import StateBox from '../../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../../components/common/FilterBar.vue'
import DetailDrawer from '../../../components/common/DetailDrawer.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import RiskBadge from '../../../components/security/RiskBadge.vue'
import EvidenceViewer from '../../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { formatDateTime } from '../../../utils/format'
import { useDetectionCenter } from './composables/useDetectionCenter'

// The list, the detail drawer and the manual pipeline run live in the
// composable; this view keeps the filter fields, which are built from the
// engine names the composable loaded.
const {
  loading, error, items, total, detail, drawer, filters, engineOptions,
  pipelineOpen, pipelineRunning, pipelineForm, pipelineResult,
  load, open, reset, runPipelineNow,
} = useDetectionCenter()

const filterFields = computed<FilterField[]>(() => [
  { key: 'search', label: '搜索 Rule/Engine', placeholder: '搜索 Rule / Engine / 建议', width: '240px' },
  { key: 'severity', label: '等级', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'engine', label: '引擎', type: 'select', options: engineOptions.value, width: '170px' },
])
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions>
        <el-button type="primary" plain @click="pipelineOpen = true"><el-icon><VideoPlay /></el-icon>&nbsp;手动流水线</el-button>
      </template>
    </FilterBar>
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column label="时间" width="160"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
        <el-table-column prop="engine" label="引擎" width="120" />
        <el-table-column prop="rule_id" label="规则" min-width="180" show-overflow-tooltip />
        <el-table-column label="等级" width="100"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
        <el-table-column label="置信度" width="100"><template #default="{ row }"><span class="mono">{{ (row.confidence * 100).toFixed(0) }}%</span></template></el-table-column>
        <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :score="row.risk_score" :level="row.risk_level" /></template></el-table-column>
        <el-table-column label="目标" width="160"><template #default="{ row }"><span class="mono">{{ row.target_type }}:{{ row.target_id }}</span></template></el-table-column>
        <el-table-column prop="recommendation" label="处置建议" min-width="200" show-overflow-tooltip />
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="检测详情" width="60%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="ID"><span class="mono">#{{ detail.detection.id }}</span></el-descriptions-item>
          <el-descriptions-item label="引擎">{{ detail.detection.engine }}</el-descriptions-item>
          <el-descriptions-item label="规则"><span class="mono">{{ detail.detection.rule_id }}</span></el-descriptions-item>
          <el-descriptions-item label="等级"><SeverityTag :value="detail.detection.severity" /></el-descriptions-item>
          <el-descriptions-item label="置信度"><span class="mono">{{ (detail.detection.confidence * 100).toFixed(0) }}%</span></el-descriptions-item>
          <el-descriptions-item label="风险"><RiskBadge :score="detail.detection.risk_score" /></el-descriptions-item>
          <el-descriptions-item label="目标"><span class="mono">{{ detail.detection.target_type }}:{{ detail.detection.target_id }}</span></el-descriptions-item>
          <el-descriptions-item label="时间"><span class="mono">{{ formatDateTime(detail.detection.timestamp) }}</span></el-descriptions-item>
          <el-descriptions-item label="创建时间"><span class="mono">{{ formatDateTime(detail.detection.created_at) }}</span></el-descriptions-item>
        </el-descriptions>
        <div class="drawer-section">
          <div class="sec-title">证据</div>
          <EvidenceViewer :evidence="detail.detection.evidence" />
          <JsonViewer :value="{ detection: detail.detection, related_incidents: detail.related_incidents, alert: detail.alert, pcap: detail.pcap }" title="完整 JSON" :height="280" />
        </div>
      </template>
    </DetailDrawer>

    <el-dialog v-model="pipelineOpen" title="手动触发检测流水线" width="640px">
      <el-form label-width="100px">
        <el-form-item label="目标类型">
          <el-select v-model="pipelineForm.target_type" style="width: 100%">
            <el-option v-for="t in ['log', 'text', 'pcap', 'integration']" :key="t" :label="t" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="日志行">
          <el-input v-model="pipelineForm.log_lines" type="textarea" :rows="6" placeholder="每行一条日志，用于日志/文本检测" />
        </el-form-item>
        <el-form-item label="数据 JSON">
          <el-input v-model="pipelineForm.data" type="textarea" :rows="5" placeholder='可选，如 {"protocol_summary": {"http": 10}}' />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pipelineOpen = false">取消</el-button>
        <el-button type="primary" :loading="pipelineRunning" @click="runPipelineNow">执行</el-button>
      </template>

      <div v-if="pipelineResult" class="pipeline-result">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="引擎数"><span class="mono">{{ pipelineResult.summary?.engine_count ?? '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="发现数"><span class="mono">{{ pipelineResult.summary?.finding_count ?? pipelineResult.findings.length }}</span></el-descriptions-item>
          <el-descriptions-item label="风险评分"><RiskBadge :score="pipelineResult.risk_score" /></el-descriptions-item>
        </el-descriptions>
        <el-table :data="pipelineResult.findings" size="small" style="margin-top: 12px">
          <el-table-column prop="engine" label="引擎" width="120" />
          <el-table-column prop="rule_id" label="规则" min-width="160" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
          <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<style scoped>
.drawer-section { margin-top: 16px; }
.pipeline-result { margin-top: 12px; border-top: 1px solid var(--soc-border); padding-top: 12px; }
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
