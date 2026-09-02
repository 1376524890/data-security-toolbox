<script setup lang="ts">
import { computed } from 'vue'
import type { DetectionFinding } from '../types/finding'
import type { Incident } from '../types/incident'
import SeverityBadge from './SeverityBadge.vue'
import RiskScore from './RiskScore.vue'
import EvidenceViewer from './EvidenceViewer.vue'
import JsonViewer from './JsonViewer.vue'
import { formatDateTime } from '../utils/format'

const props = defineProps<{
  modelValue: boolean
  finding?: DetectionFinding | null
  relatedIncidents?: Incident[]
}>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; openIncident: [incident: Incident] }>()

const visible = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit('update:modelValue', value),
})
</script>

<template>
  <el-drawer v-model="visible" title="Finding 详情" size="48%">
    <template v-if="finding">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="Engine">{{ finding.engine }}</el-descriptions-item>
        <el-descriptions-item label="Rule">{{ finding.rule_id }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatDateTime(finding.timestamp) }}</el-descriptions-item>
        <el-descriptions-item label="Severity"><SeverityBadge :value="finding.severity" /></el-descriptions-item>
        <el-descriptions-item label="置信度">{{ (finding.confidence * 100).toFixed(0) }}%</el-descriptions-item>
        <el-descriptions-item label="Target">{{ finding.target_type }} / {{ finding.target_id }}</el-descriptions-item>
      </el-descriptions>
      <el-divider content-position="left">风险</el-divider>
      <div class="risk-row"><RiskScore :score="finding.risk_score" :level="finding.risk_level" /></div>
      <el-divider content-position="left">证据</el-divider>
      <EvidenceViewer :evidence="finding.evidence" />
      <el-divider content-position="left">建议</el-divider>
      <el-alert type="warning" :closable="false" :title="finding.recommendation || '无整改建议'" />
      <el-divider content-position="left">关联事件</el-divider>
      <el-empty v-if="!relatedIncidents?.length" description="暂无关联事件" />
      <el-table v-else :data="relatedIncidents" size="small">
        <el-table-column prop="title" label="事件" />
        <el-table-column prop="severity" label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column>
        <el-table-column label="风险" width="100"><template #default="{ row }"><RiskScore :score="row.risk_score" /></template></el-table-column>
        <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="$emit('openIncident', row)">打开</el-button></template></el-table-column>
      </el-table>
      <el-divider content-position="left">原始数据</el-divider>
      <JsonViewer :value="finding" title="查看 Finding JSON" />
    </template>
  </el-drawer>
</template>

<style scoped>
.risk-row { display: flex; align-items: center; }
</style>
