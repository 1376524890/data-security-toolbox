<script setup lang="ts">
import { computed } from 'vue'
import type { Incident } from '../types/incident'
import type { DetectionFinding } from '../types/finding'
import SeverityBadge from './SeverityBadge.vue'
import RiskScore from './RiskScore.vue'
import Timeline from './Timeline.vue'
import EvidenceViewer from './EvidenceViewer.vue'
import JsonViewer from './JsonViewer.vue'
import { formatDateTime } from '../utils/format'

const props = defineProps<{
  modelValue: boolean
  incident?: Incident | null
}>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; openFinding: [finding: DetectionFinding] }>()

const visible = computed({ get: () => props.modelValue, set: (value: boolean) => emit('update:modelValue', value) })
const findings = computed<DetectionFinding[]>(() => props.incident?.findings?.items || [])
const stages = computed<string[]>(() => {
  const value = props.incident?.evidence?.stages
  return Array.isArray(value) ? value.map(String) : []
})
</script>

<template>
  <el-drawer v-model="visible" title="安全事件详情" size="52%">
    <template v-if="incident">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="标题">{{ incident.title }}</el-descriptions-item>
        <el-descriptions-item label="Severity"><SeverityBadge :value="incident.severity" /></el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatDateTime(incident.timestamp) }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ incident.status }}</el-descriptions-item>
        <el-descriptions-item label="置信度">{{ (incident.confidence * 100).toFixed(0) }}%</el-descriptions-item>
        <el-descriptions-item label="风险"><RiskScore :score="incident.risk_score" :level="incident.risk_level" /></el-descriptions-item>
      </el-descriptions>
      <el-divider content-position="left">攻击时间线</el-divider>
      <Timeline :stages="stages" />
      <el-divider content-position="left">关联 Finding</el-divider>
      <el-table :data="findings" size="small">
        <el-table-column prop="timestamp" label="时间"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
        <el-table-column prop="engine" label="Engine" />
        <el-table-column prop="rule_id" label="规则" />
        <el-table-column prop="severity" label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column>
        <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="$emit('openFinding', row)">查看</el-button></template></el-table-column>
      </el-table>
      <el-divider content-position="left">证据</el-divider>
      <EvidenceViewer :evidence="incident.evidence" />
      <el-divider content-position="left">原始数据</el-divider>
      <JsonViewer :value="incident" title="查看 Incident JSON" />
    </template>
  </el-drawer>
</template>
