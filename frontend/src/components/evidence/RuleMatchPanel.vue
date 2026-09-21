<script setup lang="ts">
import { computed } from 'vue'
import type { DetectionFinding } from '../../types/finding'
import type { RuleDefinition } from '../../types/alert'
import SeverityTag from '../security/SeverityTag.vue'
import JsonViewer from './JsonViewer.vue'
import RawViewer from './RawViewer.vue'
import { maskSensitiveValue } from '../../utils/mask'

const props = defineProps<{ rule?: RuleDefinition | null; finding?: DetectionFinding | null }>()

// Field names are shown in Chinese next to the raw key, so an operator reads
// "端口数 (port_count)" and can still match it to the rule condition text.
const keyLabels: Record<string, string> = {
  rule: '命中规则', condition: '命中条件', count: '命中次数', window: '统计窗口(秒)', threshold: '告警阈值',
  port_count: '端口数', dst_count: '目标数', src_count: '来源数', flow_count: '会话数',
  packet_count: '报文数', packet_rate: '包速率', total_bytes: '总字节', rolling: '滚动检测',
  src: '源地址', dst: '目标地址', src_ip: '源 IP', dst_ip: '目标 IP', src_port: '源端口', dst_port: '目标端口',
  dst_ports: '目标端口', ip: 'IP', port: '端口', protocol: '协议', service: '服务', services: '命中服务',
  hostname: '主机名', host: '主机', os: '操作系统', url: 'URL', method: '请求方法',
  filename: '文件名', file: '文件', content_type: '内容类型', size: '大小(字节)', length: '长度',
  sha256: 'SHA256', md5: 'MD5', id: '对象 ID', complete: '会话完整',
  matches: '敏感数据命中明细', kind: '匹配类型', entity: '识别实体', confidence: '置信度',
  samples: '命中样本(已脱敏)', sensitive: '判定为敏感',
  context: '上下文原文', triggered_by: '触发规则类型', rule_ids: '命中规则 ID',
  rule_source: '规则来源', rule_sources: '命中规则来源', action: '处置动作', mode: '检测模式',
  queries: 'DNS 查询', queried: '查询域名', resp_len: '响应长度', txt: 'TXT 记录',
  matched_iocs: '命中威胁情报', ioc: '情报指标', value: '值', type: '类型',
  tactic: '战术', technique: '技术', technique_id: '技术 ID', record: '记录', risk_model: '风险模型',
}
const noiseKeys = ['probe_id', 'risk_model', 'rule_snapshot']

const evidence = computed<Record<string, unknown>>(() => (props.finding?.evidence || {}) as Record<string, unknown>)
const ruleName = computed(() => props.rule?.title || String(evidence.value.rule || props.finding?.rule_id || '-'))
const conditionText = computed(() => {
  if (props.rule?.condition) return props.rule.condition
  if (typeof evidence.value.condition === 'string') return evidence.value.condition
  const detection = evidence.value.detection
  return detection && typeof detection === 'object' ? JSON.stringify(detection) : ''
})
const recommendation = computed(() => props.rule?.recommendation || props.finding?.recommendation || '')
const sourceFile = computed(() => props.rule?.file || '')
const confidence = computed(() => {
  const value = props.finding?.confidence
  return value == null ? '-' : `${(value * 100).toFixed(0)}%`
})

function label(key: string): string {
  return keyLabels[key] ? `${keyLabels[key]} (${key})` : key
}

function isPrimitive(value: unknown): boolean {
  return value === null || value === undefined || ['string', 'number', 'boolean'].includes(typeof value)
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (Array.isArray(value)) return value.map((item) => formatValue(item)).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return maskSensitiveValue(String(value))
}

// Scalar evidence is the concrete match: the values the rule condition was
// evaluated against.
const scalarRows = computed(() =>
  Object.entries(evidence.value)
    .filter(([key, value]) => !noiseKeys.includes(key) && isPrimitive(value) && value !== '')
    .map(([key, value]) => ({ key, label: label(key), value: formatValue(value) })),
)

interface MatchGroup {
  key: string
  label: string
  kind: 'table' | 'tags' | 'json'
  rows: Array<Record<string, unknown>>
  columns: Array<{ key: string; label: string }>
  tags: string[]
  total: number
}

const matchGroups = computed<MatchGroup[]>(() =>
  Object.entries(evidence.value)
    .filter(([key, value]) => !noiseKeys.includes(key) && !isPrimitive(value) && value !== null && value !== undefined)
    .map(([key, value]) => {
      if (Array.isArray(value)) {
        const objects = value as Array<Record<string, unknown>>
        if (value.length && value.every((item) => item !== null && typeof item === 'object' && !Array.isArray(item))) {
          const columns = Array.from(new Set(objects.slice(0, 8).flatMap((item) => Object.keys(item)))).slice(0, 6).map((col) => ({ key: col, label: label(col) }))
          return { key, label: label(key), kind: 'table' as const, rows: objects, columns, tags: [], total: value.length }
        }
        const tags = (value as unknown[]).slice(0, 60).map((item) => formatValue(item))
        return { key, label: label(key), kind: 'tags' as const, rows: [], columns: [], tags, total: value.length }
      }
      return { key, label: label(key), kind: 'json' as const, rows: [], columns: [], tags: [], total: 1 }
    })
    .filter((group) => group.kind !== 'table' || group.columns.length > 0),
)
</script>

<template>
  <div class="rmp">
    <div class="rmp-block">
      <div class="sec-title">命中规则</div>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item label="引擎"><span class="mono">{{ finding?.engine || rule?.engine || '-' }}</span></el-descriptions-item>
        <el-descriptions-item label="规则 ID"><span class="mono">{{ finding?.rule_id || rule?.rule_id || '-' }}</span></el-descriptions-item>
        <el-descriptions-item label="规则名称">{{ ruleName }}</el-descriptions-item>
        <el-descriptions-item label="等级"><SeverityTag :value="finding?.severity || rule?.severity || 'Low'" /></el-descriptions-item>
        <el-descriptions-item label="置信度"><span class="mono">{{ confidence }}</span></el-descriptions-item>
        <el-descriptions-item label="目标"><span class="mono">{{ finding?.target_type }} / {{ finding?.target_id }}</span></el-descriptions-item>
      </el-descriptions>
      <div class="rmp-line"><span class="rmp-label">命中条件</span><span class="mono">{{ conditionText || '（该规则无显式条件表达式）' }}</span></div>
      <div class="rmp-line"><span class="rmp-label">处置建议</span><span>{{ recommendation || '-' }}</span></div>
      <div class="rmp-line"><span class="rmp-label">规则来源</span><span class="mono">{{ sourceFile || '引擎内置规则（无规则文件）' }}</span></div>
      <div class="rmp-line"><span class="rmp-label">规则版本</span><span>{{ rule?.resolution === 'matched_snapshot' ? '检测时快照' : '当前定义（历史记录无快照）' }}</span></div>
      <el-collapse v-if="rule?.content">
        <el-collapse-item title="查看规则原文" name="src">
          <RawViewer :value="rule.content" :language="rule.type === 'yara' ? 'plaintext' : 'yaml'" :height="240" />
        </el-collapse-item>
      </el-collapse>
    </div>

    <div class="rmp-block">
      <div class="sec-title">命中内容</div>
      <el-descriptions v-if="scalarRows.length" :column="2" border size="small">
        <el-descriptions-item v-for="row in scalarRows" :key="row.key" :label="row.label"><span class="mono">{{ row.value }}</span></el-descriptions-item>
      </el-descriptions>
      <template v-for="group in matchGroups" :key="group.key">
        <div class="rmp-sub">{{ group.label }} · 共 {{ group.total }} 条</div>
        <el-table v-if="group.kind === 'table'" :data="group.rows" size="small" max-height="280">
          <el-table-column v-for="col in group.columns" :key="col.key" :label="col.label" min-width="120" show-overflow-tooltip>
            <template #default="{ row }"><span class="mono">{{ formatValue(row[col.key]) }}</span></template>
          </el-table-column>
        </el-table>
        <div v-else-if="group.kind === 'tags'" class="rmp-tags">
          <el-tag v-for="(tag, index) in group.tags" :key="index" size="small" effect="plain">{{ tag }}</el-tag>
          <span v-if="group.total > group.tags.length" class="text-dim">…还有 {{ group.total - group.tags.length }} 项</span>
        </div>
        <JsonViewer v-else :value="evidence[group.key]" :title="group.label" :height="200" />
      </template>
      <div v-if="!scalarRows.length && !matchGroups.length" class="text-dim">该检测未提供结构化证据。</div>
    </div>
  </div>
</template>

<style scoped>
.rmp { display: flex; flex-direction: column; gap: 14px; }
.rmp-block { display: flex; flex-direction: column; gap: 8px; }
.rmp-line { display: flex; gap: 10px; font-size: 12px; color: var(--soc-text-muted); }
.rmp-line > span:last-child { min-width: 0; overflow-wrap: anywhere; }
.rmp-label { color: var(--soc-text-dim); min-width: 62px; }
.rmp-sub { margin-top: 6px; font-size: 12px; color: var(--soc-text-strong); }
.rmp-tags { display: flex; flex-wrap: wrap; gap: 6px; max-height: 180px; overflow: auto; }
</style>
