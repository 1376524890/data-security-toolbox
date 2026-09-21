<script setup lang="ts">
import type { ScanDetail } from '../../../api/databaseConnections'
import { reasonLabel, statusType } from '../databaseConnectionPresentation'

const open = defineModel<boolean>({ required: true })
defineProps<{ scanDetail: ScanDetail | null }>()
</script>

<template>
  <el-drawer v-model="open" title="数据库采集详情" size="820px">
    <div v-if="!scanDetail">加载中…</div>
    <template v-else>
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="任务">#{{ scanDetail.id }}（{{ scanDetail.kind }}）</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag size="small" :type="statusType(scanDetail.status)">{{ scanDetail.status }}</el-tag>
          {{ scanDetail.progress }}%
        </el-descriptions-item>
        <el-descriptions-item label="阶段">{{ scanDetail.current_stage }}</el-descriptions-item>
        <el-descriptions-item label="服务器版本">{{ scanDetail.summary.server_version || '—' }}</el-descriptions-item>
        <el-descriptions-item label="目标">
          <code class="key">{{ scanDetail.summary.host }}:{{ scanDetail.summary.port }} / {{ scanDetail.summary.database || '(默认库)' }}</code>
        </el-descriptions-item>
        <el-descriptions-item label="配置快照">{{ scanDetail.summary.config_hash }}</el-descriptions-item>
        <el-descriptions-item label="表（已读/选中/总数）">
          {{ scanDetail.summary.tables_scanned }} / {{ scanDetail.summary.tables_selected }} / {{ scanDetail.summary.tables_total }}
        </el-descriptions-item>
        <el-descriptions-item label="样本行 / 值">{{ scanDetail.summary.rows_read }} / {{ scanDetail.summary.values_scanned }}</el-descriptions-item>
        <el-descriptions-item label="命中 / 检测">
          {{ scanDetail.summary.hits }} / {{ scanDetail.summary.detections }}
        </el-descriptions-item>
        <el-descriptions-item label="覆盖">
          {{ scanDetail.summary.complete_scope === null ? '—' : scanDetail.summary.complete_scope ? '完整' : '部分' }}
          / {{ reasonLabel(scanDetail.summary.termination_reason) }}
        </el-descriptions-item>
        <el-descriptions-item label="只读会话">{{ scanDetail.summary.read_only ? '已确认只读' : '未确认' }}</el-descriptions-item>
        <el-descriptions-item label="引擎/规则版本">
          {{ scanDetail.summary.engine_version }} / {{ scanDetail.summary.ruleset_version }}
        </el-descriptions-item>
      </el-descriptions>

      <el-alert v-if="scanDetail.error" type="error" :closable="false" show-icon
                style="margin-top: 12px" :title="scanDetail.error" />

      <div class="soc-card-title" style="margin-top: 14px"><span class="dot" />按表结果</div>
      <el-table :data="scanDetail.summary.tables || []" size="small" empty-text="本次没有读取到任何表">
        <el-table-column prop="path" label="表" min-width="260" show-overflow-tooltip />
        <el-table-column prop="rows_read" label="样本行" width="100" />
        <el-table-column prop="values_scanned" label="值" width="90" />
        <el-table-column prop="hits" label="命中" width="90" />
        <el-table-column prop="detections" label="检测" width="90" />
        <el-table-column label="命中类型" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ (row.categories || []).join('、') || '无' }}</template>
        </el-table-column>
        <el-table-column label="仅字段名线索" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ (row.candidates || []).join('、') || '无' }}</template>
        </el-table-column>
      </el-table>

      <template v-if="(scanDetail.summary.table_errors || []).length">
        <div class="soc-card-title" style="margin-top: 14px"><span class="dot" />读取失败的表</div>
        <ul class="notes">
          <li v-for="(item, index) in scanDetail.summary.table_errors || []" :key="index">
            <span class="danger-text">{{ item.path }}</span>：{{ item.error }}
          </li>
        </ul>
      </template>

      <template v-if="(scanDetail.summary.notes || []).length">
        <div class="soc-card-title" style="margin-top: 14px"><span class="dot" />执行说明</div>
        <ul class="notes">
          <li v-for="(line, index) in scanDetail.summary.notes" :key="index">{{ line }}</li>
        </ul>
      </template>
    </template>
  </el-drawer>
</template>

<style scoped>
.key { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.danger-text { color: #ef4444; }
.notes { margin: 6px 0 0; padding-left: 18px; color: var(--soc-text-dim); font-size: 12px; line-height: 1.7; }
</style>
