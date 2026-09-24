<script setup lang="ts">
import StateBox from '../../../components/common/StateBox.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { formatCoverage, formatDateTime, formatTerminationReason } from '../../../utils/format'
import { useRiskFiles } from '../composables/useRiskFiles'
import type { RiskPoint } from '../../../api/riskFiles'

// The risky files a scan actually produced. This reads the data-object model
// (asset instances with at least one value-level detection) rather than the
// upload table, so a scan that collected files shows its evidence here instead
// of an empty page. The state lives in the composable; this view keeps the
// template, the ruler of static labels and the row formatting.
const {
  loading, error, rows, total, filters, selected, drawer,
  riskPoints, riskLoading, riskError,
  browse, browseLoading, browseError, revealAll,
  load, setPage, open, browseContent, download, onSortChange,
} = useRiskFiles()

const SOURCES = [{ l: '主机文件', v: 'file' }, { l: '共享文件', v: 'file_share' }, { l: '数据库', v: 'database' }]
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low']

/** One matched value, with the line it came from when the collector sent one. */
function matchLabel(match: { value: string; context?: string }): string {
  return match.context ? `${match.value}  ←  ${match.context}` : match.value
}

function evidenceCount(point: RiskPoint): number {
  return point.evidence.reduce((sum, row) => sum + row.matches.length, 0)
}
</script>

<template>
  <div>
    <div class="toolbar">
      <strong>风险文件</strong>
      <span class="muted">已扫描到敏感内容的文件（值命中，按分级排序）</span>
      <div class="toolbar-spacer" />
      <el-input v-model="filters.search" clearable placeholder="路径 / 文件名" style="width: 220px"
                @keyup.enter="load()" @clear="load()" />
      <el-select v-model="filters.source_kind" clearable placeholder="全部来源" style="width: 140px" @change="load()">
        <el-option v-for="item in SOURCES" :key="item.v" :label="item.l" :value="item.v" />
      </el-select>
      <el-select v-model="filters.severity" clearable placeholder="全部风险等级" style="width: 150px" @change="load()">
        <el-option v-for="item in SEVERITIES" :key="item" :label="item" :value="item" />
      </el-select>
      <el-button @click="load">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="!rows.length"
              empty-text="还没有扫到含敏感内容的文件；先在任务中心下发一次扫描" @retry="load">
      <el-table :data="rows" size="small" @row-click="open" @sort-change="onSortChange">
        <el-table-column prop="name" label="文件" min-width="260" show-overflow-tooltip sortable="custom">
          <template #default="{ row }">
            <strong>{{ row.name }}</strong>
            <div class="muted">{{ row.path }}</div>
          </template>
        </el-table-column>
        <el-table-column label="来源" min-width="170">
          <template #default="{ row }">
            {{ row.source_name || row.owner_key || row.source_kind }}
            <div class="muted">{{ row.host }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="分级" width="160" sortable="custom">
          <template #default="{ row }">
            <el-tag size="small" :type="row.level === 'L4' ? 'danger' : row.level === 'L3' ? 'warning' : 'info'">
              {{ row.level }} {{ row.sensitivity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="风险点" min-width="200">
          <template #default="{ row }">
            <el-tag v-for="category in row.categories" :key="category" size="small" style="margin: 2px">{{ category }}</el-tag>
            <div class="muted">{{ row.risk_point_count }} 类 · {{ row.risk_hit_count }} 处命中</div>
          </template>
        </el-table-column>
        <el-table-column prop="size" label="字节" width="110" sortable="custom" />
        <el-table-column label="覆盖 / 状态" width="180">
          <template #default="{ row }">
            {{ row.status }}
            <div class="muted">{{ formatCoverage(row.coverage) }} · {{ formatTerminationReason(row.termination_reason) }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen_at" label="最近发现" width="180" sortable="custom">
          <template #default="{ row }">{{ formatDateTime(row.last_seen_at) }}</template>
        </el-table-column>
      </el-table>
      <el-pagination background layout="total, prev, pager, next" :total="total"
                     :page-size="filters.page_size" :current-page="filters.page"
                     style="margin-top: 10px" @current-change="setPage" />
    </StateBox>

    <el-drawer v-model="drawer" title="风险文件详情" size="60%">
      <template v-if="selected">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="路径"><span class="wrap">{{ selected.path }}</span></el-descriptions-item>
          <el-descriptions-item label="来源">{{ selected.source_name }} · {{ selected.host }}（{{ selected.source_kind }}）</el-descriptions-item>
          <el-descriptions-item label="分级">{{ selected.level }} · {{ selected.sensitivity }}</el-descriptions-item>
          <el-descriptions-item label="覆盖口径">{{ formatCoverage(selected.coverage) }} / {{ formatTerminationReason(selected.termination_reason) }}</el-descriptions-item>
          <el-descriptions-item label="权限">{{ selected.permission || '未上报' }}</el-descriptions-item>
        </el-descriptions>

        <div class="section-title">
          风险点
          <span v-if="riskPoints" class="muted">
            共 {{ riskPoints.detection_count }} 类 · {{ riskPoints.hit_count }} 处命中 · 回传原文 {{ riskPoints.matches_returned }} 条
          </span>
        </div>
        <div v-if="riskLoading" class="muted">风险点加载中…</div>
        <div v-else-if="riskError" class="preview-error">{{ riskError }}</div>
        <el-empty v-else-if="!riskPoints || !riskPoints.items.length" description="该文件当前对象没有命中记录" :image-size="60" />
        <template v-else>
          <div v-for="point in riskPoints.items" :key="point.detection.id" class="risk-point">
            <div class="risk-point-head">
              <el-tag size="small" :type="point.detection.sensitivity_level === 'L4' ? 'danger' : point.detection.sensitivity_level === 'L3' ? 'warning' : 'info'">
                {{ point.detection.sensitivity_level }} {{ point.detection.category }}
              </el-tag>
              <span class="muted">
                {{ point.detection.severity }} · 置信度 {{ point.detection.confidence }} ·
                命中 {{ point.detection.hit_count }} 处 · 原文 {{ evidenceCount(point) }} 条
              </span>
            </div>
            <div v-for="row in point.evidence" :key="row.id" class="evidence-row">
              <div class="muted">
                规则 {{ row.rule_id || row.rule_name || '—' }}
                <span v-if="row.recognizer">· 识别器 {{ row.recognizer }}</span>
                <span v-if="row.field_name">· 字段 {{ row.field_name }}</span>
              </div>
              <ul v-if="row.matches.length" class="matches">
                <li v-for="(match, i) in row.matches" :key="i"><code>{{ matchLabel(match) }}</code></li>
              </ul>
              <div v-else class="muted">该规则没有回传命中原文（仅字段名命中等情况）</div>
            </div>
          </div>
          <div class="muted">{{ riskPoints.note }}</div>
        </template>

        <div class="section-title">
          内容浏览
          <el-button size="small" style="margin-left: 10px" :loading="browseLoading"
                     @click="browseContent(true)">浏览内容（掩码）</el-button>
          <el-button size="small" :disabled="!browse" :loading="browseLoading"
                     @click="browseContent(false)">查看全部</el-button>
          <el-button size="small" type="primary" style="margin-left: 10px"
                     @click="download">下载原始文件</el-button>
        </div>
        <div v-if="browseError" class="preview-error">{{ browseError }}</div>
        <template v-else-if="browse && (browse.text || browse.hex)">
          <div class="muted">
            编码 {{ browse.encoding }} · 预览 {{ browse.text ? browse.text.length : (browse.hex || '').length / 2 }} 字节
            <span v-if="browse.truncated">（文件共 {{ browse.size }} 字节，仅显示前 64 KiB）</span>
            <span v-if="browse.masked">· 已掩码 {{ browse.masked_values }} 处命中值，点「查看全部」显示原文</span>
            <span v-else-if="revealAll">· 已显示原文</span>
          </div>
          <pre v-if="browse.text" class="preview">{{ browse.text }}</pre>
          <pre v-else class="preview">{{ browse.hex }}</pre>
        </template>
        <div v-else class="muted">
          浏览与下载都从采集来源只读回取该文件（浏览最多 64 KiB 且默认掩码；下载整份文件）。
          平台不存留文件本体；由探针采集的主机文件需要回到采集端重新读取。
        </div>

        <div class="section-title">原始记录</div>
        <JsonViewer :value="selected" />
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; }
.section-title { font-weight: 600; margin: 14px 0 8px; }
.wrap { overflow-wrap: anywhere; }
.preview { background: var(--soc-panel-2); border: 1px solid var(--soc-border); border-radius: 6px;
           padding: 10px; font-size: 12px; max-height: 320px; overflow: auto; white-space: pre-wrap; }
.preview-error { color: var(--soc-warning); font-size: 12px; }
.risk-point { border: 1px solid var(--soc-border); border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; }
.risk-point-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
.evidence-row { margin-top: 6px; }
.matches { margin: 4px 0 0; padding-left: 18px; font-size: 12px; }
.matches code { color: var(--soc-text-strong); overflow-wrap: anywhere; }
:deep(.el-table__row) { cursor: pointer; }
</style>
