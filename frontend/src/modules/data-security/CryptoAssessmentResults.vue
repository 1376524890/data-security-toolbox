<script setup lang="ts">
/**
 * 密码评估 under 资产中心: the assessments past 检查任务 already produced.
 *
 * A 检查任务 with 密码评估 ticked records each host's observed crypto facts in
 * ``result.crypto_profiles``; the panel below re-runs the GB/T 39786 / GM/T
 * assessment over them. This view exists so the result is reachable from the
 * asset side — before, it could only be read by opening the task's drawer in
 * 任务中心, which is not where an operator looks for an assessment result.
 *
 * 资产常驻 is the primary table: one row per host, folded across every loaded
 * task, so an operator reads each asset's standing verdict instead of having to
 * remember which 检查任务 observed it. The task table below stays as the record
 * of how the facts were collected.
 *
 * All state lives in ``composables/useCryptoAssessmentResults``; this view keeps
 * the layout, the Element Plus bindings and the time formatting.
 */
import { onMounted } from 'vue'
import StateBox from '../../components/common/StateBox.vue'
import CryptoAssessmentPanel from '../tasks/assessment/CryptoAssessmentPanel.vue'
import { useCryptoAssessmentResults } from './composables/useCryptoAssessmentResults'

const {
  rows, taskTotal, page, pageSize, loading, error, selectedId, selected, selectedProfiles,
  assets, visibleAssets, assetTotal, assetFilters, assetTable, selectedHost, selectAsset,
  panelProfiles, panelTitle,
  load, setPage, onSortChange,
} = useCryptoAssessmentResults()

/** A level is a verdict, not a severity: colour it by the verdict it states. */
function levelTone(level: string): 'success' | 'info' | 'warning' | 'danger' {
  if (level === '合规') return 'success'
  if (level === '基本合规') return 'info'
  if (level === '部分合规') return 'warning'
  return 'danger'
}

function formatDateTime(value: string): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function onAssetRowClick(row: { host: string }): void {
  selectAsset(row.host)
}

// The reverse of `selectAsset`: opening a run's hosts drops the asset pick, so
// the single panel below always belongs to the row the operator last clicked.
function onRowClick(row: { id: number }): void {
  selectedId.value = row.id
  selectedHost.value = ''
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="!rows.length"
              empty-text="尚无完成密码评估的检查任务：在任务中心发起「检查任务」并勾选密码评估后，结果会出现在这里"
              @retry="load">
      <div class="soc-card conclusion">
        <div>
          <strong>密码评估</strong>
          <div class="muted">
            当前页 {{ assets.length }} 个资产有常驻评估结果（来源 {{ rows.length }} 条含密码评估的检查任务，
            服务端共 {{ taskTotal }} 条检查任务）。同一主机被多次观测时取最新一次，
            评估在浏览器内按 GB/T 39786 / GM/T 系列执行，服务端只保存扫描观测到的算法、套件、协议与密钥事实。
          </div>
        </div>
      </div>

      <div class="section-title">按资产常驻结果（{{ assetTotal }} 个资产）</div>
      <div class="toolbar" style="margin-bottom: 10px">
        <el-input v-model="assetFilters.search" clearable placeholder="主机 / 目标 / 结论" style="width: 240px" />
        <span class="muted">显示 {{ visibleAssets.length }} / {{ assetTotal }} 个资产</span>
      </div>
      <el-table :data="visibleAssets" size="small" highlight-current-row
                :current-row-key="selectedHost || undefined" row-key="host"
                @row-click="onAssetRowClick"
                @sort-change="assetTable.onSortChange">
        <el-table-column prop="host" label="资产 / 主机" min-width="160" show-overflow-tooltip sortable="custom" />
        <el-table-column prop="target" label="扫描目标" min-width="140" show-overflow-tooltip />
        <el-table-column prop="level" label="结论" width="110" sortable="custom">
          <template #default="{ row }">
            <el-tag size="small" :type="levelTone(row.level)">{{ row.level }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="overallScore" label="总分" width="90" sortable="custom" />
        <el-table-column prop="violations" label="不符合项" width="100" sortable="custom" />
        <el-table-column prop="taskId" label="来源任务" width="100">
          <template #default="{ row }">#{{ row.taskId }}</template>
        </el-table-column>
        <el-table-column prop="observedAt" label="最近观测" width="180">
          <template #default="{ row }">{{ formatDateTime(row.observedAt) }}</template>
        </el-table-column>
      </el-table>

      <div class="section-title">已有密码评估的检查任务（观测来源）</div>
      <el-table :data="rows" size="small" highlight-current-row
                :current-row-key="selectedId ?? undefined" row-key="id"
                @row-click="onRowClick" @sort-change="onSortChange">
        <el-table-column prop="id" label="任务" width="100" sortable="custom" />
        <el-table-column prop="target" label="目标" min-width="160" show-overflow-tooltip />
        <el-table-column label="评估主机" width="100">
          <template #default="{ row }">{{ row.hostCount }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120" sortable="custom" />
        <el-table-column prop="finished_at" label="完成时间" width="180" sortable="custom">
          <template #default="{ row }">{{ formatDateTime(row.finishedAt) }}</template>
        </el-table-column>
      </el-table>

      <div class="toolbar" style="margin-top: 10px">
        <el-button size="small" :disabled="page <= 1" @click="setPage(page - 1)">上一页</el-button>
        <span class="muted">第 {{ page }} 页 · 每页 {{ pageSize }} 条</span>
        <el-button size="small" :disabled="page * pageSize >= taskTotal"
                   @click="setPage(page + 1)">下一页</el-button>
        <el-button size="small" @click="load">刷新</el-button>
      </div>

      <template v-if="panelTitle">
        <div class="section-title">评估结果</div>
        <CryptoAssessmentPanel :profiles="panelProfiles" :title="panelTitle" />
      </template>
    </StateBox>
  </div>
</template>
