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
 * All state lives in ``composables/useCryptoAssessmentResults``; this view keeps
 * the layout, the Element Plus bindings and the time formatting.
 */
import { onMounted } from 'vue'
import StateBox from '../../components/common/StateBox.vue'
import CryptoAssessmentPanel from '../tasks/assessment/CryptoAssessmentPanel.vue'
import { useCryptoAssessmentResults } from './composables/useCryptoAssessmentResults'

const {
  rows, taskTotal, page, pageSize, loading, error, selectedId, selected, selectedProfiles,
  load, setPage,
} = useCryptoAssessmentResults()

function formatDateTime(value: string): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function onRowClick(row: { id: number }): void {
  selectedId.value = row.id
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
            共 {{ taskTotal }} 条检查任务，其中 {{ rows.length }} 条在当前页含密码评估结果。
            评估在浏览器内按 GB/T 39786 / GM/T 系列执行，服务端只保存扫描观测到的算法、套件、协议与密钥事实。
          </div>
        </div>
      </div>

      <div class="section-title">已有密码评估的检查任务</div>
      <el-table :data="rows" size="small" highlight-current-row
                :current-row-key="selectedId ?? undefined" row-key="id"
                @row-click="onRowClick">
        <el-table-column prop="id" label="任务" width="90" />
        <el-table-column prop="target" label="目标" min-width="160" show-overflow-tooltip />
        <el-table-column label="评估主机" width="100">
          <template #default="{ row }">{{ row.hostCount }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="110" />
        <el-table-column label="完成时间" width="180">
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

      <template v-if="selected">
        <div class="section-title">任务 #{{ selected.id }} 观测结果</div>
        <CryptoAssessmentPanel
          :profiles="selectedProfiles"
          :title="`${selected.target || '#' + selected.id} 网络扫描观测结果（商用密码应用安全性评估，GB/T 39786 / GM/T）`" />
      </template>
    </StateBox>
  </div>
</template>
