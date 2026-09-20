<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import FilterBar from '../../components/common/FilterBar.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import { formatDateTime } from '../../utils/format'
import { useCveCenter } from './composables/useCveCenter'

// The inventory, the library state, the Grype job and the manual-add dialog
// live in the composable (the poll timer is cleared on unmount); this view
// keeps the static CVSS level mapping and binds the state into the template.
const {
  loading, error, items, search, page, pageSize, total, busy, dialog, library, draft, job,
  searchCves, updateGrype, importGrype, importCves, saveCve, load,
} = useCveCenter()

function cvssLevel(score: number): string {
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 4) return 'Medium'
  return 'Low'
}

</script>

<template>
  <div>
    <div class="toolbar">
      <el-input v-model="search" placeholder="搜索 CVE ID" clearable style="width:240px" @keyup.enter="searchCves" @clear="searchCves" />
      <el-button @click="searchCves">搜索</el-button><div class="toolbar-spacer" />
      <el-button :loading="busy" @click="updateGrype">下载 / 更新 Grype DB</el-button>
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="importGrype" accept=".zst,.gz,.tar,.db,.sqlite"><el-button :disabled="busy">导入 Grype DB</el-button></el-upload>
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="importCves" accept=".json,.csv,.yaml,.yml"><el-button :disabled="busy">导入 CVE 规则</el-button></el-upload>
      <el-button type="primary" :disabled="busy" @click="dialog=true">手动添加</el-button>
    </div>
    <el-alert :title="library" type="info" :closable="false" style="margin-bottom:12px" />
    <el-alert v-if="job" :type="job.status==='failed' ? 'error' : job.status==='completed' ? 'success' : 'info'" :closable="false" style="margin-bottom:12px"
      :title="job.error || (job.status==='completed' ? `导入完成：新增 ${job.result?.imported}，更新 ${job.result?.updated}，保留手工及其他来源 ${job.result?.preserved}` : `Grype 任务 ${job.stage || job.status}：已下载 ${((job.downloaded_bytes || 0)/1024/1024).toFixed(1)} MB，已处理 ${(job.imported || 0)+(job.updated || 0)} 条`)" />
    <el-dialog v-model="dialog" title="手动添加 CVE" width="620px">
      <el-form label-width="100px">
        <el-form-item label="CVE ID"><el-input v-model="draft.cve_id" placeholder="CVE-2026-12345" /></el-form-item>
        <el-form-item label="严重程度"><el-select v-model="draft.severity"><el-option v-for="value in ['Critical','High','Medium','Low','Unknown']" :key="value" :label="value" :value="value" /></el-select></el-form-item>
        <el-form-item label="CVSS"><el-input-number v-model="draft.cvss_score" :min="0" :max="10" :step="0.1" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="draft.description" type="textarea" :rows="5" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog=false">取消</el-button><el-button type="primary" :loading="busy" @click="saveCve">保存</el-button></template>
    </el-dialog>
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small">
        <el-table-column prop="cve_id" label="CVE ID" width="160" />
        <el-table-column prop="source" label="来源" width="110" />
        <el-table-column label="等级" width="100"><template #default="{ row }"><RiskBadge :level="row.severity || cvssLevel(row.cvss_score || 0)" /></template></el-table-column>
        <el-table-column label="CVSS" width="90"><template #default="{ row }"><span class="mono">{{ row.cvss_score ?? '-' }}</span></template></el-table-column>
        <el-table-column label="发布时间" width="150"><template #default="{ row }">{{ row.published ? formatDateTime(row.published) : '-' }}</template></el-table-column>
        <el-table-column label="修改时间" width="150"><template #default="{ row }">{{ row.modified ? formatDateTime(row.modified) : '-' }}</template></el-table-column>
        <el-table-column label="描述" min-width="240" show-overflow-tooltip><template #default="{ row }"><span>{{ typeof row.description === 'string' ? row.description : row.description?.zh || row.description?.text || row.description?.en || JSON.stringify(row.description) }}</span></template></el-table-column>
      </el-table>
    </StateBox>
    <el-pagination class="pagination" v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[20,50,100,200]" :total="total" layout="total, sizes, prev, pager, next" @current-change="load" @size-change="searchCves" />
  </div>
</template>
