<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { listLocalCves } from '../../api/offline'
import type { LocalCve } from '../../types/offline'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar from '../../components/common/FilterBar.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<LocalCve[]>([])
const search = ref('')

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = await listLocalCves(search.value)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function cvssLevel(score: number): string {
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 4) return 'Medium'
  return 'Low'
}

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="[{ key: 'search', label: '搜索 CVE', placeholder: '搜索 CVE ID', width: '240px' }]" :model="{ search }" @search="load" @reset="load" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small">
        <el-table-column prop="cve_id" label="CVE ID" width="160" />
        <el-table-column prop="source" label="来源" width="110" />
        <el-table-column label="等级" width="100"><template #default="{ row }"><RiskBadge :level="row.severity || cvssLevel(row.cvss_score || 0)" /></template></el-table-column>
        <el-table-column label="CVSS" width="90"><template #default="{ row }"><span class="mono">{{ row.cvss_score ?? '-' }}</span></template></el-table-column>
        <el-table-column label="发布时间" width="150"><template #default="{ row }">{{ row.published ? formatDateTime(row.published) : '-' }}</template></el-table-column>
        <el-table-column label="修改时间" width="150"><template #default="{ row }">{{ row.modified ? formatDateTime(row.modified) : '-' }}</template></el-table-column>
        <el-table-column label="描述" min-width="240" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ typeof row.description === 'string' ? row.description : JSON.stringify(row.description) }}</span></template></el-table-column>
      </el-table>
    </StateBox>
  </div>
</template>
