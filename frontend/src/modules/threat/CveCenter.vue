<script setup lang="ts">
import { onMounted, onUnmounted, ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost, apiUpload } from '../../api/client'
import { listLocalCves, uploadOffline, listOfflineResources } from '../../api/offline'
import type { LocalCve } from '../../types/offline'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar from '../../components/common/FilterBar.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<LocalCve[]>([])
const search = ref('')
const busy = ref(false), dialog = ref(false), library = ref('尚未导入 Grype DB')
const draft = reactive({cve_id:'', severity:'Medium', cvss_score:0, description:''})
type LibraryJob = {id:string; status:string; stage?:string; downloaded_bytes?:number; imported?:number; updated?:number; error?:string; result?:{imported:number; updated:number; preserved:number; version:string}}
const job = ref<LibraryJob|null>(null)
let pollTimer: ReturnType<typeof setTimeout> | undefined
let disposed = false
async function poll() {
  if (!job.value || disposed) return
  try {
    job.value = await apiGet<LibraryJob>(`/offline/grype/jobs/${job.value.id}`)
    if (job.value.status === 'completed' || job.value.status === 'failed') {
      busy.value = false; localStorage.removeItem('grype-library-job')
      if (job.value.status === 'completed') { ElMessage.success('Grype DB 导入完成'); await load() }
      return
    }
  } catch(e) { error.value = String(e) }
  if (!disposed) pollTimer = setTimeout(poll, 2000)
}
function track(value:LibraryJob) { job.value = value; busy.value = true; localStorage.setItem('grype-library-job', value.id); void poll() }
async function updateGrype() {
  busy.value = true
  try { track(await apiPost<LibraryJob>('/offline/grype/update')) }
  catch(e) { busy.value = false; ElMessage.error(String(e)) }
}
async function importGrype(file:{raw?:File}) {
  if (!file.raw) return
  busy.value = true
  try { track(await apiUpload<LibraryJob>('/offline/grype/import', file.raw, undefined, {timeout:1800000})) }
  catch(e) { busy.value = false; ElMessage.error(String(e)) }
}
async function importCves(file:{raw?:File}) {
  if (!file.raw) return
  busy.value = true
  try {
    const result = await uploadOffline(file.raw, 'cve')
    if (result.errors?.length) throw new Error(result.errors.join('; '))
    ElMessage.success(`新增 ${result.imported} 条，更新 ${result.duplicates} 条`); await load()
  } catch(e) { ElMessage.error(String(e)) } finally { busy.value = false }
}
async function saveCve() {
  busy.value = true
  try { await apiPost('/offline/cves', draft); dialog.value = false; await load(); ElMessage.success('CVE 已添加') }
  catch(e) { ElMessage.error(String(e)) } finally { busy.value = false }
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = await listLocalCves(search.value)
    const resources = await listOfflineResources()
    const grype = resources.find(r=>r.resource_type === 'grype_db')
    if (grype) library.value = `Grype DB：${grype.version}，${grype.count} 条 CVE`
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

onMounted(() => { void load(); const identifier = localStorage.getItem('grype-library-job'); if(identifier) track({id:identifier,status:'queued'}) })
onUnmounted(() => { disposed = true; if(pollTimer) clearTimeout(pollTimer) })
</script>

<template>
  <div>
    <div class="toolbar">
      <el-input v-model="search" placeholder="搜索 CVE ID" clearable style="width:240px" @keyup.enter="load" />
      <el-button @click="load">搜索</el-button><div class="toolbar-spacer" />
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
        <el-table-column label="描述" min-width="240" show-overflow-tooltip><template #default="{ row }"><span>{{ typeof row.description === 'string' ? row.description : row.description?.text || JSON.stringify(row.description) }}</span></template></el-table-column>
      </el-table>
    </StateBox>
  </div>
</template>
