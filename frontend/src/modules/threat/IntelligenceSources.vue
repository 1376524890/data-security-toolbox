<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost } from '../../api/client'
type Provider = { id: string; name: string; configured: boolean; key_required: boolean; last_sync: { status?: string; at?: string; error?: string; added?: number } }
const emit = defineEmits<{ changed: [] }>()
const providers = ref<Provider[]>([])
const content = ref('')
const source = ref('manual')
const busy = ref('')
const error = ref('')
const showImport = ref(false)
async function load() {
  try { providers.value = (await apiGet<{ items: Provider[] }>('/intelligence/providers')).items; error.value = '' }
  catch (e) { error.value = String(e) }
}
async function sync(id: string) {
  busy.value = id
  try { const task = await apiPost<{ id: number }>(`/intelligence/providers/${id}/sync`); ElMessage.success(`情报同步已入队，任务 #${task.id}；完成后点击刷新`); }
  catch (e) { ElMessage.error(String(e)) }
  finally { busy.value = '' }
}
async function importData() {
  busy.value = 'import'
  try {
    const r = await apiPost<{added: number; updated: number; rejected: number}>('/intelligence/import', { content: content.value, source: source.value })
    ElMessage.success(`新增 ${r.added}，更新 ${r.updated}，无效 ${r.rejected}`); showImport.value = false; emit('changed')
  } catch (e) { ElMessage.error(String(e)) }
  finally { busy.value = '' }
}
async function exportData() {
  try {
    const data = await apiGet('/intelligence/export')
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}))
    const a = document.createElement('a'); a.href = url; a.download = 'local-intelligence.json'; a.click(); URL.revokeObjectURL(url)
  } catch (e) { ElMessage.error(String(e)) }
}
async function readFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  if (file.size > 5 * 1024 * 1024) { ElMessage.error('文件不能超过 5 MiB'); return }
  content.value = await file.text()
}
onMounted(load)
</script>
<template>
  <el-card shadow="never" style="margin-bottom:16px">
    <template #header><b>情报接入与自建情报库</b><el-button style="float:right" @click="load(); emit('changed')">刷新</el-button></template>
    <el-alert v-if="error" :title="error" type="error" />
    <el-table :data="providers" size="small">
      <el-table-column prop="name" label="情报源" />
      <el-table-column label="配置状态"><template #default="{row}">{{ row.configured ? '可同步' : (row.key_required ? '需配置服务端密钥' : '需配置服务端地址') }}</template></el-table-column>
      <el-table-column label="最近同步"><template #default="{row}">{{ row.last_sync.status || '尚未同步' }} {{ row.last_sync.at || '' }}</template></el-table-column>
      <el-table-column label="结果"><template #default="{row}">{{ row.last_sync.error || (row.last_sync.added != null ? `新增 ${row.last_sync.added}` : '—') }}</template></el-table-column>
      <el-table-column width="110"><template #default="{row}"><el-button :disabled="!row.configured || !!busy" :loading="busy === row.id" @click="sync(row.id)">同步</el-button></template></el-table-column>
    </el-table>
    <div style="margin-top:12px"><el-button type="primary" @click="showImport = true">添加 / 导入 IOC</el-button><el-button @click="exportData">导出自建情报</el-button><span style="margin-left:12px">支持 IP、域名、URL、MD5 / SHA1 / SHA256；仅下载指标，不下载恶意样本。</span></div>
  </el-card>
  <el-dialog v-model="showImport" title="导入本地情报" width="650px">
    <el-form label-width="80px"><el-form-item label="来源"><el-input v-model="source" maxlength="100" /></el-form-item>
      <el-form-item label="文件"><input type="file" accept=".json,.csv" @change="readFile" /></el-form-item>
      <el-form-item label="内容"><el-input v-model="content" type="textarea" :rows="10" placeholder='[{"type":"domain","value":"demo-exfil.example","tags":["demo"]}] 或 CSV 表头 type,value,tags' /></el-form-item>
    </el-form>
    <template #footer><el-button type="primary" :loading="busy === 'import'" :disabled="!content.trim()" @click="importData">导入</el-button></template>
  </el-dialog>
</template>
