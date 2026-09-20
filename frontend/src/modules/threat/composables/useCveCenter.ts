/**
 * CVE-centre state: the local CVE inventory, the offline Grype-DB library and
 * the Grype import job.
 *
 * The poller owns its timer: it is armed when a job is tracked, stops once the
 * job completes or fails, and is cleared on unmount.  The running job id
 * survives a reload in ``localStorage``.  The static CVSS level mapping stays
 * in the view.
 */
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost, apiUpload } from '../../../api/client'
import { listLocalCves, uploadOffline, listOfflineResources } from '../../../api/offline'
import type { LocalCve } from '../../../types/offline'

export function useCveCenter() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<LocalCve[]>([])
  const search = ref('')
  const page = ref(1), pageSize = ref(50), total = ref(0)
  function searchCves() { page.value = 1; void load() }
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
      const result = await listLocalCves(search.value, page.value, pageSize.value)
      items.value = result.items
      total.value = result.total
      const resources = await listOfflineResources()
      const grype = resources.find(r=>r.resource_type === 'grype_db')
      if (grype) library.value = `Grype DB：${grype.version}，${grype.count} 条 CVE`
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  onMounted(() => { void load(); const identifier = localStorage.getItem('grype-library-job'); if(identifier) track({id:identifier,status:'queued'}) })
  onUnmounted(() => { disposed = true; if(pollTimer) clearTimeout(pollTimer) })

  return {
    loading, error, items, search, page, pageSize, total, busy, dialog, library, draft, job,
    searchCves, updateGrype, importGrype, importCves, saveCve, load,
  }
}
