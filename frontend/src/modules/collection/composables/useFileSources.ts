import { onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  deleteFileSource, listFileSources, saveFileSource, runFileSource,
  type FileSource, type FileSourceForm,
} from '../../../api/fileSources'
const empty = (): FileSourceForm => ({ name: '', protocol: 'ftp', host: '', port: 21, username: '', password: '',
  root_path: '/', host_key_sha256: '', enabled: true, limits: { max_files: 200, max_depth: 3,
    max_bytes: 67108864, max_file_bytes: 8388608, max_seconds: 120 }, interval_minutes: 0 })
export function useFileSources() {
  const rows = ref<FileSource[]>([]), total = ref(0), page = ref(1), error = ref(''), loading = ref(false)
  const open = ref(false), editing = ref<number | null>(null), saving = ref(false)
  const busy = ref<number | null>(null), form = reactive(empty())
  let timer: ReturnType<typeof setInterval> | undefined
  let version = 0
  async function load(p = page.value) {
    const request = ++version
    page.value = p; loading.value = true; error.value = ''
    try {
      const result = await listFileSources(p)
      if (request !== version) return
      rows.value = result.items; total.value = result.total
    } catch (e) { if (request === version) error.value = String(e) }
    finally { if (request === version) loading.value = false }
  }
  function edit(row?: FileSource) {
    editing.value = row?.id ?? null
    Object.assign(form, empty(), row ? { name: row.name, protocol: row.protocol, host: row.host, port: row.port,
      username: row.username, root_path: row.root_path, host_key_sha256: row.host_key_sha256,
      enabled: row.enabled, limits: { ...row.limits }, interval_minutes: row.interval_minutes } : {})
    form.password = ''; open.value = true
  }
  async function save() {
    saving.value = true
    try {
      const payload = { ...form, limits: { ...form.limits } }
      if (editing.value && !payload.password) delete payload.password
      await saveFileSource(editing.value, payload)
      form.password = ''; open.value = false; await load()
    } catch(e) { ElMessage.error(String(e)) }
    finally { saving.value = false }
  }
  async function run(row: FileSource, operation: 'test' | 'scan') {
    busy.value = row.id
    try { const task = await runFileSource(row.id, operation); ElMessage.success(`已创建任务 #${task.id}，在采集任务中查看进度`); await load() }
    catch(e) { ElMessage.error(String(e)) }
    finally { busy.value = null }
  }
  async function remove(row: FileSource) {
    try {
      await ElMessageBox.confirm(`删除来源「${row.name}」？已采集的资产与证据仍保留，只移除这份配置。`, '删除来源',
        { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' })
    } catch { return }
    busy.value = row.id
    try { await deleteFileSource(row.id); ElMessage.success('已删除来源'); await load() }
    catch(e) { ElMessage.error(String(e)) }
    finally { busy.value = null }
  }
  onMounted(() => { void load(); timer = setInterval(() => { if (!open.value) void load() }, 10000) })
  onBeforeUnmount(() => { version++; clearInterval(timer) })
  return { rows, total, page, error, loading, open, editing, saving, busy, form, load, edit, save, run, remove }
}
