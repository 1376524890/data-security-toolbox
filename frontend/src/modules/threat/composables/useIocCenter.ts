/**
 * IOC-centre state: the indicator inventory, the association drawer and the
 * enable/disable toggle.
 *
 * The filters drive the server-side query; a failed association read is
 * reported without opening the drawer.  The static filter fields and the time
 * formatter stay in the view.
 */
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listIocs, getIocAssociations } from '../../../api/intelligence'
import type { Ioc, IocAssociation } from '../../../types/ioc'
import { apiPost } from '../../../api/client'

export function useIocCenter() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<Ioc[]>([])
  const total = ref(0)
  const detail = ref<IocAssociation | null>(null)
  const drawer = ref(false)
  const filters = reactive({ type: '', source: '', search: '', page: 1, page_size: 50 })

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await listIocs({ ...filters })
      items.value = result.items
      total.value = result.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function open(row: Ioc): Promise<void> {
    try {
      detail.value = await getIocAssociations(row.id)
      drawer.value = true
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function reset(): void { filters.page = 1; load() }

  async function toggle(row: Ioc) {
    try { await apiPost(`/intelligence/${row.id}/toggle`, { enabled: row.metadata?.enabled === false }); await load() }
    catch (e) { ElMessage.error(String(e)) }
  }

  onMounted(load)

  return {
    loading, error, items, total, detail, drawer, filters, load, open, reset, toggle,
  }
}
