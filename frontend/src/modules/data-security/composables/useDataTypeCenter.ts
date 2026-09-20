/**
 * Data-type centre state: the per-type rows, the sensitivity levels and the
 * server totals the top cards show.
 *
 * The view keeps the template and the row navigation; loading, filtering and
 * the totals live here.  The totals are the server's de-duplicated object and
 * instance sets, so they are never recomputed by summing the rows.
 */
import { computed, onMounted, ref } from 'vue'
import { getSensitivityLevels, listDataTypes } from '../../../api/dataCatalog'

export function useDataTypeCenter() {
  const loading = ref(true)
  const error = ref('')
  const rows = ref<Awaited<ReturnType<typeof listDataTypes>> | null>(null)
  const levels = ref<Awaited<ReturnType<typeof getSensitivityLevels>> | null>(null)
  const search = ref('')

  const filtered = computed(() => {
    const items = rows.value?.items || []
    const needle = search.value.trim().toLowerCase()
    if (!needle) return items
    return items.filter((item) =>
      item.category.includes(needle) || item.entity.toLowerCase().includes(needle))
  })

  // Totals come from the server's de-duplicated object/instance sets: summing the
  // per-type rows would count a file holding both email and credential twice.
  const totals = computed(() => rows.value?.totals ?? {
    types: 0, objects: 0, instances: 0, hosts: 0,
    confirmed_duplicates: 0, candidate_duplicates: 0, identity_pending: 0, truncated: false,
  })
  const scopeLabel = computed(() => (rows.value?.totals_scope === 'all_probes'
    ? '全部探针'
    : `探针 ${rows.value?.totals_scope?.replace('probe:', '') ?? ''}`))

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [center, levelResult] = await Promise.all([listDataTypes(), getSensitivityLevels()])
      rows.value = center
      levels.value = levelResult
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  onMounted(load)

  return {
    loading,
    error,
    rows,
    levels,
    search,
    filtered,
    totals,
    scopeLabel,
    load,
  }
}
