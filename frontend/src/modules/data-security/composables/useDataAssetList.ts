import { computed, reactive, ref } from 'vue'
import { listDataAssets, getDataAsset } from '../../../api/dataAssets'
import { listProbes, type Probe } from '../../../api/probes'
import { useAutoRefresh } from '../../../composables/useAutoRefresh'
import { useTableSort } from '../../../composables/useTableSort'
import type { DataAsset as DataAssetType, DataAssetDetail } from '../../../types/dataAsset'

/** Read-side state for the asset list and detail drawer. */
export function useDataAssetList() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<DataAssetType[]>([])
  const total = ref(0)
  const detail = ref<DataAssetDetail | null>(null)
  const drawer = ref(false)
  const filters = reactive({
    search: '', sensitivity: '', asset_type: '', source: '', probe_id: '',
    order_by: undefined as string | undefined, page: 1, page_size: 50,
  })

  // The list is paginated, so the sort has to travel to the server: ordering
  // only the rows on screen would reorder a page, not the inventory.
  const { onSortChange, orderBy } = useTableSort(() => { filters.page = 1; void load() })

  const probes = ref<Probe[]>([])
  // "1 field, 100 sample hits" and "1 field, 0 hits" are different findings, so
  // the two units are never collapsed into one number.
  const piiData = computed(() => {
    const detailed = detail.value?.pii_summary_detail
    if (detailed && Object.keys(detailed).length) {
      return Object.entries(detailed).map(([name, value]) => ({
        name, fields: value.fields, sample_hits: value.sample_hits,
      }))
    }
    return Object.entries(detail.value?.pii_summary || {}).map(([name, value]) => ({
      name, fields: value, sample_hits: 0,
    }))
  })

  async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
    if (!silent) { loading.value = true; error.value = '' }
    try {
      filters.order_by = orderBy()
      const result = await listDataAssets({
        search: filters.search,
        sensitivity: filters.sensitivity,
        asset_type: filters.asset_type,
        source: filters.source,
        probe_id: filters.probe_id ? Number(filters.probe_id) : undefined,
        page: filters.page,
        page_size: filters.page_size,
      })
      items.value = result.items
      total.value = result.total
      error.value = ''
    } catch (err) {
      // A failed background refresh keeps the last good page instead of
      // replacing it with an error the operator did not ask for.
      if (!silent) error.value = err instanceof Error ? err.message : String(err)
    } finally {
      if (!silent) loading.value = false
    }
  }

  useAutoRefresh(load, { intervalMs: 60000 })

  async function loadProbes(): Promise<void> {
    try {
      const result = await listProbes({ page: 1, page_size: 200 })
      probes.value = result.items
    } catch {
      probes.value = []
    }
  }

  async function open(row: DataAssetType): Promise<void> {
    try {
      detail.value = await getDataAsset(row.id)
      drawer.value = true
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    }
  }

  function reset(): void { filters.page = 1; load() }

    return { loading, error, items, total, detail, drawer, filters, probes, piiData,
      load, loadProbes, open, reset, onSortChange }
}
