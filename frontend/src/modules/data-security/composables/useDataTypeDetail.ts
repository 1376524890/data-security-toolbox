/**
 * Data-type detail state: the type row, the page of objects inside it and the
 * identity badge wording.
 *
 * `category` is the route-derived computed ref, handed in so the page can react to
 * it and to the pager.  `setPage` exists so the template can move
 * the pager: a ref that a composable returns cannot be assigned to from the
 * template (the assignment would only rebind the setup-local name), the same
 * reason the PCAP batch added `closeFileDialog`.
 */
import { computed, onMounted, ref, watch, type ComputedRef } from 'vue'
import { getDataType, type DataObjectRow, type DataTypeRow } from '../../../api/dataCatalog'

export function useDataTypeDetail(category: ComputedRef<string>) {
  const loading = ref(true)
  const error = ref('')
  const row = ref<DataTypeRow | null>(null)
  const objects = ref<DataObjectRow[]>([])
  const page = ref(1)
  const pageSize = ref(20)
  const total = ref(0)

  function identityTag(row: DataObjectRow): { text: string; type: 'success' | 'warning' | 'info' } {
    if (row.identity_kind === 'confirmed') return { text: `内容一致 ${row.identity_confidence}`, type: 'success' }
    // A partial fingerprint on a lone instance is an unresolved identity; only
    // two or more instances make it a suspected copy.
    if (row.identity_kind === 'candidate') {
      return {
        text: row.active_instance_count >= 2 ? `疑似副本 ${row.identity_confidence}` : `待确认身份 ${row.identity_confidence}`,
        type: 'warning',
      }
    }
    return { text: '作用域内标识', type: 'info' }
  }

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await getDataType(category.value, { page: page.value, page_size: pageSize.value })
      row.value = result
      objects.value = result.objects.items
      total.value = result.objects.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  function setPage(value: number): void { page.value = value }

  watch([page, category], () => { void load() })
  onMounted(load)

  return {
    loading,
    error,
    row,
    objects,
    page,
    pageSize,
    total,
    identityTag,
    load,
    setPage,
  }
}
