import { onMounted, ref, watch, type Ref } from 'vue'
import { listAssetInstances, type AssetInstanceRow } from '../../../api/dataCatalog'
export function useAssetInventory(sensitive: boolean, owner: Ref<string>) {
  const rows = ref<AssetInstanceRow[]>([]), total = ref(0), page = ref(1), loading = ref(false), error = ref('')
  const search = ref(''), source = ref(''), status = ref('ACTIVE')
  let version = 0
  async function load(p = 1) {
    const request = ++version; page.value = p; loading.value = true; error.value = ''
    try {
      const result = await listAssetInstances({ page: p, page_size: 50, search: search.value || undefined,
        source_kind: source.value || undefined, status: status.value || undefined,
        sensitive_only: sensitive, owner_key: owner.value || undefined, order_by: '-last_seen_at' })
      if (request !== version) return
      rows.value = result.items; total.value = result.total
    } catch(e) { if (request === version) error.value = String(e) }
    finally { if (request === version) loading.value = false }
  }
  watch(owner, () => { void load() })
  onMounted(() => { void load() })
  return { rows, total, page, loading, error, search, source, status, load }
}
