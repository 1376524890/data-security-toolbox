/**
 * 网络资产 state: what the active scan found on the wire, per port.
 *
 * The rows are the scanner's own output (asset + service fingerprint) joined to
 * the CVE findings the threat-intel engine matched against that fingerprint, so
 * this page never re-derives a match: it shows what the pipeline decided and
 * keeps "confirmed" and "candidate" apart.
 *
 * ``libraryTotal`` is part of the state on purpose. An empty CVE library makes
 * every scan produce zero hits, and a page that shows "0 漏洞" without saying why
 * reads as "the network is clean" — it is not the same statement.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import {
  getNetworkAssetSummary,
  listNetworkAssets,
  type NetworkAsset,
  type NetworkAssetSummary,
} from '../../../api/networkAssets'
import { listLocalCves } from '../../../api/cveLibrary'

export function useNetworkAssets() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<NetworkAsset[]>([])
  const summary = ref<NetworkAssetSummary | null>(null)
  const libraryTotal = ref<number | null>(null)
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(50)
  const filters = reactive({ search: '', severity: '', only_vulnerable: false, source: '' })
  const selected = ref<NetworkAsset | null>(null)
  const drawer = ref(false)

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [pageData, summaryData] = await Promise.all([
        listNetworkAssets({ ...filters, page: page.value, page_size: pageSize.value }),
        getNetworkAssetSummary(),
      ])
      items.value = pageData.items
      total.value = pageData.total
      summary.value = summaryData
    } catch (err) {
      error.value = String(err)
    } finally {
      loading.value = false
    }
  }

  /** Whether the CVE library can match anything at all; null while unknown. */
  async function loadLibrarySize(): Promise<void> {
    try {
      libraryTotal.value = (await listLocalCves('', 1, 1)).total
    } catch {
      libraryTotal.value = null
    }
  }

  function search(): void {
    page.value = 1
    void load()
  }

  function setPage(value: number): void {
    page.value = value
    void load()
  }

  function open(row: NetworkAsset): void {
    selected.value = row
    drawer.value = true
  }

  /** Confirmed first, then by CVSS: a confirmed 9.8 is the reason to open the row. */
  const cves = computed(() => {
    const row = selected.value
    if (!row) return []
    return [...row.cves].sort((a, b) =>
      Number(b.confirmed) - Number(a.confirmed) || b.cvss_score - a.cvss_score)
  })

  /** The honest reason a page full of zeroes is a zero and not a clean bill. */
  const emptyCveReason = computed(() => {
    if (libraryTotal.value === null) return ''
    if (libraryTotal.value === 0) {
      return '本地 CVE 规则库为空：扫描无法确认任何漏洞。请到「采集与规则 → 漏洞库」做在线更新或手动导入。'
    }
    return '规则库已有规则，但没有任何指纹落在其受影响版本范围内；可疑命中会以“线索”列出。'
  })

  onMounted(async () => {
    await Promise.all([load(), loadLibrarySize()])
  })

  return {
    loading, error, items, summary, libraryTotal, total, page, pageSize, filters,
    selected, drawer, cves, emptyCveReason, load, loadLibrarySize, search, setPage, open,
  }
}
