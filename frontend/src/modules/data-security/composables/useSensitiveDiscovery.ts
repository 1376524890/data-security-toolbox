/**
 * The sensitive-discovery view: the server-side findings for one page, plus the
 * chart-shaped projections the template renders.
 *
 * Nothing is recomputed client-side: the totals, entities and sources come from
 * `getSensitiveFindings`, and the category labels only rename what the server
 * already grouped.
 */
import { onMounted, ref, computed } from 'vue'
import { getSensitiveFindings, type SensitiveFindings } from '../../../api/dataAssets'

export function useSensitiveDiscovery() {
  const loading = ref(true)
  const error = ref('')
  const sensitive = ref<SensitiveFindings | null>(null)
  const page = ref(1)
  const pageSize = ref(50)

  const categoryLabels: Record<string, string> = {
    id_card: '身份证', phone: '手机号', bank_card: '银行卡', email: 'Email', medical_record: '医疗记录',
    api_key: 'API 密钥', token: 'Token', credential: '凭证', name: '姓名', address: '地址', user_id: '用户标识',
  }

  const assets = computed(() => sensitive.value?.data_assets)
  const totals = computed(() => sensitive.value?.totals)
  const entityData = computed(() => (sensitive.value?.entities || []).map(
    (item) => ({ name: categoryLabels[item.category] || item.category, value: item.count })))
  const sensitivityData = computed(() => Object.entries(assets.value?.by_sensitivity || {}).map(([name, value]) => ({ name, value })))
  const sources = computed(() => sensitive.value?.sources || [])

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      sensitive.value = await getSensitiveFindings({ page: page.value, page_size: pageSize.value })
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  function onPageChange(value: number): void {
    page.value = value
    void load()
  }

  onMounted(load)
  return {
    loading,
    error,
    sensitive,
    page,
    pageSize,
    assets,
    totals,
    entityData,
    sensitivityData,
    sources,
    load,
    onPageChange,
  }
}
