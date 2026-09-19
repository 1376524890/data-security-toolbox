/**
 * Asset-instance detail state: the instance row, the history toggle and the
 * evidence drawer.
 *
 * `instanceId` is the route-derived computed ref, handed in so the page keeps
 * owning the route.  The time formatters stay in the view: they are pure
 * presentation.
 */
import { onMounted, ref, type ComputedRef } from 'vue'
import {
  getAssetInstance, getDetectionEvidence,
  type DetectionRow, type EvidenceRow, type InstanceDetail,
} from '../../../api/dataCatalog'

export function useAssetInstanceDetail(instanceId: ComputedRef<number>) {
  const loading = ref(true)
  const error = ref('')
  const detail = ref<InstanceDetail | null>(null)
  const includeHistory = ref(false)

  const evidenceOpen = ref(false)
  const evidenceLoading = ref(false)
  const evidenceError = ref('')
  const evidence = ref<{ detection: DetectionRow; items: EvidenceRow[]; note: string } | null>(null)

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      detail.value = await getAssetInstance(instanceId.value, includeHistory.value)
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function openEvidence(row: DetectionRow): Promise<void> {
    evidenceOpen.value = true
    evidenceLoading.value = true
    evidenceError.value = ''
    evidence.value = null
    try {
      evidence.value = await getDetectionEvidence(row.id)
    } catch (err) {
      evidenceError.value = err instanceof Error ? err.message : String(err)
    } finally {
      evidenceLoading.value = false
    }
  }

  async function toggleHistory(): Promise<void> {
    includeHistory.value = !includeHistory.value
    await load()
  }

  onMounted(load)

  return {
    loading,
    error,
    detail,
    includeHistory,
    evidenceOpen,
    evidenceLoading,
    evidenceError,
    evidence,
    load,
    openEvidence,
    toggleHistory,
  }
}
