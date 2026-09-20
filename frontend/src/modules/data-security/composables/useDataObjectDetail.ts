/**
 * Data-object detail state: the object itself, the page of its detections and
 * the evidence drawer.
 *
 * `objectId` is the route-derived computed ref, handed in so the page keeps
 * owning the route.  `setDetectionPage` exists so the pager can move: a ref a
 * composable returns cannot be assigned to from the template, and moving the
 * pager must also reload that page.
 */
import { computed, onMounted, ref, type ComputedRef } from 'vue'
import {
  getDataObject, getDetectionEvidence, listObjectDetections,
  type AssetInstanceRow, type DetectionRow, type EvidenceRow, type ObjectDetail,
} from '../../../api/dataCatalog'

export function useDataObjectDetail(objectId: ComputedRef<number>) {
  const loading = ref(true)
  const error = ref('')
  const detail = ref<ObjectDetail | null>(null)
  const detections = ref<DetectionRow[]>([])
  const detectionPage = ref(1)
  const detectionTotal = ref(0)
  const pageSize = 10

  const evidenceOpen = ref(false)
  const evidenceLoading = ref(false)
  const evidenceError = ref('')
  const evidence = ref<{ detection: DetectionRow; items: EvidenceRow[]; note: string } | null>(null)

  const identityText = computed(() => {
    const kind = detail.value?.identity_kind
    if (kind === 'confirmed') return '内容一致（完整 SHA256 相同）'
    if (kind === 'candidate') {
      return (detail.value?.active_instance_count ?? 0) >= 2
        ? '疑似副本（部分指纹相同且存在多个实例，需人工确认）'
        : '待确认身份（部分指纹相同，但仅观察到 1 个实例，不称副本）'
    }
    return '作用域内标识（无可靠 Hash，仅在同一探针内可比）'
  })

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [object, detectionResult] = await Promise.all([
        getDataObject(objectId.value),
        listObjectDetections(objectId.value, { page: detectionPage.value, page_size: pageSize }),
      ])
      detail.value = object
      detections.value = detectionResult.items
      detectionTotal.value = detectionResult.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function loadDetections(): Promise<void> {
    const result = await listObjectDetections(objectId.value, { page: detectionPage.value, page_size: pageSize })
    detections.value = result.items
    detectionTotal.value = result.total
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

  function setDetectionPage(value: number): void {
    detectionPage.value = value
    void loadDetections()
  }

  onMounted(load)

  return {
    loading,
    error,
    detail,
    detections,
    detectionPage,
    detectionTotal,
    pageSize,
    evidenceOpen,
    evidenceLoading,
    evidenceError,
    evidence,
    identityText,
    load,
    loadDetections,
    openEvidence,
    setDetectionPage,
  }
}
