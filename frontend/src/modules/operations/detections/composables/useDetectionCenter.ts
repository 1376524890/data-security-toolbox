/**
 * The detection centre: the paged finding list, the finding detail and the
 * manual pipeline trigger.
 *
 * The engine filter has to offer the names findings are actually stored under,
 * so the option list is built from the engine registry instead of a hard-coded
 * list.  The filter field configuration stays in the view because it is static
 * presentation; every API call and every piece of page state lives here.
 */
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listDetections, getDetection, type DetectionQuery } from '../../../../api/detections'
import { getEngineRegistry, runPipeline, type PipelineRunResult } from '../../../../api/engine'
import type { DetectionFinding, FindingDetail } from '../../../../types/finding'

export function useDetectionCenter() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<DetectionFinding[]>([])
  const total = ref(0)
  const detail = ref<FindingDetail | null>(null)
  const drawer = ref(false)
  const filters = reactive<DetectionQuery>({ search: '', severity: '', engine: '', page: 1, page_size: 50 })

  // The engine filter must offer the names findings are actually stored under.
  // The previous hard-coded list (traffic/protocol/zeek/...) never matched
  // ``detection_findings.engine``, so filtering by engine always returned nothing.
  const engineOptions = ref<Array<{ label: string; value: string }>>([])

  async function loadEngines(): Promise<void> {
    try {
      const engines = await getEngineRegistry()
      engineOptions.value = engines.map((e) => ({ label: `${e.label || e.name} (${e.detection_count ?? 0})`, value: e.detection_engine || e.name }))
    } catch {
      engineOptions.value = []
    }
  }

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await listDetections({ ...filters })
      items.value = result.items
      total.value = result.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function open(row: DetectionFinding): Promise<void> {
    try {
      detail.value = await getDetection(row.id)
      drawer.value = true
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function reset(): void { filters.page = 1; load() }

  // --- Manual pipeline trigger ---
  const pipelineOpen = ref(false)
  const pipelineRunning = ref(false)
  const pipelineForm = reactive({ target_type: 'log', log_lines: '', data: '' })
  const pipelineResult = ref<PipelineRunResult | null>(null)

  async function runPipelineNow(): Promise<void> {
    pipelineRunning.value = true
    pipelineResult.value = null
    try {
      let data: Record<string, unknown> = {}
      if (pipelineForm.data.trim()) {
        data = JSON.parse(pipelineForm.data)
      }
      pipelineResult.value = await runPipeline({
        target_type: pipelineForm.target_type,
        log_lines: pipelineForm.log_lines ? pipelineForm.log_lines.split(/\n/).filter(Boolean) : undefined,
        data,
      })
      ElMessage.success('流水线执行完成')
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      pipelineRunning.value = false
    }
  }

  onMounted(async () => {
    await loadEngines()
    await load()
  })

  return {
    loading, error, items, total, detail, drawer, filters, engineOptions,
    pipelineOpen, pipelineRunning, pipelineForm, pipelineResult,
    load, loadEngines, open, reset, runPipelineNow,
  }
}
