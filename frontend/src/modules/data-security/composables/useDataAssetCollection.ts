import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { collectProbeDataAssets } from '../../../api/probes'
import { getTask } from '../../../api/tasks'
import { formatTerminationReason } from '../../../utils/format'

/** Collection owns its progress; a completed report asks the read side to refresh. */
export function useDataAssetCollection(onCollected: () => void) {
  const collectDialog = ref(false)
  const collecting = ref(false)
  const collectProgress = ref(0)
  const collectStage = ref('')
  // 0 = 不限制 for every coverage knob: the dialog must not quietly cap a scan at
  // 200 files / depth 3 / 120 s, which is what made every inventory stop early.
  const collectForm = reactive({ probe_id: null as number | null, pathsText: '', max_files: 0, max_depth: 0, timeout_seconds: 0, include_databases: true })

  function openCollect(): void {
    collectDialog.value = true
    collectProgress.value = 0
    collectStage.value = ''
  }

  // A finished run is not the same as a finished scope: name what was missed
  // instead of letting "100%" read as full coverage.
  function partialReason(result: { coverage?: Record<string, unknown>; not_observed?: number }): string {
    const coverage = result.coverage || {}
    const parts: string[] = []
    if (coverage.termination_reason) {
      parts.push(`终止原因：${formatTerminationReason(String(coverage.termination_reason))}`)
    }
    const truncated = coverage.truncated_files
    if (Array.isArray(truncated) && truncated.length) parts.push(`仅采样内容的文件 ${truncated.length} 个`)
    // 0 is "no limit", so it must not be reported as if it were a cap.
    if (Number(coverage.max_files) > 0) parts.push(`文件上限 ${String(coverage.max_files)}`)
    if (coverage.max_depth != null && Number(coverage.max_depth) > 0) {
      parts.push(`目录深度上限 ${String(coverage.max_depth)}`)
    }
    if (coverage.files_analyzed != null && coverage.files_discovered != null) {
      parts.push(`已分析 ${String(coverage.files_analyzed)}/${String(coverage.files_discovered)}`)
    }
    if (result.not_observed) parts.push(`${result.not_observed} 个实例未再观测`)
    return parts.length ? parts.join('，') : '覆盖范围未完成，详见任务中心'
  }

  async function submitCollect(): Promise<void> {
    if (!collectForm.probe_id) { ElMessage.warning('请选择探针'); return }
    const paths = collectForm.pathsText.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)
    if (!paths.length) { ElMessage.warning('请填写至少一个采集目录（绝对路径），例如 /srv/data'); return }
    collecting.value = true
    collectProgress.value = 5
    collectStage.value = '下发采集任务'
    try {
      const task = await collectProbeDataAssets(collectForm.probe_id, {
        paths,
        max_files: collectForm.max_files,
        max_depth: collectForm.max_depth,
        timeout_seconds: collectForm.timeout_seconds,
        include_databases: collectForm.include_databases,
      })
      for (let i = 0; i < 100; i++) {
        await new Promise((resolve) => setTimeout(resolve, 3000))
        const current = await getTask(task.id)
        collectProgress.value = current.progress ?? collectProgress.value
        collectStage.value = current.current_stage || collectStage.value
        const status = String(current.status || '')
        if (['Cancelled', 'Canceled'].includes(status)) {
          collectStage.value = '已取消'
          throw new Error('采集任务已取消')
        }
        if (['Success', 'Partial', 'Failed', 'Failure'].includes(status)) {
          collectProgress.value = 100
          const result = (current.result || {}) as { assets?: number; coverage?: Record<string, unknown>; not_observed?: number }
          if (status === 'Failed' || status === 'Failure') throw new Error(current.error || '采集失败')
          if (status === 'Partial') {
            collectStage.value = '部分完成'
            ElMessage.warning(`采集部分完成：已上报 ${result.assets ?? 0} 个资产；${partialReason(result)}`)
            collectDialog.value = false
            onCollected()
            return
          }
          ElMessage.success(`数据资产采集完成：${result.assets ?? 0} 个资产`)
          collectDialog.value = false
          onCollected()
          return
        }
      }
      throw new Error('采集超时，请稍后在任务中心查看结果')
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      collecting.value = false
    }
  }

    return { collectDialog, collecting, collectProgress, collectStage, collectForm,
      openCollect, submitCollect }
}
