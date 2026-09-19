/**
 * Security-audit state: the read-only audit summary and the log-analysis run.
 *
 * The summary is only ever read.  The log console is the only thing that sends
 * anything: the pasted lines go to the server as they are typed, and the answer
 * is projected into the match groups the template renders.  The static risk
 * labels stay in the view.
 */
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getAuditSummary, analyzeLog, type AuditSummary, type LogAnalysisResult } from '../../../../api/audit'

export function useSecurityAudit() {
  const loading = ref(true)
  const error = ref('')
  const summary = ref<AuditSummary | null>(null)

  const logContent = ref('')
  const logRunning = ref(false)
  const logResult = ref<LogAnalysisResult | null>(null)
  const logError = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      summary.value = await getAuditSummary()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function runLogAnalysis(): Promise<void> {
    if (!logContent.value.trim()) {
      ElMessage.warning('请输入待分析日志内容')
      return
    }
    logRunning.value = true
    logError.value = ''
    try {
      logResult.value = await analyzeLog(logContent.value)
    } catch (err) {
      logError.value = err instanceof Error ? err.message : String(err)
    } finally {
      logRunning.value = false
    }
  }

  function matchGroups(result: LogAnalysisResult): Array<{ key: string; label: string; lines: string[] }> {
    const labels: Record<string, string> = {
      auth_failure: '认证失败',
      sql_error: 'SQL 错误',
      port_scan: '端口扫描',
      privilege: '提权/特权',
      traversal: '路径穿越',
    }
    const matches: Record<string, string[] | undefined> = (result?.log_summary?.matches as Record<string, string[] | undefined>) || {}
    return Object.entries(labels).map(([key, label]) => ({ key, label, lines: matches[key] || [] })).filter((item) => item.lines.length > 0)
  }

  onMounted(load)

  return {
    loading, error, summary, logContent, logRunning, logResult, logError,
    load, runLogAnalysis, matchGroups,
  }
}
