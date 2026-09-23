export function formatBytes(value: number): string {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

export function formatDateTime(value?: string | number | null): string {
  if (!value) return '-'
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString('zh-CN', { hour12: false })
}

// 风险评分统一保留两位小数（如 81 -> 81.00, 81.0 -> 81.00, 81.234 -> 81.23）
export function formatRiskScore(value?: number | null): string {
  if (value == null || Number.isNaN(Number(value))) return '-'
  return Number(value).toFixed(2)
}

export function formatDuration(value?: number): string {
  if (!value) return '-'
  const seconds = Math.max(0, Number(value))
  if (seconds < 60) return `${seconds.toFixed(2)}s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${Math.floor(seconds % 60)}s`
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

/** ``2026-09-22`` -> ``09-22``; anything else is passed through untouched.
 *
 * Both homepages shorten the server's ISO day buckets with this one helper, so a
 * chart axis label cannot differ between the cockpit and the wall screen. */
export function shortDay(value: string): string {
  return /^\d{4}-\d{2}-\d{2}/.test(value) ? value.slice(5, 10) : value
}

/** Coverage limits all follow one rule: 0 means "no limit".
 *
 * Printing the raw 0 next to a limit label makes an unlimited scan read like a
 * capped one, so both the task centre and the collection dialog use this. */
export function formatCoverageLimit(value?: number | null): string {
  if (value == null || Number.isNaN(Number(value))) return '-'
  return Number(value) > 0 ? String(value) : '不限制'
}

/** Scanner termination codes, translated once.
 *
 * The same code is shown in the task centre and in the collection result; a
 * second copy of this table would let the two disagree. An unknown code falls
 * through unchanged so a new reason is visible instead of hidden. */
const TERMINATION_LABELS: Record<string, string> = {
  complete: '正常完成',
  timeout: '执行超时',
  time_budget: '执行超时',
  cancelled: '已取消',
  file_budget: '达到文件上限',
  directory_budget: '达到目录上限',
  byte_budget: '达到读取字节上限',
  single_file_limit: '单文件超过上限',
  row_budget: '达到行数上限',
  depth_or_exclude: '达到目录深度上限或排除规则',
  depth_limit: '达到目录深度上限',
  resource_limit: '达到资源上限',
  unreadable: '内容无法读取',
  unconfigured: '未配置扫描范围',
  file_changed_during_read: '读取期间文件发生变化',
  // Content-level reasons a single file can carry (parsers and the sampler).
  sampled: '按头/中/尾采样',
  row_limit: '达到行数上限',
  line_truncated: '行内容被截断',
  binary_metadata_only: '二进制文件仅登记元数据',
}

/** The per-file coverage verdict that sits next to the reason above. */
const COVERAGE_LABELS: Record<string, string> = {
  complete: '内容完整',
  partial: '部分内容',
  unsupported: '未解析内容',
  failed: '读取失败',
}

export function formatCoverage(coverage?: string | null): string {
  if (!coverage) return '-'
  return COVERAGE_LABELS[coverage] || coverage
}

export function formatTerminationReason(reason?: string | null): string {
  if (!reason) return '-'
  return TERMINATION_LABELS[reason] || reason
}
