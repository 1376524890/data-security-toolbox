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
