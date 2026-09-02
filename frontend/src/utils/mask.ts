function maskDigits(value: string, prefix: number, suffix: number, placeholder = '*'): string {
  const clean = value.replace(/\s/g, '')
  if (clean.length <= prefix + suffix) return clean
  return `${clean.slice(0, prefix)}${placeholder.repeat(Math.min(clean.length - prefix - suffix, 12))}${clean.slice(-suffix)}`
}

export function maskSensitiveValue(value: string): string {
  const clean = value.trim()
  if (!clean) return clean
  if (/^1[3-9]\d{9}$/.test(clean)) return maskDigits(clean, 3, 4)
  if (/^\d{17}[\dXx]$/.test(clean) || /^\d{15}$/.test(clean)) return maskDigits(clean, 6, 4)
  if (/^(?:\d[ -]?){12,23}$/.test(clean)) return maskDigits(clean.replace(/\s/g, ''), 4, 4)
  if (/^(?:sk-|AKIA|ghp_|AIza)/i.test(clean)) return `${clean.slice(0, 4)}****${clean.slice(-4)}`
  if (/^(password|passwd|secret|token|api[_-]?key)/i.test(clean)) return `${clean.slice(0, 8)}****`
  return clean
}

export function maskRecord(value: unknown): unknown {
  if (typeof value === 'string') return maskSensitiveValue(value)
  if (Array.isArray(value)) return value.map(maskRecord)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, isPasswordLikeKey(key) && typeof item === 'string' ? '****' : maskRecord(item)]))
  }
  return value
}

export function isPasswordLikeKey(key: string): boolean {
  return /password|passwd|secret|token|api[_-]?key/i.test(key)
}
