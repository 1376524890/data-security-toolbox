export const severityColors: Record<string, string> = {
  Critical: '#b91c1c',
  High: '#ea580c',
  Medium: '#d97706',
  Low: '#2563eb',
}

export const statusColors: Record<string, string> = {
  ready: '#16a34a',
  success: '#16a34a',
  open: '#ea580c',
  running: '#2563eb',
  pending: '#64748b',
  failed: '#b91c1c',
  disabled: '#64748b',
  unavailable: '#b91c1c',
  error: '#b91c1c',
  analyzed: '#16a34a',
  imported: '#16a34a',
}

export const nodeTypeColors: Record<string, string> = {
  probe: '#0ea5e9',
  host: '#2563eb',
  service: '#16a34a',
  database: '#7c3aed',
  data_asset: '#d97706',
  ioc: '#b91c1c',
  incident: '#ea580c',
}

export function severityClass(value?: string): string {
  return (value || 'Low').toLowerCase()
}
