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
  REMOVING: '#2563eb',
  REMOVED: '#0d9488',
  // Deployment state machine (install path). Without these the console falls
  // back to grey for every stage of a live deployment.
  CREATED: '#64748b',
  CONNECTING: '#2563eb',
  PREFLIGHT: '#2563eb',
  UPLOADING: '#2563eb',
  INSTALLING: '#2563eb',
  STARTING: '#2563eb',
  WAIT_CALLBACK: '#ea580c',
  REGISTERED: '#16a34a',
  FAILED: '#b91c1c',
  REMOVAL_PARTIAL: '#ea580c',
  REMOVAL_FAILED: '#b91c1c',
  ONLINE: '#16a34a',
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
