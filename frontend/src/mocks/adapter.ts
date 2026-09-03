import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios'
import * as data from './data'

type Params = Record<string, unknown>

function paginate<T>(list: T[], params: Params): { items: T[]; page: number; page_size: number; total: number } {
  const page = Number(params.page || 1)
  const pageSize = Number(params.page_size || 50)
  const start = (page - 1) * pageSize
  return { items: list.slice(start, start + pageSize), page, page_size: pageSize, total: list.length }
}

function findById<T extends { id: number }>(list: T[], id: number): T | null {
  return list.find((item) => item.id === id) || null
}

// Deep clone to avoid mutation across requests.
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value))
}

function route(method: string, url: string, params: Params, body: unknown): unknown {
  const path = url.replace(/^\/api\/v1/, '')
  const [basePath, ...rest] = path.split('/')
  const parts = path.split('/').filter(Boolean)


  // ---- Auth ----
  if (path === '/auth/me' && method === 'get') return { id: 1, username: 'demo_admin', role: 'admin' }
  if (path === '/auth/login' && method === 'post') return { id: 1, username: 'demo_admin', role: 'admin' }
  if (path === '/auth/logout' && method === 'post') return { status: 'ok' }

  // ---- Health ----
  if (path === '/health') return clone(data.health)

  // ---- Dashboard ----
  if (path === '/dashboard/summary') return clone(data.dashboardSummary)
  if (path === '/dashboard/risk-trend') return clone(data.riskTrend)
  if (path === '/dashboard/severity') return clone(data.dashboardSeverity)
  if (path === '/dashboard/engines') return clone(data.dashboardEngines)
  if (path === '/dashboard/incidents') return { items: clone(data.incidents.slice(0, 10)) }
  if (path === '/dashboard/high-risk-assets') return { items: clone(data.assets.filter((a) => ['Critical', 'High'].includes(a.risk_level)).slice(0, 10)) }
  if (path === '/dashboard/sensitive-data') return clone(data.dashboardSensitive)
  if (path === '/risk/summary') return clone(data.riskSummary)

  // ---- Alerts ----
  if (path === '/alerts' && method === 'get') return paginate(clone(data.alerts), params)
  if (path === '/alerts/summary') return clone(data.alertSummary)
  if (path === '/alerts' && method === 'post') return clone(data.alerts[0])
  if (parts[0] === 'alerts' && parts.length === 2 && method === 'get') {
    const id = Number(parts[1])
    const alert = findById(data.alerts, id)
    if (!alert) return { detail: 'alert not found' }
    const finding = findById(data.detections, alert.finding_id || 900)
    const incident = alert.incident_id ? findById(data.incidents, alert.incident_id) : null
    return {
      alert: clone(alert),
      finding: finding ? clone(finding) : null,
      incident: incident ? clone(incident) : null,
      probe: clone(data.probes.find((p) => p.id === alert.probe_id) || null),
      pcap: clone(data.pcaps[0] || null),
      deliveries: [
        { id: 1, channel: 'webhook', target: 'https://soc.example.com/hook', status: 'success', attempts: 1, last_error: '', sent_at: data.iso(Date.now() - 5000) },
        { id: 2, channel: 'email', target: 'soc@example.com', status: 'failed', attempts: 3, last_error: 'SMTP timeout', sent_at: null },
      ],
    }
  }
  if (parts[0] === 'alerts' && parts.length === 2 && method === 'patch') {
    const id = Number(parts[1])
    const alert = findById(data.alerts, id) || data.alerts[0]
    return { ...clone(alert), ...(body as Record<string, unknown>), id: alert.id, last_seen: data.iso(Date.now()) }
  }

  // ---- Incidents ----
  if (path === '/incidents' && method === 'get') return paginate(clone(data.incidents), params)
  if (path === '/incidents' && method === 'post') return clone(data.incidents[0])
  if (parts[0] === 'incidents' && parts.length === 2 && method === 'get') {
    const id = Number(parts[1])
    return clone(findById(data.incidents, id) || data.incidents[0])
  }
  if (parts[0] === 'incidents' && parts.length === 2 && method === 'patch') {
    const id = Number(parts[1])
    const inc = findById(data.incidents, id) || data.incidents[0]
    return { ...clone(inc), ...(body as Record<string, unknown>), id: inc.id }
  }

  // ---- Detections ----
  if (path === '/detections' && method === 'get') return paginate(clone(data.detections), params)
  if (parts[0] === 'detections' && parts.length === 2) {
    const id = Number(parts[1])
    const det = findById(data.detections, id) || data.detections[0]
    return { detection: clone(det), related_incidents: clone(data.incidents.slice(0, 2)), pcap: clone(data.pcaps[0]), alert: clone(data.alerts[0]) }
  }

  // ---- Assets ----
  if (path === '/assets' && method === 'get') return paginate(clone(data.assets), params)
  if (path === '/assets/summary') return { count: data.assets.length, risk: { Critical: 3, High: 4, Medium: 4, Low: 3 } }
  if (path === '/assets/relations') return []
  if (parts[0] === 'assets' && parts.length === 2 && method === 'get') {
    const id = Number(parts[1])
    const asset = findById(data.assets, id) || data.assets[0]
    return {
      asset: clone(asset),
      findings: clone(data.detections.slice(0, 3)),
      incidents: clone(data.incidents.slice(0, 2)),
      data_assets: clone(data.dataAssets.slice(0, 2)),
      iocs: clone(data.iocs.slice(0, 2)),
      relations: clone(data.graph.relations.slice(0, 3)),
    }
  }

  // ---- PCAPs ----
  if (path === '/pcaps' && method === 'get') return paginate(clone(data.pcaps), params)
  if (path === '/pcaps' && method === 'post') return { id: 999, task_id: 101, filename: 'uploaded.pcap', size: 1024 }
  if (parts[0] === 'pcaps' && parts.length === 2 && method === 'get') return clone(findById(data.pcaps, Number(parts[1])) || data.pcaps[0])
  if (parts[0] === 'pcaps' && parts.length === 2 && method === 'post') return clone(data.tasks[0])
  if (parts[0] === 'pcaps' && parts[2] === 'flows') return paginate(clone(data.flows), params)
  if (parts[0] === 'pcaps' && parts[2] === 'packets') return paginate(clone(data.packets), params)
  if (parts[0] === 'pcaps' && parts[2] === 'alerts') return clone(data.pcapAlerts)
  if (parts[0] === 'pcaps' && parts[2] === 'dns') return clone(data.pcapDns)
  if (parts[0] === 'pcaps' && parts[2] === 'http') return clone(data.pcapHttp)
  if (parts[0] === 'pcaps' && parts[2] === 'tls') return clone(data.pcapTls)
  if (parts[0] === 'pcaps' && parts[2] === 'files') return clone(data.pcapFiles)
  if (parts[0] === 'pcaps' && parts[2] === 'traffic') return clone(data.traffic)
  if (parts[0] === 'pcaps' && parts[2] === 'protocols') return clone(data.pcapProtocols)
  if (parts[0] === 'pcaps' && parts[2] === 'anomalies') return clone(data.pcapAnomalies)

  // ---- Data assets ----
  if (path === '/data/assets' && method === 'get') return paginate(clone(data.dataAssets), params)
  if (parts[0] === 'data' && parts[2] === 'assets' && parts.length === 3 && method === 'get') {
    const id = Number(parts[3])
    const item = findById(data.dataAssets, id) || data.dataAssets[0]
    return { data_asset: clone(item), findings: clone(data.detections.filter((d) => d.engine === 'data').slice(0, 3)), pii_summary: { phone: 42, id_card: 18, email: 56 } }
  }

  // ---- Files ----
  if (path === '/files' && method === 'get') return paginate(clone(data.files), params)
  if (path === '/files' && method === 'post') return { id: 999, name: 'upload.bin', size: 1024 }
  if (parts[0] === 'files' && parts.length === 2 && method === 'get') {
    const id = Number(parts[1])
    const file = findById(data.files, id) || data.files[0]
    return { file: clone(file), findings: clone(data.detections.slice(0, 2)), data_assets: clone(data.dataAssets.slice(0, 1)) }
  }
  if (parts[0] === 'files' && parts.length === 2 && method === 'post') return clone(data.tasks[0])

  // ---- IOCs ----
  if (path === '/iocs' && method === 'get') return paginate(clone(data.iocs), params)
  if (parts[0] === 'iocs' && parts[2] === 'associations') {
    const id = Number(parts[1])
    const ioc = findById(data.iocs, id) || data.iocs[0]
    return { ioc: clone(ioc), findings: clone(data.detections.slice(0, 3)), incidents: clone(data.incidents.slice(0, 2)), assets: clone(data.assets.slice(0, 2)) }
  }

  // ---- Offline ----
  if (path === '/offline/resources') return clone(data.offlineResources)
  if (path === '/offline/cves') return clone(data.localCves)

  // ---- Integrations ----
  if (path === '/integrations') return clone(data.integrations)
  if (path === '/engine/registry') return clone(data.engineRegistry)

  // ---- Probes ----
  if (path === '/probes' && method === 'get') return paginate(clone(data.probes), params)
  if (path === '/probes' && method === 'post') return { id: 999, name: 'probe-new', token: 'demo-token' }
  if (parts[0] === 'probes' && parts[2] === 'tasks') return clone(data.tasks.slice(0, 5))
  if (parts[0] === 'probes' && parts[2] === 'analyze') return clone(data.tasks[0])

  // ---- Tasks ----
  if (path === '/tasks' && method === 'get') return paginate(clone(data.tasks), params)
  if (path === '/tasks' && method === 'post') return clone(data.tasks[0])
  if (parts[0] === 'tasks' && parts.length === 2 && method === 'get') return clone(findById(data.tasks, Number(parts[1])) || data.tasks[0])

  // ---- Reports ----
  if (path === '/reports' && method === 'get') return paginate(clone(data.reports), params)
  if (path === '/reports' && method === 'post') return clone(data.reports[0])
  if (parts[0] === 'reports' && parts[2] === 'download') return { status: 'ok', url: '/reports/download' }

  // ---- Graph / Audit / Analysis ----
  if (path === '/graph') return clone(data.graph)
  if (path === '/audit/summary') return clone(data.auditSummary)
  if (path === '/analysis/results') return []

  // ---- Fallback ----
  return { detail: `mock: no route for ${method} ${path}` }
}

export function mockAdapter(config: InternalAxiosRequestConfig): Promise<AxiosResponse> {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  const params = (config.params || {}) as Params
  const body = config.data ? (typeof config.data === 'string' ? JSON.parse(config.data) : config.data) : null
  const payload = route(method, url, params, body)
  // Simulate realistic network latency
  return new Promise((resolve) => {
    setTimeout(() => resolve({ data: payload, status: 200, statusText: 'OK', headers: {}, config }), 180 + Math.random() * 220)
  })
}
