import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { useLiveTraffic } from '../modules/network/traffic/composables/useLiveTraffic'
import type { HealthResponse } from '../api/health'
import type { Probe } from '../api/probes'
import type { LiveNetwork } from '../api/network'
import type { PcapRecord } from '../types/pcap'
import * as health from '../api/health'
import * as probes from '../api/probes'
import * as network from '../api/network'
import * as pcaps from '../api/pcaps'
import * as alerts from '../api/alerts'

vi.mock('../api/health', () => ({ getHealth: vi.fn() }))
vi.mock('../api/probes', () => ({ listProbes: vi.fn() }))
vi.mock('../api/network', () => ({ getLiveNetwork: vi.fn() }))
vi.mock('../api/pcaps', () => ({ listPcaps: vi.fn() }))
vi.mock('../api/alerts', () => ({
  getAlertSummary: vi.fn(),
  alertStreamUrl: vi.fn(() => '/api/v1/alerts/stream'),
}))

const STREAM_URL = '/api/v1/alerts/stream'

class FakeEventSource {
  static instances: FakeEventSource[] = []
  listeners: Record<string, Array<(event: { data: string }) => void>> = {}
  closed = false
  constructor(public url: string) {
    FakeEventSource.instances.push(this)
  }
  addEventListener(type: string, handler: (event: { data: string }) => void): void {
    ;(this.listeners[type] ||= []).push(handler)
  }
  close(): void {
    this.closed = true
  }
  emit(type: string, data: string): void {
    ;(this.listeners[type] || []).forEach((handler) => handler({ data }))
  }
}

const healthResponse = (overrides: Partial<HealthResponse> = {}): HealthResponse => ({
  status: 'ok', service: 'api', api: '1.0.0', database: 'ok', redis: 'ok',
  celery: { broker: 'redis', workers: 2, running: 1, queued: 0 }, analysis_worker: 'ready',
  worker_capabilities: [], tshark: { available: true, version: '4.0' },
  zeek: { available: true, version: '6.0' }, suricata: { available: false, version: '', rule_count: 0 },
  storage_usage_bytes: 0, storage_max_bytes: 0,
  queue: { pending: 3, running: 1, oldest_pending_age: 9 },
  probe: { count: 1, online: 1, degraded: 0, offline: 0, auth_error: 0 }, ...overrides,
})

const probe = (overrides: Partial<Probe> = {}): Probe => ({
  id: 2, name: 'test123', hostname: 'probe-a', ip_address: '192.168.191.130', status: 'online',
  metadata: {}, created_at: '2026-09-19T09:00:00', ...overrides,
})

const liveNetwork = (overrides: Partial<LiveNetwork> = {}): LiveNetwork => ({
  window_seconds: 60, probes: { online: 1, degraded: 0, total: 1 }, connections: 120, packets: 40000,
  bytes: 6000000, pps: 1234.6, bps: 98765.4, avg_cpu_percent: 12, avg_memory_percent: 30,
  top_src: [{ ip: '10.0.0.1', bytes: 500 }], top_dst: [{ ip: '10.0.0.2', bytes: 400 }],
  top_port: [{ port: 443, bytes: 300 }], alerts_30m: 4, ...overrides,
})

const pcap = (overrides: Partial<PcapRecord> = {}): PcapRecord => ({
  id: 9, filename: 'capture.pcap', size: 1024, sha256: 'a'.repeat(64), packet_count: 40,
  duration: 12, capture_start: '2026-09-19T08:59:00', capture_end: '2026-09-19T09:00:00',
  protocol_summary: { tcp: 30 }, status: 'analyzed', created_at: '2026-09-19T09:00:00',
  ...overrides,
})

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async (): Promise<ReturnType<typeof useLiveTraffic>> => {
  let state: ReturnType<typeof useLiveTraffic>
  const Harness = defineComponent({
    setup() {
      state = useLiveTraffic()
      return () => null
    },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(Harness)
  app.mount(host)
  await flushing()
  return state!
}

beforeEach(() => {
  vi.clearAllMocks()
  FakeEventSource.instances = []
  vi.stubGlobal('EventSource', FakeEventSource)
  vi.mocked(health.getHealth).mockResolvedValue(healthResponse())
  vi.mocked(probes.listProbes).mockResolvedValue({ items: [probe()], total: 1, page: 1, page_size: 100 })
  vi.mocked(alerts.getAlertSummary).mockResolvedValue({
    total: 479, status: {}, severity: {}, unhandled_critical_high: 12,
  })
  vi.mocked(pcaps.listPcaps).mockResolvedValue({ items: [pcap()], total: 1, page: 1, page_size: 5 })
  vi.mocked(network.getLiveNetwork).mockResolvedValue(liveNetwork())
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
  vi.unstubAllGlobals()
})

describe('live traffic state', () => {
  it('loads the health, the probes, the alert summary, the recent captures and the live window', async () => {
    const state = await mount()
    expect(health.getHealth).toHaveBeenCalled()
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 100 })
    expect(alerts.getAlertSummary).toHaveBeenCalled()
    expect(pcaps.listPcaps).toHaveBeenCalledWith({ page: 1, page_size: 5 })
    expect(network.getLiveNetwork).toHaveBeenCalled()
    expect(state.health.value?.queue.pending).toBe(3)
    expect(state.probes.value).toHaveLength(1)
    expect(state.summary.value?.unhandled_critical_high).toBe(12)
    expect(state.recentPcaps.value[0].filename).toBe('capture.pcap')
    expect(state.live.value?.connections).toBe(120)
    expect(state.loading.value).toBe(false)
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(network.getLiveNetwork).mockRejectedValue(new Error('实时窗口不可用'))
    const state = await mount()
    expect(state.error.value).toBe('实时窗口不可用')
    expect(state.loading.value).toBe(false)
    expect(state.live.value).toBeNull()
  })

  it('keeps only the online probes', async () => {
    vi.mocked(probes.listProbes).mockResolvedValue({
      items: [
        probe({ id: 1, status: 'online' }),
        probe({ id: 2, status: 'degraded' }),
        probe({ id: 3, status: 'offline' }),
      ],
      total: 3, page: 1, page_size: 100,
    })
    const state = await mount()
    expect(state.probes.value).toHaveLength(3)
    expect(state.onlineProbes.value.map((item) => item.id)).toEqual([1])
  })

  it('derives the capture rate from the live window and reports none without one', async () => {
    const state = await mount()
    expect(state.captureRate.value).toEqual({ pps: 1235, bps: 98765, source: '实时窗口 60s' })

    state.live.value = null
    expect(state.captureRate.value).toEqual({ pps: null, bps: null, source: null })
  })

  it('opens the alert stream on mount and keeps the newest 50 alerts', async () => {
    const state = await mount()
    expect(FakeEventSource.instances).toHaveLength(1)
    expect(FakeEventSource.instances[0].url).toBe(STREAM_URL)

    const stream = FakeEventSource.instances[0]
    for (let id = 1; id <= 55; id += 1) {
      stream.emit('alert', JSON.stringify({ alert_id: id, severity: 'Critical', title: `告警 ${id}` }))
    }
    expect(state.liveAlerts.value).toHaveLength(50)
    expect(state.liveAlerts.value[0].id).toBe(55)
    expect(state.liveAlerts.value[0].severity).toBe('Critical')
    expect(state.liveAlerts.value[0].title).toBe('告警 55')
    expect(state.liveAlerts.value[0].time).toBeTruthy()
  })

  it('defaults the severity and the title of a stream alert', async () => {
    const state = await mount()
    FakeEventSource.instances[0].emit('alert', JSON.stringify({ alert_id: 7 }))
    expect(state.liveAlerts.value[0]).toMatchObject({ id: 7, severity: 'Medium', title: '新告警' })
  })

  it('ignores a malformed alert event', async () => {
    const state = await mount()
    FakeEventSource.instances[0].emit('alert', '{not json')
    expect(state.liveAlerts.value).toEqual([])
  })

  it('closes the alert stream on unmount', async () => {
    await mount()
    const stream = FakeEventSource.instances[0]
    expect(stream.closed).toBe(false)
    app?.unmount()
    app = undefined
    host?.remove()
    host = undefined
    expect(stream.closed).toBe(true)
  })
})
