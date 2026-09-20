/**
 * Live-traffic state: the live window, the probe list, the alert summary, the
 * recent captures and the alert stream.
 *
 * The capture rate is derived from the most recently analyzed capture (there is
 * no dedicated live endpoint) and the alert stream is an ``EventSource`` this
 * composable owns: it is opened on mount and closed on unmount, and the newest
 * 50 alerts are kept.  The view keeps the router and the formatters.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { getHealth, type HealthResponse } from '../../../../api/health'
import { listProbes, type Probe } from '../../../../api/probes'
import { getLiveNetwork, type LiveNetwork } from '../../../../api/network'
import { listPcaps } from '../../../../api/pcaps'
import type { PcapRecord } from '../../../../types/pcap'
import { getAlertSummary, alertStreamUrl } from '../../../../api/alerts'

export function useLiveTraffic() {
  const loading = ref(true)
  const error = ref('')
  const health = ref<HealthResponse | null>(null)
  const probes = ref<Probe[]>([])
  const recentPcaps = ref<PcapRecord[]>([])
  const live = ref<LiveNetwork | null>(null)
  const summary = ref<{ total: number; unhandled_critical_high: number } | null>(null)
  const liveAlerts = ref<Array<{ id: number; severity: string; title: string; time: string }>>([])
  let eventSource: EventSource | null = null

  const onlineProbes = computed(() => probes.value.filter((p: Probe) => p.status === 'online'))
  // Derive a real capture rate from the most recently analyzed capture (no dedicated live endpoint).
  const captureRate = computed(() => {
    if (!live.value) return { pps: null as number | null, bps: null as number | null, source: null as string | null }
    return { pps: Math.round(live.value.pps), bps: Math.round(live.value.bps), source: `实时窗口 ${live.value.window_seconds}s` }
  })

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [h, p, s, pcaps, lv] = await Promise.all([
        getHealth(),
        listProbes({ page: 1, page_size: 100 }),
        getAlertSummary(),
        listPcaps({ page: 1, page_size: 5 }),
        getLiveNetwork(),
      ])
      health.value = h
      probes.value = p.items
      summary.value = s
      recentPcaps.value = pcaps.items
      live.value = lv
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  function connect(): void {
    eventSource = new EventSource(alertStreamUrl())
    eventSource.addEventListener('alert', (event) => {
      try {
        const data = JSON.parse(event.data)
        liveAlerts.value.unshift({ id: data.alert_id, severity: data.severity || 'Medium', title: data.title || '新告警', time: new Date().toISOString() })
        liveAlerts.value = liveAlerts.value.slice(0, 50)
      } catch { /* ignore */ }
    })
  }

  onMounted(() => { load(); connect() })
  onBeforeUnmount(() => { eventSource?.close() })

  return {
    loading, error, health, probes, recentPcaps, live, summary, liveAlerts,
    onlineProbes, captureRate, load,
  }
}
