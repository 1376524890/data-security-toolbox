import { defineStore } from 'pinia'
import { ref } from 'vue'
import { getHealth, type HealthResponse } from '../api/health'
import { listIntegrations } from '../api/integrations'
import { getAlertSummary, alertStreamUrl, getAlert } from '../api/alerts'
import type { AlertSummary } from '../types/alert'
import type { IntegrationStatus } from '../types/integration'

export const useSystemStore = defineStore('system', () => {
  const health = ref<HealthResponse | null>(null)
  const integrations = ref<IntegrationStatus[]>([])
  const alertSummary = ref<AlertSummary | null>(null)
  const lastAlert = ref<{ title: string; severity: string; id: number } | null>(null)
  let eventSource: EventSource | null = null
  let timer = 0

  async function refresh(): Promise<void> {
    const [h, i, a] = await Promise.allSettled([getHealth(), listIntegrations(), getAlertSummary()])
    if (h.status === 'fulfilled') health.value = h.value
    if (i.status === 'fulfilled') integrations.value = i.value
    if (a.status === 'fulfilled') alertSummary.value = a.value
  }

  function connect(onAlert?: (alert: { title: string; severity: string; id: number }) => void): void {
    if (eventSource) eventSource.close()
    eventSource = new EventSource(alertStreamUrl())
    eventSource.addEventListener('alert', async (event) => {
      try {
        const data = JSON.parse(event.data)
        const detail = await getAlert(data.alert_id)
        const alert = detail.alert
        lastAlert.value = { title: alert.title, severity: alert.severity, id: alert.id }
        onAlert?.(lastAlert.value)
        alertSummary.value = await getAlertSummary()
      } catch {
        // SSE payload may arrive before DB visibility; next summary refresh fixes the badge.
      }
    })
  }

  function start(): void {
    refresh()
    timer = window.setInterval(refresh, 30000)
  }

  function stop(): void {
    window.clearInterval(timer)
    eventSource?.close()
    eventSource = null
  }

  return { health, integrations, alertSummary, lastAlert, refresh, connect, start, stop }
})
