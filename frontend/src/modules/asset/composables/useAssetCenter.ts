/**
 * The asset centre: the paged asset list, the detail drawer with its relation
 * graph, and the network-scan console.
 *
 * The scan console can run on the platform or on a probe; a probe run waits for
 * the probe to poll and only then polls the task itself, which is why the poll
 * budget differs.  The filter field configuration stays in the view because it
 * is static presentation; every API call and every piece of page state lives
 * here.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listAssets, getAsset } from '../../../api/assets'
import { listProbes } from '../../../api/probes'
import { startScan, getScan, type ScanResult } from '../../../api/scan'
import type { Asset, AssetDetail } from '../../../types/asset'

export function useAssetCenter() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<Asset[]>([])
  const total = ref(0)
  const detail = ref<AssetDetail | null>(null)
  const drawer = ref(false)
  const detailLoading = ref(false)
  const activeTab = ref('basic')
  const filters = reactive({ risk: '', asset_type: '', search: '', page: 1, page_size: 50 })
  const scanTarget = ref('')
  const scanTopPorts = ref(200)
  const scanPorts = ref('')
  const scanSource = ref<'platform' | 'probe'>('platform')
  const scanProbeId = ref<number | null>(null)
  const scanNuclei = ref(false)
  const scanNucleiTags = ref('')
  const scanning = ref(false)
  const scanProgress = ref(0)
  const scanStage = ref('')
  const scanResult = ref<ScanResult | null>(null)
  const probes = ref<Array<{ id: number; name: string; ip_address: string; status: string }>>([])

  const scanSummary = computed(() => {
    const info = (scanResult.value?.result || {}) as { assets?: number; alive_hosts?: number; engine?: string; hosts?: string[] }
    return {
      assets: info.assets ?? 0,
      hosts: info.alive_hosts ?? info.hosts?.length ?? 0,
      engine: info.engine || '',
    }
  })

  function parsePorts(): number[] {
    return scanPorts.value
      .split(/[,\s]+/)
      .map((item) => Number.parseInt(item, 10))
      .filter((item) => Number.isInteger(item) && item > 0 && item <= 65535)
  }

  const graphNodes = computed(() => {
    if (!detail.value) return []
    const nodes = [{ id: `asset:${detail.value.asset.id}`, name: detail.value.asset.ip, type: 'host', risk: detail.value.asset.risk_level }]
    detail.value.data_assets.forEach((d) => nodes.push({ id: `data:${d.id}`, name: d.name, type: 'data_asset', risk: d.sensitivity }))
    detail.value.iocs.forEach((i) => nodes.push({ id: `ioc:${i.id}`, name: i.value, type: 'ioc', risk: 'High' }))
    detail.value.incidents.forEach((inc) => nodes.push({ id: `incident:${inc.id}`, name: inc.title, type: 'incident', risk: inc.risk_level }))
    return nodes
  })
  const graphEdges = computed(() => {
    if (!detail.value) return []
    const edges: Array<{ source: string; target: string; label?: string }> = []
    const root = `asset:${detail.value.asset.id}`
    detail.value.data_assets.forEach((d) => edges.push({ source: root, target: `data:${d.id}`, label: 'data' }))
    detail.value.iocs.forEach((i) => edges.push({ source: root, target: `ioc:${i.id}`, label: 'ioc' }))
    detail.value.incidents.forEach((inc) => edges.push({ source: root, target: `incident:${inc.id}`, label: 'incident' }))
    return edges
  })

  const TERMINAL_STATUSES = ['Success', 'Partial', 'Failed', 'Failure']

  async function runScan(): Promise<void> {
    if (!scanTarget.value) { ElMessage.warning('请填写扫描目标'); return }
    if (scanSource.value === 'probe' && !scanProbeId.value) { ElMessage.warning('请选择执行扫描的探针'); return }
    scanning.value = true
    scanResult.value = null
    scanProgress.value = 0
    scanStage.value = '下发扫描任务'
    try {
      const task = await startScan({
        target: scanTarget.value.trim(),
        discovery: scanTarget.value.includes('/') || scanTarget.value.includes('-'),
        top_ports: scanTopPorts.value,
        ports: parsePorts(),
        probe_id: scanSource.value === 'probe' && scanProbeId.value ? scanProbeId.value : undefined,
        nuclei: scanSource.value === 'platform' && scanNuclei.value,
        nuclei_tags: scanNucleiTags.value,
      })
      // Probe jobs wait for the probe to poll (30s) and finish its own bounded scan.
      const maxPolls = scanSource.value === 'probe' ? 200 : 240
      for (let i = 0; i < maxPolls; i++) {
        await new Promise((r) => setTimeout(r, 3000))
        const cur = await getScan(task.id)
        scanProgress.value = cur.progress ?? scanProgress.value
        scanStage.value = cur.current_stage?.replace(/nmap|nuclei|python-tcp|TCP-connect/gi, '服务检测') || scanStage.value
        if (TERMINAL_STATUSES.includes(cur.status)) {
          scanResult.value = cur
          break
        }
      }
      if (!scanResult.value) throw new Error('扫描超时，请稍后在任务中心查看结果')
      if (scanResult.value.status === 'Failed' || scanResult.value.status === 'Failure') {
        throw new Error(scanResult.value.error || '扫描失败')
      }
      if (scanSource.value === 'probe') {
        const info = scanResult.value.result as { assets?: number } | undefined
        ElMessage.success(`探针扫描完成：发现 ${info?.assets ?? 0} 个服务资产`)
      } else {
        const info = scanResult.value.result as { assets?: number; alive_hosts?: number } | undefined
        ElMessage.success(`扫描完成：${info?.alive_hosts ?? 0} 台存活主机，${info?.assets ?? 0} 个服务资产`)
      }
      load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      scanning.value = false
    }
  }

  async function loadProbes(): Promise<void> {
    try {
      const result = await listProbes({ page: 1, page_size: 200 })
      probes.value = result.items.map((item) => ({ id: item.id, name: item.name, ip_address: item.ip_address, status: item.status }))
    } catch {
      probes.value = []
    }
  }

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await listAssets({ ...filters })
      items.value = result.items
      total.value = result.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function open(row: Asset): Promise<void> {
    detailLoading.value = true
    activeTab.value = 'basic'
    drawer.value = true
    try {
      detail.value = await getAsset(row.id)
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      detailLoading.value = false
    }
  }

  function reset(): void { filters.page = 1; load() }

  onMounted(() => { load(); loadProbes() })

  return {
    loading, error, items, total, detail, drawer, detailLoading, activeTab, filters,
    scanTarget, scanTopPorts, scanPorts, scanSource, scanProbeId, scanNuclei, scanNucleiTags,
    scanning, scanProgress, scanStage, scanResult, probes, scanSummary, graphNodes, graphEdges,
    loadProbes, load, open, runScan, reset,
  }
}
