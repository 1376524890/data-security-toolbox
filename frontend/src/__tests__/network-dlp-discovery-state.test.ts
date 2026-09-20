import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useNetworkDlp } from '../modules/data-security/composables/useNetworkDlp'
import { useSensitiveDiscovery } from '../modules/data-security/composables/useSensitiveDiscovery'
import type { SensitiveFindings } from '../api/dataAssets'
import * as api from '../api/client'
import * as dataAssets from '../api/dataAssets'

vi.mock('../api/client', () => ({
  apiGet: vi.fn(), apiPost: vi.fn(), apiPatch: vi.fn(), apiUpload: vi.fn(), downloadUrl: vi.fn(),
}))
vi.mock('../api/dataAssets', () => ({ getSensitiveFindings: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const mocked = api as unknown as { apiGet: Mock; apiPost: Mock; apiPatch: Mock }
const assets = dataAssets as unknown as { getSensitiveFindings: Mock }

const policy = {
  enabled: true, categories: ['id_card', 'bank_card'], keywords: ['机密', '内部'], fingerprints: ['ab'.repeat(32)],
  min_matches: 2, min_confidence: 0.6, exclude_cidrs: ['127.0.0.0/8'],
}

const transfer = (overrides: Record<string, unknown> = {}) => ({
  task_id: 5, binary_available: true, id: 3, pcap_id: 1, filename: 'dlp.bin', src_ip: '10.0.0.1',
  src_port: 51000, dst_ip: '10.0.0.2', dst_port: 443, size: 2048, sha256: 'c'.repeat(64),
  complete: true, content_type: 'application/octet-stream', matches: [], ...overrides,
})

const dlpRule = (overrides: Record<string, unknown> = {}) => ({
  id: 'bank_card', name: '银行卡', entity: 'bank_card', pattern: '\\d{16}', source: 'builtin',
  enabled: false, confidence: 0.9, sensitive: true, ...overrides,
})

const findings = (overrides: Partial<SensitiveFindings> = {}): SensitiveFindings => ({
  categories: [{ category: 'id_card', count: 3, severity: 'High', risk_score: 80 }],
  entities: [{ category: 'id_card', count: 12 }, { category: 'unknown_thing', count: 1 }],
  details: [],
  sources: [{ source: 'probe-1', kind: 'probe', count: 4 }],
  totals: { findings: 4, categories: 1, entities: 2, objects: 3, instances: 5, detections: 6, data_assets: 2 },
  pagination: { page: 1, page_size: 50, total: 4, pages: 1 },
  note: '只统计已上报的发现',
  data_assets: { total: 2, by_sensitivity: { High: 1, Medium: 1 }, observed: { total: 2, by_sensitivity: {} } },
  ...overrides,
} as SensitiveFindings)

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async <T>(composable: () => T): Promise<T> => {
  let state: T
  const Harness = defineComponent({
    setup() {
      state = composable()
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
  mocked.apiGet.mockImplementation(async (path: string) => {
    if (path === '/dlp/policy') return policy
    if (path === '/dlp/transfers') return { items: [transfer()], coverage: [{ probe_id: 1 }] }
    if (path === '/dlp/rules') return { items: [dlpRule()] }
    return {}
  })
  mocked.apiPost.mockResolvedValue({})
  mocked.apiPatch.mockResolvedValue({})
  assets.getSensitiveFindings.mockResolvedValue(findings())
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('network DLP console state', () => {
  it('loads the policy, the transfers and the rule catalogue together', async () => {
    const state = await mount(() => useNetworkDlp())
    expect(mocked.apiGet).toHaveBeenCalledWith('/dlp/policy')
    expect(mocked.apiGet).toHaveBeenCalledWith('/dlp/transfers')
    expect(mocked.apiGet).toHaveBeenCalledWith('/dlp/rules')
    expect(state.config.min_matches).toBe(2)
    expect(state.keywords.value).toBe('机密\n内部')
    expect(state.hashes.value).toBe('ab'.repeat(32))
    expect(state.cidrs.value).toBe('127.0.0.0/8')
    expect(state.items.value.map((row) => row.id)).toEqual([3])
    expect(state.coverage.value).toEqual([{ probe_id: 1 }])
    expect(state.rules.value.map((rule) => rule.id)).toEqual(['bank_card'])
    expect(state.error.value).toBe('')
    expect(state.busy.value).toBe(false)
  })

  it('saves the policy with the textareas split back into lists', async () => {
    const state = await mount(() => useNetworkDlp())
    state.keywords.value = '机密\n\n  内部  \n'
    state.hashes.value = `${'ab'.repeat(32)}\n\n`
    state.cidrs.value = '127.0.0.0/8\n10.0.0.0/8'
    await state.save()
    expect(mocked.apiPost).toHaveBeenCalledWith('/dlp/policy', expect.objectContaining({
      // keywords are dropped when blank but never trimmed (behaviour unchanged)
      keywords: ['机密', '  内部  '],
      fingerprints: ['ab'.repeat(32)],
      exclude_cidrs: ['127.0.0.0/8', '10.0.0.0/8'],
    }))
    expect(ElMessage.success).toHaveBeenCalled()
    expect(state.busy.value).toBe(false)
  })

  it('shows the server reason when saving the policy is refused', async () => {
    mocked.apiPost.mockRejectedValue(new Error('confidence 必须小于 1'))
    const state = await mount(() => useNetworkDlp())
    await state.save()
    expect(ElMessage.error).toHaveBeenCalledWith('Error: confidence 必须小于 1')
    expect(state.busy.value).toBe(false)
  })

  it('mirrors a toggled builtin rule into the category list', async () => {
    const state = await mount(() => useNetworkDlp())
    await state.toggleRule(dlpRule(), true)
    expect(mocked.apiPatch).toHaveBeenCalledWith('/dlp/rules/bank_card', { enabled: true })
    expect(state.config.categories).toContain('bank_card')

    await state.toggleRule(dlpRule(), false)
    expect(state.config.categories).not.toContain('bank_card')
    expect(mocked.apiGet).toHaveBeenCalledWith('/dlp/rules')
  })

  it('adds a regex rule and keeps the dialog open when the server refuses', async () => {
    const state = await mount(() => useNetworkDlp())
    state.ruleDialog.value = true
    Object.assign(state.newRule, { name: '工号', entity: 'employee_id', pattern: 'EMP\\d+' })
    await state.addRule()
    expect(mocked.apiPost).toHaveBeenCalledWith('/dlp/rules', state.newRule)
    expect(state.ruleDialog.value).toBe(false)
    expect(ElMessage.success).toHaveBeenCalledWith('规则已添加，对新分析任务生效')

    mocked.apiPost.mockRejectedValue(new Error('正则不合法'))
    state.ruleDialog.value = true
    await state.addRule()
    expect(ElMessage.error).toHaveBeenCalled()
    expect(state.ruleDialog.value).toBe(true)
    expect(state.ruleBusy.value).toBe(false)
  })

  it('imports the Presidio rules and reports what came in', async () => {
    const state = await mount(() => useNetworkDlp())
    mocked.apiPost.mockResolvedValue({ imported: 42, version: '2.2.35' })
    await state.importPresidio()
    expect(mocked.apiPost).toHaveBeenCalledWith('/dlp/rules/presidio/update')
    expect(ElMessage.success).toHaveBeenCalledWith('已导入 Presidio 2.2.35：42 条正则规则')
    expect(state.ruleBusy.value).toBe(false)
  })

  it('ignores a slower evidence response for a transfer the user already left', async () => {
    const state = await mount(() => useNetworkDlp())
    let resolveSlow: (value: unknown) => void = () => {}
    mocked.apiGet.mockImplementationOnce(() => new Promise((resolve) => { resolveSlow = resolve }))
    const slow = state.openTransfer(transfer({ id: 3 }) as never)

    mocked.apiGet.mockResolvedValueOnce({ hex: 'bbbb' })
    await state.openTransfer(transfer({ id: 9 }) as never)
    expect(state.binary.value).toBe('bbbb')
    expect(state.selected.value?.id).toBe(9)

    resolveSlow({ hex: 'aaaa' })
    await slow
    expect(state.binary.value).toBe('bbbb')
    expect(state.binaryLoading.value).toBe(false)
    expect(state.drawer.value).toBe(true)
  })

  it('does not request evidence for a transfer whose binary is gone', async () => {
    const state = await mount(() => useNetworkDlp())
    mocked.apiGet.mockClear()
    await state.openTransfer(transfer({ binary_available: false }) as never)
    expect(mocked.apiGet).not.toHaveBeenCalled()
    expect(state.binaryLoading.value).toBe(false)
    expect(state.binary.value).toBe('')
  })

  it('only calls a hit alertable when it is sensitive enough', async () => {
    const state = await mount(() => useNetworkDlp())
    expect(state.alertableHit({ kind: 'id_card', count: 1, samples: [], confidence: 0.9 })).toBe(true)
    expect(state.alertableHit({ kind: 'ip', count: 1, samples: [], sensitive: false })).toBe(false)
    expect(state.alertableHit({ kind: 'id_card', count: 1, samples: [], confidence: 0.2 })).toBe(false)
  })

  it('keeps a failed load in the page state', async () => {
    mocked.apiGet.mockRejectedValue(new Error('DLP 服务不可用'))
    const state = await mount(() => useNetworkDlp())
    expect(state.error.value).toContain('DLP 服务不可用')
    expect(state.busy.value).toBe(false)
  })
})

describe('sensitive discovery view state', () => {
  it('loads the findings and projects them with the category labels', async () => {
    const state = await mount(() => useSensitiveDiscovery())
    expect(assets.getSensitiveFindings).toHaveBeenCalledWith({ page: 1, page_size: 50 })
    expect(state.sensitive.value?.totals.findings).toBe(4)
    expect(state.totals.value?.data_assets).toBe(2)
    expect(state.entityData.value).toEqual([
      { name: '身份证', value: 12 }, { name: 'unknown_thing', value: 1 },
    ])
    expect(state.sensitivityData.value).toEqual([{ name: 'High', value: 1 }, { name: 'Medium', value: 1 }])
    expect(state.sources.value.map((item) => item.source)).toEqual(['probe-1'])
    expect(state.loading.value).toBe(false)
  })

  it('moves the pager and re-queries that page', async () => {
    const state = await mount(() => useSensitiveDiscovery())
    assets.getSensitiveFindings.mockClear()
    state.onPageChange(3)
    await flushing()
    expect(state.page.value).toBe(3)
    expect(assets.getSensitiveFindings).toHaveBeenCalledWith({ page: 3, page_size: 50 })
  })

  it('keeps a failed load in the page state', async () => {
    assets.getSensitiveFindings.mockRejectedValue(new Error('发现接口不可用'))
    const state = await mount(() => useSensitiveDiscovery())
    expect(state.error.value).toBe('发现接口不可用')
    expect(state.loading.value).toBe(false)
    expect(state.sensitive.value).toBeNull()
  })
})
