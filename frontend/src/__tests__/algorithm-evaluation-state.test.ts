import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useAlgorithmEvaluation } from '../modules/tools/composables/useAlgorithmEvaluation'
import { defaultCodeSample } from '../modules/tools/complexityAnalysis'
import type { Probe } from '../api/probes'
import type { CryptoProbeProfile } from '../api/crypto'
import * as probes from '../api/probes'
import * as crypto from '../api/crypto'

vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))
vi.mock('../api/probes', () => ({ listProbes: vi.fn() }))
vi.mock('../api/crypto', () => ({ getCryptoProbeProfile: vi.fn() }))

const probe = (id: number, status: string): Probe => ({
  id, name: `probe-${id}`, hostname: `host-${id}`, ip_address: `10.0.0.${id}`, status,
} as Probe)

const profile = (overrides: Partial<CryptoProbeProfile> = {}): CryptoProbeProfile => ({
  probe_id: 1, probe_name: '探针一号', hostname: 'host-1', ip_address: '10.0.0.1',
  config: {
    algorithms: ['SM4', 'SM3'], cipherSuites: ['TLS_ECDHE_SM2_WITH_SM4_GCM_SM3'],
    protocols: ['TLSv1.3'], keyLengths: [256], keyManagement: { rotationDays: 30 },
  },
  passwordTypes: ['TLS'], passwordSignals: [], tlsHandshakeCount: 12, serviceCount: 4,
  coverage: { algorithms: 'detected' }, sources: ['banner'],
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

const mount = async (): Promise<ReturnType<typeof useAlgorithmEvaluation>> => {
  let state: ReturnType<typeof useAlgorithmEvaluation>
  const Harness = defineComponent({
    setup() {
      state = useAlgorithmEvaluation()
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
  vi.mocked(probes.listProbes).mockResolvedValue({ items: [probe(1, 'online'), probe(2, 'offline')], total: 2, page: 1, page_size: 100 })
  vi.mocked(crypto.getCryptoProbeProfile).mockResolvedValue(profile())
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('algorithm evaluation state', () => {
  it('starts on the cryptography tab with the default configuration and sample', async () => {
    const state = await mount()
    expect(state.activeTab.value).toBe('crypto')
    expect(state.cryptoConfig.value.algorithms).toEqual(['SM4', 'SM3', 'SM2', 'AES-256'])
    expect(state.cryptoResult.value).toBeNull()
    expect(state.algorithmText.value).toBe('SM4, SM3, SM2, AES-256')
    expect(state.language.value).toBe('javascript')
    expect(state.code.value).toBe(defaultCodeSample)
    expect(state.complexityResult.value).toBeNull()
  })

  it('loads the probe list on mount', async () => {
    const state = await mount()
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 100 })
    expect(state.probes.value.map((p) => p.id)).toEqual([1, 2])
    expect(state.selectedProbeId.value).toBeNull()
  })

  it('keeps an empty probe list when the API returns none', async () => {
    vi.mocked(probes.listProbes).mockResolvedValue({ items: [], total: 0, page: 1, page_size: 100 })
    const state = await mount()
    expect(state.probes.value).toEqual([])
  })

  it('reports a failed probe list without leaving the page running', async () => {
    vi.mocked(probes.listProbes).mockRejectedValue(new Error('探针列表不可用'))
    const state = await mount()
    expect(ElMessage.error).toHaveBeenCalledWith('探针列表不可用')
    expect(state.probes.value).toEqual([])
    expect(state.detecting.value).toBe(false)
  })

  it('assesses the default configuration as compliant', async () => {
    const state = await mount()
    state.runCrypto()
    expect(state.cryptoResult.value?.level).toBe('合规')
    expect(state.cryptoResult.value?.sm4RoundTrip).toBe(true)
    expect(ElMessage.success).toHaveBeenCalledWith('商用密码应用安全性评估完成')
    expect(state.cryptoRunning.value).toBe(false)
  })

  it('syncs the four text inputs into the configuration before assessing', async () => {
    const state = await mount()
    state.algorithmText.value = 'SM4, SM3\nRC4; '
    state.suiteText.value = 'TLS_ECDHE_SM2_WITH_SM4_GCM_SM3'
    state.protocolText.value = 'TLSv1.2, TLSv1.1'
    state.keyLengthText.value = '256, abc, 1024'
    state.runCrypto()
    expect(state.cryptoConfig.value.algorithms).toEqual(['SM4', 'SM3', 'RC4'])
    expect(state.cryptoConfig.value.protocols).toEqual(['TLSv1.2', 'TLSv1.1'])
    expect(state.cryptoConfig.value.keyLengths).toEqual([256, 1024])
    expect(state.cryptoResult.value?.findings.some((f) => f.level === 'Critical')).toBe(true)
  })

  it('loads the weak preset, clears the previous result and reports a low score', async () => {
    const state = await mount()
    state.runCrypto()
    state.loadPreset('weak')
    expect(state.cryptoResult.value).toBeNull()
    expect(state.algorithmText.value).toBe('MD5, 3DES, RC4, RSA')
    expect(state.keyLengthText.value).toBe('512, 1024')
    expect(state.cryptoConfig.value.keyManagement.rotationDays).toBe(365)
    state.runCrypto()
    expect(state.cryptoResult.value!.overallScore).toBeLessThan(90)
    expect(state.cryptoLevelTone.value).toBe('danger')
  })

  it('maps the assessment levels to the tones the template renders', async () => {
    const state = await mount()
    const withLevel = (level: string) => {
      state.cryptoResult.value = { level } as unknown as typeof state.cryptoResult.value
      return state.cryptoLevelTone.value
    }
    expect(withLevel('合规')).toBe('success')
    expect(withLevel('基本合规')).toBe('info')
    expect(withLevel('部分合规')).toBe('warning')
    expect(withLevel('不合规')).toBe('danger')
  })

  it('refuses to detect from a probe without a selection', async () => {
    const state = await mount()
    await state.autoDetectFromProbe()
    expect(ElMessage.warning).toHaveBeenCalledWith('请先选择探针')
    expect(crypto.getCryptoProbeProfile).not.toHaveBeenCalled()
    expect(state.detecting.value).toBe(false)
  })

  it('fills the configuration from the probe and assesses it straight away', async () => {
    const state = await mount()
    state.selectedProbeId.value = 1
    await state.autoDetectFromProbe()
    expect(crypto.getCryptoProbeProfile).toHaveBeenCalledWith(1)
    expect(state.cryptoConfig.value.algorithms).toEqual(['SM4', 'SM3'])
    expect(state.cryptoConfig.value.keyLengths).toEqual([256])
    expect(state.algorithmText.value).toBe('SM4, SM3')
    expect(state.keyLengthText.value).toBe('256')
    expect(state.detectedProfile.value?.probe_name).toBe('探针一号')
    expect(state.cryptoResult.value).not.toBeNull()
    expect(ElMessage.success).toHaveBeenCalledWith('已从探针「探针一号」自动识别并填充，开始评估')
    expect(state.detecting.value).toBe(false)
  })

  it('falls back to the defaults for the empty profile fields', async () => {
    vi.mocked(crypto.getCryptoProbeProfile).mockResolvedValue(profile({
      config: { algorithms: [], cipherSuites: [], protocols: [], keyLengths: [], keyManagement: {} },
    }))
    const state = await mount()
    state.selectedProbeId.value = 1
    await state.autoDetectFromProbe()
    expect(state.cryptoConfig.value.algorithms).toEqual(['SM4', 'SM3', 'SM2', 'AES-256'])
    expect(state.cryptoConfig.value.cipherSuites).toEqual(['TLS_ECDHE_SM2_WITH_SM4_GCM_SM3', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'])
    expect(state.cryptoConfig.value.keyLengths).toEqual([256, 2048, 128])
    expect(state.cryptoConfig.value.keyManagement.rotationDays).toBe(60)
    expect(state.cryptoConfig.value.passwordSignals).toEqual([])
  })

  it('keeps the probe password signals in the assessment findings', async () => {
    vi.mocked(crypto.getCryptoProbeProfile).mockResolvedValue(profile({
      passwordSignals: [{ type: 'weak_auth', level: 'High', detail: '检测到匿名 FTP 访问' }],
    }))
    const state = await mount()
    state.selectedProbeId.value = 1
    await state.autoDetectFromProbe()
    expect(state.cryptoResult.value?.findings.some((f) => f.dimension === '密码/认证' && f.title === '检测到匿名 FTP 访问')).toBe(true)
  })

  it('reports a failed profile read and clears the detecting flag', async () => {
    vi.mocked(crypto.getCryptoProbeProfile).mockRejectedValue(new Error('探针离线'))
    const state = await mount()
    state.selectedProbeId.value = 1
    await state.autoDetectFromProbe()
    expect(ElMessage.error).toHaveBeenCalledWith('探针离线')
    expect(state.detecting.value).toBe(false)
    expect(state.detectedProfile.value).toBeNull()
    expect(state.cryptoResult.value).toBeNull()
  })

  it('analyses the sample code for the selected language', async () => {
    const state = await mount()
    state.runComplexity()
    expect(state.complexityResult.value?.language).toBe('javascript')
    expect(state.complexityResult.value!.bigO.time).toBeTruthy()
    expect(state.complexityResult.value!.lines).toBeGreaterThan(0)
    expect(ElMessage.success).toHaveBeenCalledWith('复杂度分析完成')
    expect(state.complexityRunning.value).toBe(false)
  })

  it('analyses the code of the language the operator picked', async () => {
    const state = await mount()
    state.code.value = 'def f(n):\n    for i in range(n):\n        pass'
    state.language.value = 'python'
    state.runComplexity()
    expect(state.complexityResult.value?.language).toBe('python')
    expect(state.complexityResult.value!.bigO.time).toBeTruthy()
  })
})