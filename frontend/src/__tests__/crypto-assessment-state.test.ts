import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useCryptoAssessment } from '../modules/tasks/assessment/composables/useCryptoAssessment'
import { assessCrypto, defaultCryptoConfig } from '../modules/tasks/assessment/cryptoAssessment'

vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

beforeEach(() => vi.clearAllMocks())

/** A scan-derived profile, exactly the shape ``result.crypto_profiles[host]``
 *  carries: the server already folded the banners and handshakes into it. */
const profile = {
  config: {
    algorithms: ['SHA1', 'SM4'],
    cipherSuites: ['TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
    protocols: ['TLSv1.0'],
    keyLengths: [1024],
    keyManagement: { rotationDays: 365, storage: 'file', useHardware: false },
  },
  passwordSignals: [{
    type: 'weak_auth' as const, service: 'telnet', port: 23, level: 'Critical' as const,
    detail: 'Telnet 明文口令认证', recommendation: '改用 SSH',
  }],
  passwordTypes: ['明文口令'],
  tlsHandshakeCount: 2,
  serviceCount: 5,
  coverage: { algorithms: 'detected', protocols: 'detected' },
}

describe('crypto assessment state', () => {
  it('assesses the host a scan already observed', () => {
    const state = useCryptoAssessment({ profiles: ref({ '10.0.0.9': profile }) })
    expect(state.hostKeys.value).toEqual(['10.0.0.9'])
    expect(state.hostKey.value).toBe('10.0.0.9')

    const result = state.assessSelected()

    expect(result).not.toBeNull()
    expect(state.source.value?.label).toBe('10.0.0.9')
    expect(state.source.value?.serviceCount).toBe(5)
    // The observed facts, not the shipped sample: SHA1 and 3DES are violations.
    expect(state.algorithmText.value).toBe('SHA1, SM4')
    expect(result?.findings.some((item) => item.title.includes('SHA1'))).toBe(true)
    expect(result?.overallScore).toBe(63)
    expect(result?.level).toBe('部分合规')
    expect(state.levelTone.value).toBe('warning')
  })

  it('folds the observed password/authentication signals into the findings', () => {
    const state = useCryptoAssessment({ profiles: ref({ '10.0.0.9': profile }) })
    const result = state.assessSelected()
    const auth = result?.findings.filter((item) => item.dimension === '密码/认证') || []
    expect(auth).toHaveLength(1)
    expect(auth[0].level).toBe('Critical')
    expect(auth[0].recommendation).toBe('改用 SSH')
  })

  it('fills the gaps with the shipped defaults instead of assessing nothing', () => {
    const state = useCryptoAssessment({
      profiles: ref({ '10.0.0.9': { config: { protocols: ['TLSv1.2'] } } }),
    })
    state.assessSelected()
    // A host that exposed only its protocol still gets a complete form, so it
    // cannot score a perfect 100 by having empty lists.
    expect(state.config.value.algorithms).toEqual(defaultCryptoConfig.algorithms)
    expect(state.config.value.keyLengths).toEqual(defaultCryptoConfig.keyLengths)
    expect(state.config.value.protocols).toEqual(['TLSv1.2'])
  })

  it('warns instead of assessing when no host is selected', () => {
    const state = useCryptoAssessment({ profiles: ref({}) })
    expect(state.assessSelected()).toBeNull()
    expect(ElMessage.warning).toHaveBeenCalled()
  })

  it('drops the previous selection when the task is swapped', async () => {
    const profiles = ref<Record<string, typeof profile>>({ '10.0.0.9': profile })
    const state = useCryptoAssessment({ profiles })
    profiles.value = { '10.0.0.10': profile }
    await Promise.resolve()
    await Promise.resolve()
    expect(state.hostKey.value).toBe('10.0.0.10')
  })

  it('keeps the two presets as the documented pass and fail cases', () => {
    const state = useCryptoAssessment()
    state.loadPreset('compliant')
    expect(state.run()?.level).toBe('合规')
    expect(state.levelTone.value).toBe('success')

    state.loadPreset('weak')
    expect(state.run()?.level).toBe('不合规')
    expect(state.levelTone.value).toBe('danger')
    // Loading a preset clears the previous observation, so the panel cannot
    // claim a host's profile is still loaded after the operator replaced it.
    expect(state.source.value).toBeNull()
  })

  it('assesses a hand-typed configuration without any profile at all', () => {
    const state = useCryptoAssessment()
    state.algorithmText.value = 'SM2, SM3, SM4'
    state.protocolText.value = 'TLSv1.3'
    const result = state.run()
    expect(result?.complianceScore).toBe(100)
    expect(state.config.value.algorithms).toEqual(['SM2', 'SM3', 'SM4'])
  })

  it('runs the same assessment the probe page ran', () => {
    // The panel is the old 密码评估 tab; it must not drift from the rule set.
    const direct = assessCrypto(defaultCryptoConfig)
    const state = useCryptoAssessment()
    state.loadPreset('compliant')
    expect(state.run()?.overallScore).toBe(direct.overallScore)
  })
})
