/**
 * 商用密码应用安全性评估 (密码评估) state.
 *
 * The assessment itself runs in the browser (``assessCrypto`` — SM4/SM3 round
 * trip, GB/T 39786 and GM/T rule sets), so the only traffic is reading the
 * observed facts from the server: a probe's crypto profile, or the per-host
 * profile a network scan already produced.
 *
 * Both of those come from the same server-side aggregation
 * (``services/crypto_profile.profile_from_observations``), so one adapter fills
 * the form either way — a host must not score differently depending on which
 * path read its services.
 */
import { computed, ref, unref, watch, type MaybeRef } from 'vue'
import { ElMessage } from 'element-plus'
import {
  assessCrypto, defaultCryptoConfig, weakCryptoConfig,
  type CryptoAssessmentResult, type CryptoConfig, type PasswordSignal,
} from '../cryptoAssessment'

/**
 * The observed facts: the ``config`` block (algorithms, suites, protocols, key
 * lengths, key management) plus the password/authentication signals the scan or
 * probe saw. ``GET /crypto/probe-profile`` and each entry of a scan's
 * ``result.crypto_profiles`` both fit this shape.
 */
export interface CryptoProfileLike {
  config: {
    algorithms?: string[]
    cipherSuites?: string[]
    protocols?: string[]
    keyLengths?: number[]
    keyManagement?: CryptoConfig['keyManagement']
  }
  passwordSignals?: PasswordSignal[]
  passwordTypes?: string[]
  tlsHandshakeCount?: number
  serviceCount?: number
  coverage?: Record<string, string>
  sources?: string[]
}

/** Where the current form came from, so the panel can say it instead of
 *  leaving an auto-filled config looking hand-typed. */
export interface CryptoProfileSource {
  label: string
  passwordTypes: string[]
  passwordSignals: PasswordSignal[]
  tlsHandshakeCount: number
  serviceCount: number
  coverage: Record<string, string>
  sources: string[]
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

/**
 * The config an observed profile implies: the observed lists win when they have
 * entries and the shipped default fills the gaps, so a host that only exposed a
 * protocol still gets a complete assessment instead of an accidentally perfect
 * (empty) one.
 *
 * Exported because the asset-side results page scores every host the same way:
 * a second copy of this rule would let one host score differently depending on
 * which page assessed it.
 */
export function configFromProfile(
  profile: CryptoProfileLike,
  defaults: CryptoConfig = defaultCryptoConfig,
): CryptoConfig {
  const observed = profile.config || {}
  return {
    algorithms: observed.algorithms?.length ? [...observed.algorithms] : [...defaults.algorithms],
    cipherSuites: observed.cipherSuites?.length ? [...observed.cipherSuites] : [...defaults.cipherSuites],
    protocols: observed.protocols?.length ? [...observed.protocols] : [...defaults.protocols],
    keyLengths: observed.keyLengths?.length ? [...observed.keyLengths] : [...defaults.keyLengths],
    keyManagement: { ...defaults.keyManagement, ...(observed.keyManagement || {}) },
    sm4Key: defaults.sm4Key,
    passwordSignals: [...(profile.passwordSignals || [])],
  }
}

export interface UseCryptoAssessmentOptions {
  /** Per-host profiles to offer for one-click assessment, keyed by host (the
   *  scan's ``result.crypto_profiles`` is exactly this). Omitted for the plain
   *  manual form. */
  profiles?: MaybeRef<Record<string, CryptoProfileLike> | undefined>
}

export function useCryptoAssessment(options: UseCryptoAssessmentOptions = {}) {
  const config = ref<CryptoConfig>(clone(defaultCryptoConfig))
  const result = ref<CryptoAssessmentResult | null>(null)
  const running = ref(false)
  const source = ref<CryptoProfileSource | null>(null)

  // The four list fields are edited as text (an operator pastes a comma list),
  // so they live beside the config and are parsed on every read/评估.
  const algorithmText = ref(defaultCryptoConfig.algorithms.join(', '))
  const suiteText = ref(defaultCryptoConfig.cipherSuites.join(', '))
  const protocolText = ref(defaultCryptoConfig.protocols.join(', '))
  const keyLengthText = ref(defaultCryptoConfig.keyLengths.join(', '))

  function parseList(text: string): string[] {
    return text.split(/[,\n;]/).map((item) => item.trim()).filter(Boolean)
  }

  function syncConfig(): void {
    config.value.algorithms = parseList(algorithmText.value)
    config.value.cipherSuites = parseList(suiteText.value)
    config.value.protocols = parseList(protocolText.value)
    config.value.keyLengths = parseList(keyLengthText.value)
      .map(Number)
      .filter((value) => !Number.isNaN(value))
  }

  function writeTexts(crypto: CryptoConfig): void {
    algorithmText.value = crypto.algorithms.join(', ')
    suiteText.value = crypto.cipherSuites.join(', ')
    protocolText.value = crypto.protocols.join(', ')
    keyLengthText.value = crypto.keyLengths.join(', ')
  }

  /** Assess the form as it stands. A synchronous function, so it reports a
   *  failure through the message channel rather than a rejected promise. */
  function run(): CryptoAssessmentResult | null {
    running.value = true
    try {
      syncConfig()
      result.value = assessCrypto(config.value)
      return result.value
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
      return null
    } finally {
      running.value = false
    }
  }

  function loadPreset(name: 'compliant' | 'weak'): void {
    const preset = name === 'compliant' ? defaultCryptoConfig : weakCryptoConfig
    config.value = clone(preset)
    writeTexts(config.value)
    source.value = null
    result.value = null
  }

  /** Fill the form from an observed profile; see :func:`configFromProfile`. */
  function applyProfile(profile: CryptoProfileLike, label = ''): void {
    config.value = configFromProfile(profile, defaultCryptoConfig)
    writeTexts(config.value)
    source.value = {
      label,
      passwordTypes: profile.passwordTypes || [],
      passwordSignals: profile.passwordSignals || [],
      tlsHandshakeCount: profile.tlsHandshakeCount || 0,
      serviceCount: profile.serviceCount || 0,
      coverage: profile.coverage || {},
      sources: profile.sources || [],
    }
    result.value = null
  }

  // The offered hosts come from the caller's profiles; the selection resets
  // when the set changes (opening another task must not keep the previous
  // host's name pointing at the new task's profiles).
  const hostKeys = computed(() => Object.keys(unref(options.profiles) || {}))
  const hostKey = ref('')
  watch(hostKeys, (keys) => {
    if (!keys.includes(hostKey.value)) hostKey.value = keys[0] || ''
  }, { immediate: true })

  /** Read the selected host's observed profile and assess it in one step: the
   *  scan already collected these facts, so the operator does not retype them. */
  function assessSelected(): CryptoAssessmentResult | null {
    const profiles = unref(options.profiles) || {}
    const key = hostKey.value
    const profile = profiles[key]
    if (!profile) {
      ElMessage.warning('请先选择要评估的主机')
      return null
    }
    applyProfile(profile, key)
    return run()
  }

  const levelTone = computed(() => {
    const level = result.value?.level || ''
    return level === '合规' ? 'success'
      : level === '基本合规' ? 'info'
        : level === '部分合规' ? 'warning' : 'danger'
  })

  return {
    config, result, running, source,
    algorithmText, suiteText, protocolText, keyLengthText,
    levelTone, hostKeys, hostKey,
    parseList, syncConfig, run, loadPreset, applyProfile, assessSelected,
  }
}
