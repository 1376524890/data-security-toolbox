/**
 * Algorithm-evaluation state: the commercial-cryptography assessment and the
 * code-complexity analysis.
 *
 * The cryptography tab assesses the configuration in the browser, so the only
 * traffic is the probe list and the per-probe profile read; the complexity tab
 * is purely local.  The tab, the two form models and the two results live here,
 * the view keeps the component imports and the static language list.
 */
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { assessCrypto, defaultCryptoConfig, weakCryptoConfig, type CryptoConfig, type CryptoAssessmentResult } from '../cryptoAssessment'
import { listProbes, type Probe } from '../../../api/probes'
import { getCryptoProbeProfile, type CryptoProbeProfile } from '../../../api/crypto'
import { analyzeComplexity, defaultCodeSample, type ComplexityResult } from '../complexityAnalysis'

export function useAlgorithmEvaluation() {
  const activeTab = ref('crypto')

  // ============ 商用密码应用安全性评估 ============
  const cryptoConfig = ref<CryptoConfig>(JSON.parse(JSON.stringify(defaultCryptoConfig)))
  const cryptoResult = ref<CryptoAssessmentResult | null>(null)
  const cryptoRunning = ref(false)
  const probes = ref<Probe[]>([])
  const selectedProbeId = ref<number | null>(null)
  const detecting = ref(false)
  const detectedProfile = ref<CryptoProbeProfile | null>(null)

  const algorithmText = ref(defaultCryptoConfig.algorithms.join(', '))
  const suiteText = ref(defaultCryptoConfig.cipherSuites.join(', '))
  const protocolText = ref(defaultCryptoConfig.protocols.join(', '))
  const keyLengthText = ref(defaultCryptoConfig.keyLengths.join(', '))

  function parseList(text: string): string[] {
    return text.split(/[,\n;]/).map((s) => s.trim()).filter(Boolean)
  }

  function syncConfig(): void {
    cryptoConfig.value.algorithms = parseList(algorithmText.value)
    cryptoConfig.value.cipherSuites = parseList(suiteText.value)
    cryptoConfig.value.protocols = parseList(protocolText.value)
    cryptoConfig.value.keyLengths = parseList(keyLengthText.value).map(Number).filter((n) => !Number.isNaN(n))
  }

  function runCrypto(): void {
    cryptoRunning.value = true
    syncConfig()
    try {
      cryptoResult.value = assessCrypto(cryptoConfig.value)
      ElMessage.success('商用密码应用安全性评估完成')
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      cryptoRunning.value = false
    }
  }

  function loadPreset(name: 'compliant' | 'weak'): void {
    const src = name === 'compliant' ? defaultCryptoConfig : weakCryptoConfig
    cryptoConfig.value = JSON.parse(JSON.stringify(src))
    algorithmText.value = src.algorithms.join(', ')
    suiteText.value = src.cipherSuites.join(', ')
    protocolText.value = src.protocols.join(', ')
    keyLengthText.value = src.keyLengths.join(', ')
    cryptoResult.value = null
  }

  async function loadProbes(): Promise<void> {
    try {
      const res = await listProbes({ page: 1, page_size: 100 })
      probes.value = res.items || []
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  async function autoDetectFromProbe(): Promise<void> {
    if (!selectedProbeId.value) {
      ElMessage.warning('请先选择探针')
      return
    }
    detecting.value = true
    try {
      const profile = await getCryptoProbeProfile(selectedProbeId.value)
      const cfg = profile.config
      cryptoConfig.value = {
        algorithms: cfg.algorithms?.length ? cfg.algorithms : defaultCryptoConfig.algorithms,
        cipherSuites: cfg.cipherSuites?.length ? cfg.cipherSuites : defaultCryptoConfig.cipherSuites,
        protocols: cfg.protocols?.length ? cfg.protocols : defaultCryptoConfig.protocols,
        keyLengths: cfg.keyLengths?.length ? cfg.keyLengths : defaultCryptoConfig.keyLengths,
        keyManagement: { ...defaultCryptoConfig.keyManagement, ...(cfg.keyManagement || {}) },
        sm4Key: defaultCryptoConfig.sm4Key,
        passwordSignals: profile.passwordSignals || [],
      }
      algorithmText.value = cryptoConfig.value.algorithms.join(', ')
      suiteText.value = cryptoConfig.value.cipherSuites.join(', ')
      protocolText.value = cryptoConfig.value.protocols.join(', ')
      keyLengthText.value = cryptoConfig.value.keyLengths.join(', ')
      detectedProfile.value = profile
      runCrypto()
      ElMessage.success(`已从探针「${profile.probe_name}」自动识别并填充，开始评估`)
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      detecting.value = false
    }
  }

  onMounted(loadProbes)

  const cryptoLevelTone = computed(() => {
    const level = cryptoResult.value?.level || ''
    return level === '合规' ? 'success' : level === '基本合规' ? 'info' : level === '部分合规' ? 'warning' : 'danger'
  })

  // ============ 代码算法复杂度分析 ============
  const code = ref(defaultCodeSample)
  const language = ref('javascript')
  const complexityResult = ref<ComplexityResult | null>(null)
  const complexityRunning = ref(false)


  function runComplexity(): void {
    complexityRunning.value = true
    try {
      complexityResult.value = analyzeComplexity(code.value, language.value)
      ElMessage.success('复杂度分析完成')
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      complexityRunning.value = false
    }
  }

  return {
    activeTab, cryptoConfig, cryptoResult, cryptoRunning, probes, selectedProbeId, detecting, detectedProfile,
    algorithmText, suiteText, protocolText, keyLengthText, cryptoLevelTone,
    code, language, complexityResult, complexityRunning, defaultCodeSample,
    runCrypto, loadPreset, loadProbes, autoDetectFromProbe, runComplexity,
  }
}
