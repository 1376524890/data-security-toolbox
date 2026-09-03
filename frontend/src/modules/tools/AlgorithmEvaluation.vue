<script setup lang="ts">
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import GaugeChart from '../../components/charts/GaugeChart.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { assessCrypto, defaultCryptoConfig, weakCryptoConfig, type CryptoConfig, type CryptoAssessmentResult } from './cryptoAssessment'
import { analyzeComplexity, defaultCodeSample, type ComplexityResult } from './complexityAnalysis'

const activeTab = ref('crypto')

// ============ 商用密码应用安全性评估 ============
const cryptoConfig = ref<CryptoConfig>(JSON.parse(JSON.stringify(defaultCryptoConfig)))
const cryptoResult = ref<CryptoAssessmentResult | null>(null)
const cryptoRunning = ref(false)
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

const cryptoLevelTone = computed(() => {
  const level = cryptoResult.value?.level || ''
  return level === '合规' ? 'success' : level === '基本合规' ? 'info' : level === '部分合规' ? 'warning' : 'danger'
})

// ============ 代码算法复杂度分析 ============
const code = ref(defaultCodeSample)
const language = ref('javascript')
const complexityResult = ref<ComplexityResult | null>(null)
const complexityRunning = ref(false)
const languages = [
  { label: 'JavaScript', value: 'javascript' },
  { label: 'TypeScript', value: 'typescript' },
  { label: 'Python', value: 'python' },
  { label: '伪代码 / 其他', value: 'other' },
]

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
</script>

<template>
  <div>
    <el-tabs v-model="activeTab" class="eval-tabs">
      <!-- 商用密码应用安全性评估 -->
      <el-tab-pane label="商用密码应用安全性评估" name="crypto">
        <div class="grid cols-2">
          <!-- 配置输入 -->
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />密码应用配置</div>
            <div class="toolbar" style="margin-bottom: 10px">
              <el-button size="small" type="primary" @click="loadPreset('compliant')">合规样例</el-button>
              <el-button size="small" @click="loadPreset('weak')">弱配置样例</el-button>
            </div>
            <el-form label-position="top" size="small">
              <el-form-item label="密码算法（逗号分隔）"><el-input v-model="algorithmText" placeholder="SM4, SM3, SM2, AES-256" /></el-form-item>
              <el-form-item label="密码套件（逗号分隔）"><el-input v-model="suiteText" placeholder="TLS_ECDHE_SM2_WITH_SM4_GCM_SM3" /></el-form-item>
              <el-form-item label="协议版本（逗号分隔）"><el-input v-model="protocolText" placeholder="TLSv1.3, TLSv1.2" /></el-form-item>
              <el-form-item label="密钥长度（逗号分隔）"><el-input v-model="keyLengthText" placeholder="256, 2048, 128" /></el-form-item>
              <el-form-item label="密钥轮换周期（天）"><el-input-number v-model="cryptoConfig.keyManagement.rotationDays" :min="0" :max="3650" style="width: 100%" /></el-form-item>
              <el-form-item label="密钥存储"><el-select v-model="cryptoConfig.keyManagement.storage" style="width: 100%"><el-option label="HSM / 密码卡" value="HSM" /><el-option label="文件" value="file" /><el-option label="数据库" value="db" /></el-select></el-form-item>
              <el-form-item label="使用硬件密码模块"><el-switch v-model="cryptoConfig.keyManagement.useHardware" /></el-form-item>
            </el-form>
            <el-button type="primary" :loading="cryptoRunning" style="width: 100%" @click="runCrypto">开始评估</el-button>
          </div>

          <!-- 评估结果 -->
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />评估结果</div>
            <div v-if="!cryptoResult" class="eval-placeholder">点击"开始评估"，依据 GB/T 39786 / GM/T 系列标准进行合规性、正确性、有效性评估。</div>
            <template v-else>
              <div class="eval-score">
                <div class="eval-gauge"><GaugeChart :value="cryptoResult.overallScore" :color="cryptoResult.overallScore >= 90 ? '#22c55e' : cryptoResult.overallScore >= 75 ? '#38bdf8' : cryptoResult.overallScore >= 60 ? '#f59e0b' : '#ef4444'" :height="180" /></div>
                <div class="eval-level">
                  <StatusBadge :value="cryptoLevelTone" />
                  <div class="eval-level-text">{{ cryptoResult.level }}</div>
                  <div class="text-dim">合规 {{ cryptoResult.complianceScore }} · 正确 {{ cryptoResult.correctnessScore }} · 有效 {{ cryptoResult.effectivenessScore }}</div>
                </div>
              </div>
              <div class="eval-metrics">
                <div class="metric"><span>合规性</span><el-progress :percentage="cryptoResult.complianceScore" :stroke-width="6" :color="cryptoResult.complianceScore >= 90 ? '#22c55e' : '#f59e0b'" /></div>
                <div class="metric"><span>正确性</span><el-progress :percentage="cryptoResult.correctnessScore" :stroke-width="6" :color="cryptoResult.correctnessScore >= 90 ? '#22c55e' : '#f59e0b'" /></div>
                <div class="metric"><span>有效性</span><el-progress :percentage="cryptoResult.effectivenessScore" :stroke-width="6" :color="cryptoResult.effectivenessScore >= 90 ? '#22c55e' : '#f59e0b'" /></div>
              </div>
              <div class="eval-summary">
                <span class="text-muted">符合项 {{ cryptoResult.summary.compliant }}</span>
                <span class="text-muted">违规项 {{ cryptoResult.summary.violations }}</span>
                <span class="text-muted">弱项 {{ cryptoResult.summary.weakItems }}</span>
              </div>
              <div class="eval-sm">
                <span class="text-muted">SM4 回环校验：<StatusBadge :value="cryptoResult.sm4RoundTrip ? 'success' : 'error'" /></span>
                <span class="text-muted mono">SM3: {{ cryptoResult.sm3Digest.slice(0, 24) }}…</span>
              </div>
            </template>
          </div>
        </div>

        <!-- 发现明细 -->
        <div v-if="cryptoResult" class="soc-card" style="margin-top: 12px">
          <div class="soc-card-title"><span class="dot danger" />评估发现（{{ cryptoResult.findings.length }}）</div>
          <el-table :data="cryptoResult.findings" size="small">
            <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.level" /></template></el-table-column>
            <el-table-column prop="dimension" label="维度" width="80" />
            <el-table-column prop="title" label="问题" min-width="200" show-overflow-tooltip />
            <el-table-column prop="detail" label="详情" min-width="260" show-overflow-tooltip />
            <el-table-column prop="standard" label="标准依据" width="180" show-overflow-tooltip />
            <el-table-column prop="recommendation" label="整改建议" min-width="260" show-overflow-tooltip />
          </el-table>
          <div class="eval-standards">
            <span class="text-muted">评估依据：</span>
            <el-tag v-for="s in cryptoResult.standards" :key="s" size="small" effect="plain">{{ s }}</el-tag>
          </div>
        </div>
      </el-tab-pane>

      <!-- 代码算法复杂度分析 -->
      <el-tab-pane label="代码算法复杂度分析" name="complexity">
        <div class="grid cols-2">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />源代码输入</div>
            <div class="toolbar" style="margin-bottom: 8px">
              <el-select v-model="language" style="width: 150px"><el-option v-for="l in languages" :key="l.value" :label="l.label" :value="l.value" /></el-select>
              <el-button size="small" @click="code = defaultCodeSample">示例代码</el-button>
            </div>
            <el-input v-model="code" type="textarea" :rows="18" placeholder="粘贴源代码进行复杂度分析" class="code-input" />
            <el-button type="primary" :loading="complexityRunning" style="width: 100%; margin-top: 10px" @click="runComplexity">分析复杂度</el-button>
          </div>

          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />分析结果</div>
            <div v-if="!complexityResult" class="eval-placeholder">粘贴代码后点击"分析复杂度"，使用 acorn AST 与启发式方法估算时间/空间复杂度。</div>
            <template v-else>
              <div class="complex-head">
                <div class="big-o">
                  <div class="bo-label">时间复杂度</div>
                  <div class="bo-value mono">{{ complexityResult.bigO.time }}</div>
                </div>
                <div class="big-o">
                  <div class="bo-label">空间复杂度</div>
                  <div class="bo-value mono">{{ complexityResult.bigO.space }}</div>
                </div>
                <div class="big-o">
                  <div class="bo-label">代码行数</div>
                  <div class="bo-value">{{ complexityResult.lines }}</div>
                </div>
                <div class="big-o">
                  <div class="bo-label">循环 / 递归</div>
                  <div class="bo-value">{{ complexityResult.loops }} / {{ complexityResult.recursion ? '是' : '否' }}</div>
                </div>
              </div>
              <div v-if="complexityResult.functions.length" class="eval-fn">
                <div class="sec-title">函数级复杂度</div>
                <el-table :data="complexityResult.functions" size="small">
                  <el-table-column prop="name" label="函数" min-width="140" />
                  <el-table-column prop="time" label="时间复杂度" width="140" />
                  <el-table-column prop="space" label="空间复杂度" width="140" />
                  <el-table-column prop="lines" label="行数" width="70" />
                </el-table>
              </div>
              <div class="eval-notes">
                <div class="sec-title">分析说明</div>
                <div v-for="(note, i) in complexityResult.notes" :key="i" class="note">· {{ note }}</div>
              </div>
            </template>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.eval-tabs :deep(.el-tabs__content) { padding-top: 8px; }
.eval-placeholder { color: var(--soc-text-dim); font-size: 13px; padding: 30px 0; text-align: center; }
.eval-score { display: flex; align-items: center; gap: 20px; }
.eval-gauge { width: 180px; }
.eval-level { flex: 1; }
.eval-level-text { font-size: 22px; font-weight: 700; margin-top: 6px; }
.eval-metrics { display: flex; flex-direction: column; gap: 8px; margin-top: 14px; }
.metric { display: grid; grid-template-columns: 60px 1fr; align-items: center; gap: 10px; color: var(--soc-text-muted); }
.eval-summary { display: flex; gap: 16px; margin-top: 12px; }
.eval-sm { display: flex; gap: 16px; align-items: center; margin-top: 8px; }
.eval-standards { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 12px; }
.complex-head { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.big-o { background: var(--soc-panel-2); border: 1px solid var(--soc-border); border-radius: 6px; padding: 12px; text-align: center; }
.bo-label { color: var(--soc-text-dim); font-size: 11px; }
.bo-value { font-size: 20px; font-weight: 700; color: var(--soc-text-strong); margin-top: 6px; }
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; margin-top: 14px; }
.note { color: var(--soc-text-muted); font-size: 12px; padding: 2px 0; }
.code-input :deep(textarea) { font-family: var(--soc-font-mono); font-size: 12px; background: #0e1626; }
</style>
