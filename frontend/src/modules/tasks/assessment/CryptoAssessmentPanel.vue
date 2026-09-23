<script setup lang="ts">
/**
 * 商用密码应用安全性评估 panel: fill the observed facts (or a preset), assess,
 * read the result.
 *
 * It is used from the scan flow — a network scan already recorded each host's
 * services and TLS handshakes, so the panel offers those hosts and assesses the
 * selected one against GB/T 39786 / GM/T without a second collection — and it
 * still works as a plain form when no profile is available.
 *
 * All state lives in ``composables/useCryptoAssessment``; this view keeps the
 * layout, the Element Plus bindings and the static option lists.
 */
import { computed } from 'vue'
import GaugeChart from '../../../components/charts/GaugeChart.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import StatusBadge from '../../../components/security/StatusBadge.vue'
import {
  useCryptoAssessment, type CryptoProfileLike,
} from './composables/useCryptoAssessment'

const props = defineProps<{
  /** Host address → the profile that host's observation produced. */
  profiles?: Record<string, CryptoProfileLike>
  /** Heading for the section; the scan dialog passes the task it belongs to. */
  title?: string
}>()

const {
  config, result, running, source,
  algorithmText, suiteText, protocolText, keyLengthText,
  levelTone, hostKeys, hostKey,
  run, loadPreset, assessSelected,
} = useCryptoAssessment({ profiles: computed(() => props.profiles) })

// The colour scale the gauge and the three bars share: a score below 90 is not
// a pass, so it must not be drawn in the same green as one.
function scoreColor(score: number): string {
  return score >= 90 ? '#22c55e' : score >= 75 ? '#38bdf8' : score >= 60 ? '#f59e0b' : '#ef4444'
}

const coverageLabels: Record<string, string> = {
  detected: '已探测', inferred: '推断', default: '默认值',
}

const coverageText = computed(() => {
  const rows = Object.entries(source.value?.coverage || {})
  return rows.map(([key, value]) => `${key} ${coverageLabels[value] || value}`).join(' · ')
})
</script>

<template>
  <div class="crypto-panel">
    <div v-if="title" class="crypto-title">{{ title }}</div>
    <div v-if="hostKeys.length" class="crypto-source">
      <span class="crypto-source-label">评估目标</span>
      <el-select v-model="hostKey" filterable placeholder="选择主机" style="width: 220px">
        <el-option v-for="host in hostKeys" :key="host" :label="host" :value="host" />
      </el-select>
      <el-button type="primary" :loading="running" @click="assessSelected">评估该主机</el-button>
      <span class="muted">
        直接使用扫描已采集的服务 banner 与 TLS 握手填充算法/套件/协议/密钥长度，无需二次采集
      </span>
    </div>

    <div v-if="source" class="crypto-detected">
      <span class="muted">已填入 {{ source.label }}：</span>
      <el-tag v-for="item in source.passwordTypes" :key="item" size="small" effect="plain">{{ item }}</el-tag>
      <el-tag size="small" effect="plain">TLS 握手 {{ source.tlsHandshakeCount }}</el-tag>
      <el-tag size="small" effect="plain">服务 {{ source.serviceCount }}</el-tag>
      <div v-if="coverageText" class="muted crypto-coverage">数据来源：{{ coverageText }}</div>
      <div v-if="source.passwordSignals.length" class="muted crypto-coverage">
        检测到 {{ source.passwordSignals.length }} 条密码/认证风险，已并入评估发现。
      </div>
    </div>

    <div class="grid cols-2">
      <div class="soc-card">
        <div class="soc-card-title"><span class="dot" />密码应用配置</div>
        <div class="toolbar" style="margin-bottom: 10px">
          <el-button size="small" type="primary" @click="loadPreset('compliant')">合规样例</el-button>
          <el-button size="small" @click="loadPreset('weak')">弱配置样例</el-button>
        </div>
        <el-form label-position="top" size="small">
          <el-form-item label="密码算法（逗号分隔）">
            <el-input v-model="algorithmText" placeholder="SM4, SM3, SM2, AES-256" />
          </el-form-item>
          <el-form-item label="密码套件（逗号分隔）">
            <el-input v-model="suiteText" placeholder="TLS_ECDHE_SM2_WITH_SM4_GCM_SM3" />
          </el-form-item>
          <el-form-item label="协议版本（逗号分隔）">
            <el-input v-model="protocolText" placeholder="TLSv1.3, TLSv1.2" />
          </el-form-item>
          <el-form-item label="密钥长度（逗号分隔）">
            <el-input v-model="keyLengthText" placeholder="256, 2048, 128" />
          </el-form-item>
          <el-form-item label="密钥轮换周期（天）">
            <el-input-number v-model="config.keyManagement.rotationDays" :min="0" :max="3650" style="width: 100%" />
          </el-form-item>
          <el-form-item label="密钥存储">
            <el-select v-model="config.keyManagement.storage" style="width: 100%">
              <el-option label="HSM / 密码卡" value="HSM" />
              <el-option label="文件" value="file" />
              <el-option label="数据库" value="db" />
            </el-select>
          </el-form-item>
          <el-form-item label="使用硬件密码模块">
            <el-switch v-model="config.keyManagement.useHardware" />
          </el-form-item>
        </el-form>
        <el-button type="primary" :loading="running" style="width: 100%" @click="run">开始评估</el-button>
      </div>

      <div class="soc-card">
        <div class="soc-card-title"><span class="dot warn" />评估结果</div>
        <div v-if="!result" class="crypto-placeholder">
          点击"开始评估"，依据 GB/T 39786 / GM/T 系列标准进行合规性、正确性、有效性评估。
        </div>
        <template v-else>
          <div class="crypto-score">
            <div class="crypto-gauge">
              <GaugeChart :value="result.overallScore" :color="scoreColor(result.overallScore)" :height="180" />
            </div>
            <div class="crypto-level">
              <StatusBadge :value="levelTone" />
              <div class="crypto-level-text">{{ result.level }}</div>
              <div class="muted">
                合规 {{ result.complianceScore }} · 正确 {{ result.correctnessScore }} · 有效 {{ result.effectivenessScore }}
              </div>
            </div>
          </div>
          <div class="crypto-metrics">
            <div class="crypto-metric">
              <span>合规性</span>
              <el-progress :percentage="result.complianceScore" :stroke-width="6" :color="scoreColor(result.complianceScore)" />
            </div>
            <div class="crypto-metric">
              <span>正确性</span>
              <el-progress :percentage="result.correctnessScore" :stroke-width="6" :color="scoreColor(result.correctnessScore)" />
            </div>
            <div class="crypto-metric">
              <span>有效性</span>
              <el-progress :percentage="result.effectivenessScore" :stroke-width="6" :color="scoreColor(result.effectivenessScore)" />
            </div>
          </div>
          <div class="crypto-summary">
            <span class="muted">符合项 {{ result.summary.compliant }}</span>
            <span class="muted">违规项 {{ result.summary.violations }}</span>
            <span class="muted">弱项 {{ result.summary.weakItems }}</span>
          </div>
          <div class="crypto-summary">
            <span class="muted">SM4 回环校验：<StatusBadge :value="result.sm4RoundTrip ? 'success' : 'error'" /></span>
            <span class="muted mono">SM3: {{ result.sm3Digest.slice(0, 24) }}…</span>
          </div>
        </template>
      </div>
    </div>

    <div v-if="result" class="soc-card" style="margin-top: 12px">
      <div class="soc-card-title"><span class="dot danger" />评估发现（{{ result.findings.length }}）</div>
      <el-table :data="result.findings" size="small">
        <el-table-column label="等级" width="90">
          <template #default="{ row }"><SeverityTag :value="row.level" /></template>
        </el-table-column>
        <el-table-column prop="dimension" label="维度" width="90" />
        <el-table-column prop="title" label="问题" min-width="200" show-overflow-tooltip />
        <el-table-column prop="detail" label="详情" min-width="260" show-overflow-tooltip />
        <el-table-column prop="standard" label="标准依据" width="180" show-overflow-tooltip />
        <el-table-column prop="recommendation" label="整改建议" min-width="260" show-overflow-tooltip />
      </el-table>
      <div class="crypto-standards">
        <span class="muted">评估依据：</span>
        <el-tag v-for="item in result.standards" :key="item" size="small" effect="plain">{{ item }}</el-tag>
      </div>
    </div>
  </div>
</template>

<style scoped>
.crypto-title { font-size: 13px; font-weight: 600; color: var(--soc-text-strong); margin-bottom: 10px; }
.crypto-source { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.crypto-source-label { font-size: 12px; font-weight: 600; color: var(--soc-text-strong); }
.crypto-detected { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-bottom: 10px; }
.crypto-coverage { flex-basis: 100%; font-size: 12px; }
.crypto-placeholder { color: var(--soc-text-dim); font-size: 13px; padding: 30px 0; text-align: center; }
.crypto-score { display: flex; align-items: center; gap: 20px; }
.crypto-gauge { width: 180px; }
.crypto-level { flex: 1; }
.crypto-level-text { font-size: 22px; font-weight: 700; margin-top: 6px; }
.crypto-metrics { display: flex; flex-direction: column; gap: 8px; margin-top: 14px; }
.crypto-metric { display: grid; grid-template-columns: 60px 1fr; align-items: center; gap: 10px; color: var(--soc-text-muted); }
.crypto-summary { display: flex; gap: 16px; align-items: center; margin-top: 10px; flex-wrap: wrap; }
.crypto-standards { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 12px; }
.muted { color: var(--soc-text-dim); font-size: 12px; }
</style>
