<script setup lang="ts">
import StateBox from '../../../components/common/StateBox.vue'
import StatCard from '../../../components/common/StatCard.vue'
import RiskBadge from '../../../components/security/RiskBadge.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import { formatRiskScore } from '../../../utils/format'
import { useSecurityAudit } from './composables/useSecurityAudit'

// The audit summary and the log-analysis run live in the composable; this view
// keeps the static risk labels and binds the state into the template below.
const {
  loading, error, summary, logContent, logRunning, logResult, logError,
  load, runLogAnalysis, matchGroups,
} = useSecurityAudit()

const riskLabels: Record<string, string> = { Critical: '严重', High: '高危', Medium: '中危', Low: '低危' }
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="!summary" @retry="load">
      <template v-if="summary">
        <div class="stat-grid cols-4">
          <StatCard label="资产总数" :value="summary.assets" tone="info" />
          <StatCard label="文件总数" :value="summary.files" tone="primary" />
          <StatCard label="PCAP 捕获" :value="summary.pcaps" tone="success" />
          <StatCard label="异常事件" :value="summary.anomalies" tone="warning" />
        </div>

        <div class="grid cols-3" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />资产风险分布</div>
            <div class="risk-row" v-for="(count, level) in summary.asset_risk" :key="level">
              <span>{{ riskLabels[level] || level }}</span><RiskBadge :level="level" />
              <span class="mono">{{ count }}</span>
            </div>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />文件风险分布</div>
            <div class="risk-row" v-for="(count, level) in summary.file_risk" :key="level">
              <span>{{ riskLabels[level] || level }}</span><RiskBadge :level="level" />
              <span class="mono">{{ count }}</span>
            </div>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />异常等级分布</div>
            <div class="risk-row" v-for="(count, level) in summary.anomaly_severity" :key="level">
              <span>{{ riskLabels[level] || level }}</span><RiskBadge :level="level" />
              <span class="mono">{{ count }}</span>
            </div>
          </div>
        </div>

        <div class="soc-card" style="margin-top: 12px">
          <div class="soc-card-title"><span class="dot" />泄漏风险审计</div>
          <div class="leak-grid">
            <div class="leak-item"><span class="li-label">风险等级</span><RiskBadge :level="summary.leak_risk.risk_level" /></div>
            <div class="leak-item"><span class="li-label">高危协议</span><span class="mono">{{ summary.leak_risk.high_risk_protocols?.join(', ') || '无' }}</span></div>
            <div class="leak-item"><span class="li-label">协议分布</span><span class="mono">{{ Object.entries(summary.leak_risk.protocols || {}).map(([k, v]) => `${k}:${v}`).join('  ') || '无' }}</span></div>
          </div>
        </div>
      </template>
    </StateBox>

    <div class="soc-card" style="margin-top: 12px">
      <div class="soc-card-title"><span class="dot" />日志安全审计</div>
      <el-input
        v-model="logContent"
        type="textarea"
        :rows="8"
        placeholder="粘贴待审计的日志（每行一条），如：login failed for user admin ..."
        class="log-input"
      />
      <div class="log-actions">
        <el-button type="primary" :loading="logRunning" @click="runLogAnalysis">开始分析</el-button>
      </div>

      <el-alert v-if="logError" :title="logError" type="error" show-icon style="margin-top: 12px" />
      <StateBox v-else-if="logResult" :loading="false" :error="''" :empty="false" style="margin-top: 12px">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="行数"><span class="mono">{{ logResult.log_summary.line_count }}</span></el-descriptions-item>
          <el-descriptions-item label="风险评分"><RiskBadge :score="logResult.risk.score" /></el-descriptions-item>
          <el-descriptions-item label="风险等级"><SeverityTag :value="logResult.risk.level" /></el-descriptions-item>
        </el-descriptions>

        <div class="match-grid" v-if="matchGroups(logResult).length">
          <div class="match-item" v-for="group in matchGroups(logResult)" :key="group.key">
            <div class="match-title">{{ group.label }} <span class="match-count mono">{{ group.lines.length }}</span></div>
            <div class="match-line mono" v-for="line in group.lines" :key="line">{{ line }}</div>
          </div>
        </div>

        <div v-if="logResult.findings.length" style="margin-top: 12px">
          <div class="sec-title">检测发现</div>
          <el-table :data="logResult.findings" size="small">
            <el-table-column prop="engine" label="引擎" width="130" />
            <el-table-column prop="rule_id" label="规则" min-width="160" show-overflow-tooltip />
            <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
            <el-table-column label="风险" width="90"><template #default="{ row }"><span class="mono">{{ formatRiskScore(row.risk_score) }}</span></template></el-table-column>
            <el-table-column prop="recommendation" label="建议" min-width="220" show-overflow-tooltip />
          </el-table>
        </div>
      </StateBox>
    </div>
  </div>
</template>

<style scoped>
.risk-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-bottom: 1px dashed var(--soc-border); color: var(--soc-text-muted); }
.leak-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.leak-item { border: 1px solid var(--soc-border); border-radius: 6px; padding: 10px; }
.li-label { display: block; color: var(--soc-text-dim); font-size: 11px; margin-bottom: 4px; }
.log-input :deep(textarea) { font-family: var(--soc-font-mono, monospace); }
.log-actions { margin-top: 10px; }
.match-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 12px; }
.match-item { border: 1px solid var(--soc-border); border-radius: 6px; padding: 10px; }
.match-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 6px; }
.match-count { margin-left: 6px; color: var(--soc-text-dim); }
.match-line { font-size: 11px; color: var(--soc-text-muted); padding: 2px 0; word-break: break-all; }
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
