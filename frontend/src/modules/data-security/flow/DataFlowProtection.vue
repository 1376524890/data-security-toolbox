<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import StateBox from '../../../components/common/StateBox.vue'
import StatCard from '../../../components/common/StatCard.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import HexViewer from '../../../components/evidence/HexViewer.vue'
import { downloadUrl } from '../../../api/client'
import AssessmentPanel from '../assessments/components/AssessmentPanel.vue'
import { useFlowReport } from './composables/useFlowReport'

// 数据流动与防护 shows exactly two reports and no rule configuration: a) the
// risk-flow report (what was captured, and whether it carried sensitive
// content), b) the data-egress report (where the traffic went, by IP). The one
// control is the rule-set switch; the rules themselves live in 采集与规则.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'flow'))
watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}

const {
  loading, error, transfers, coverage, enabled, busy, selected, drawer, binary, binaryError,
  binaryLoading, riskyCount, matchedText, alertable, load, toggleRuleSet, openTransfer,
} = useFlowReport()
</script>

<template>
  <div>
    <div class="hub-title">数据流动与防护</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="风险数据流动报告" name="flow">
        <div class="toolbar">
          <span class="muted">旁路被动采集，不解密 TLS；抓包由任务中心下发（每 30 秒一段）后自动分析</span>
          <div class="toolbar-spacer" />
          <span class="muted">规则集</span>
          <el-switch :model-value="enabled" :loading="busy" @change="(v: boolean | string | number) => toggleRuleSet(Boolean(v))" />
          <span class="muted">（规则配置在「采集与规则」）</span>
          <el-button @click="load">刷新</el-button>
        </div>
        <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
          <div class="stat-grid cols-4">
            <StatCard label="传输对象" :value="transfers.length" sub="已分析的抓包对象" />
            <StatCard label="风险对象" :value="riskyCount" sub="命中规则集且达置信度" tone="danger" />
            <StatCard label="命中对象" :value="transfers.filter((t) => t.matches.length).length" tone="warning" />
            <StatCard label="覆盖抓包" :value="coverage.length" sub="含截断信息见下" />
          </div>
          <div class="soc-card" style="margin-top: 12px">
            <div class="soc-card-title"><span class="dot danger" />传输对象与命中</div>
            <el-table :data="transfers" size="small" @row-click="openTransfer">
              <el-table-column prop="pcap_id" label="PCAP" width="70" />
              <el-table-column prop="filename" label="对象 / 文件" min-width="160" show-overflow-tooltip />
              <el-table-column label="方向" min-width="220">
                <template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }} → {{ row.dst_ip }}:{{ row.dst_port }}</template>
              </el-table-column>
              <el-table-column prop="size" label="字节" width="90" />
              <el-table-column label="完整性" width="110">
                <template #default="{ row }">{{ row.complete ? '完整' : '部分 / 未确认' }}</template>
              </el-table-column>
              <el-table-column label="命中" min-width="240">
                <template #default="{ row }">
                  <el-tag v-for="(hit, index) in row.matches" :key="index" size="small"
                          :type="alertable(hit) ? 'danger' : 'info'" style="margin: 2px">
                    {{ hit.kind }} × {{ hit.count }}{{ alertable(hit) ? '' : '（仅证据）' }}
                  </el-tag>
                  <span v-if="!row.matches.length" class="muted">未命中</span>
                </template>
              </el-table-column>
            </el-table>
            <el-empty v-if="!transfers.length" description="尚无抓包分析结果；在任务中心下发监控任务后自动产生" />
          </div>
          <el-collapse style="margin-top: 12px">
            <el-collapse-item title="检测覆盖范围与截断信息">
              <JsonViewer :value="coverage" />
            </el-collapse-item>
          </el-collapse>
        </StateBox>
      </el-tab-pane>

      <el-tab-pane label="数据出境报告" name="egress">
        <AssessmentPanel v-if="active === 'egress'" kind="egress" />
      </el-tab-pane>
    </el-tabs>

    <el-drawer v-model="drawer" title="传输文件证据" size="70%">
      <template v-if="selected">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="SHA256"><span class="wrap">{{ selected.sha256 }}</span></el-descriptions-item>
          <el-descriptions-item label="哈希范围">{{ selected.complete ? '完整重组文件' : '已捕获片段，不能作为完整文件哈希' }}</el-descriptions-item>
          <el-descriptions-item label="内容类型">{{ selected.content_type || '未知' }}</el-descriptions-item>
        </el-descriptions>
        <div class="section-title">命中原文</div>
        <el-table :data="matchedText(selected)" size="small" empty-text="该对象未命中规则集或规则未回传原文">
          <el-table-column prop="kind" label="类别" width="120" />
          <el-table-column prop="count" label="次数" width="70" />
          <el-table-column prop="ruleId" label="规则" min-width="140" />
          <el-table-column prop="value" label="命中值" min-width="160" />
          <el-table-column prop="context" label="上下文" min-width="240" show-overflow-tooltip />
        </el-table>
        <div class="section-title">二进制证据</div>
        <el-alert v-if="binaryError" :title="binaryError" type="info" :closable="false" />
        <el-alert v-else-if="!selected.binary_available" type="info" :closable="false"
                  title="该对象未保留二进制证据（历史 PCAP 请重新分析）" />
        <template v-else>
          <el-button @click="downloadUrl(`/dlp/transfers/${selected.task_id}/${selected.id}/content?download=true`)">下载</el-button>
          <div v-loading="binaryLoading" style="margin-top: 8px">
            <HexViewer v-if="binary" :data="binary" />
          </div>
        </template>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
.muted { color: var(--soc-text-dim); font-size: 12px; }
.section-title { font-weight: 600; margin: 14px 0 8px; }
.wrap { overflow-wrap: anywhere; }
:deep(.el-table__row) { cursor: pointer; }
</style>
