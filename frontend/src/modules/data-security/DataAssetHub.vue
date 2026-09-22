<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import BarChart from '../../components/charts/BarChart.vue'
import NetworkAssets from './NetworkAssets.vue'
import { getAssessment, type AssessmentEnvelope, type AssessmentKpi } from '../../api/assessments'

// 资产中心 has two inventories: 数据资产 (a: the overview and distribution of the
// data landscape, b: the risky and fragile data with its rating) and 网络资产
// (what the active scan found on the wire). Both are read-only aggregations of
// rows the engines already produced — the same numbers the big screen shows — so
// there is no second source of truth and no duplicated 数据类型 / 检测中心 page.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'data'))
watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}

const loading = ref(true)
const error = ref('')
const classification = ref<AssessmentEnvelope | null>(null)
const exposure = ref<AssessmentEnvelope | null>(null)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [a, b] = await Promise.all([getAssessment('classification'), getAssessment('exposure')])
    classification.value = a
    exposure.value = b
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

function kpiOf(envelope: AssessmentEnvelope | null, key: string): AssessmentKpi | undefined {
  return envelope?.kpis.find((item) => item.key === key)
}

type Row = Record<string, unknown>
const levelDistribution = computed<Row[]>(
  () => (classification.value?.sections?.level_distribution as Row[]) || [])
const levelChart = computed(() => ({
  x: levelDistribution.value.map((row) => `${row.level} ${row.name}`),
  y: levelDistribution.value.map((row) => Number(row.count || 0)),
}))

/** 风险数据: the sensitive types, most sensitive first, each with its rating. */
const riskTypes = computed<Row[]>(() => {
  const rows = (classification.value?.sections?.types as Row[]) || []
  const rank: Record<string, number> = { L4: 0, L3: 1, L2: 2, L1: 3 }
  return [...rows].sort((a, b) =>
    (rank[String(a.level)] ?? 9) - (rank[String(b.level)] ?? 9) ||
    Number(b.object_count || 0) - Number(a.object_count || 0))
})

const vulnSeverity = computed<Row[]>(
  () => (exposure.value?.sections?.vulnerability_severity as Row[]) || [])
const findingSeverity = computed<Row[]>(
  () => (exposure.value?.sections?.finding_severity as Row[]) || [])

const gaps = computed(() => [...(classification.value?.gaps || []), ...(exposure.value?.gaps || [])])

onMounted(load)
</script>

<template>
  <div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="数据资产" name="data">
    <StateBox :loading="loading" :error="error" :empty="!classification" @retry="load">
      <template v-if="classification && exposure">
        <div class="soc-card conclusion">
          <el-icon><InfoFilled /></el-icon>
          <div><strong>数据资产</strong>
            <div class="muted">{{ classification.conclusion }}</div>
            <div class="muted">{{ exposure.conclusion }}</div>
          </div>
        </div>

        <!-- a) 概览 + 数据分布 -->
        <div class="section-title">数据资产概览与分布</div>
        <div class="stat-grid cols-6">
          <StatCard v-for="item in classification.kpis.slice(0, 6)" :key="item.key"
                    :label="item.label" :value="String(item.value)"
                    :sub="`分母 ${item.denominator}${item.unit ? ' ' + item.unit : ''}`"
                    :tone="item.tone as never" />
        </div>
        <div class="grid cols-2" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />分级分布</div>
            <BarChart :x-data="levelChart.x" :data="levelChart.y" :height="240" />
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />去重口径</div>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="确认副本">
                {{ kpiOf(classification, 'confirmed_duplicates')?.value }}
              </el-descriptions-item>
              <el-descriptions-item label="疑似副本">
                {{ kpiOf(classification, 'candidate_duplicates')?.value }}
              </el-descriptions-item>
              <el-descriptions-item label="待确认身份">
                {{ kpiOf(classification, 'identity_pending')?.value }}
              </el-descriptions-item>
              <el-descriptions-item label="观测来源">{{ kpiOf(classification, 'sources')?.value }}</el-descriptions-item>
            </el-descriptions>
            <div class="note">{{ (classification.sections.dedup as Row)?.rule }}</div>
          </div>
        </div>

        <!-- b) 风险数据与脆弱数据 -->
        <div class="section-title" style="margin-top: 14px">风险数据与脆弱数据（含评级）</div>
        <div class="stat-grid cols-4">
          <StatCard v-for="item in exposure.kpis.slice(0, 4)" :key="item.key"
                    :label="item.label" :value="String(item.value)"
                    :sub="`分母 ${item.denominator}${item.unit ? ' ' + item.unit : ''}`"
                    :tone="item.tone as never" />
        </div>
        <div class="grid cols-2" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />风险数据（按分级）</div>
            <el-table :data="riskTypes" size="small" max-height="320" empty-text="尚无敏感类型">
              <el-table-column prop="category" label="类型" min-width="140" />
              <el-table-column label="评级" width="150">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.level === 'L4' ? 'danger' : row.level === 'L3' ? 'warning' : 'info'">
                    {{ row.level }} {{ row.level_name }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="object_count" label="关联对象" width="100" sortable />
              <el-table-column prop="active_instance_count" label="活跃实例" width="110" sortable />
              <el-table-column label="仅字段名" width="100">
                <template #default="{ row }"><span class="muted">{{ row.field_only ? '是' : '否' }}</span></template>
              </el-table-column>
            </el-table>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />脆弱数据分布</div>
            <el-descriptions :column="1" border size="small">
              <el-descriptions-item label="漏洞等级">
                <el-tag v-for="row in vulnSeverity" :key="String(row.severity)" size="small"
                        style="margin-right: 4px">{{ row.severity }} {{ row.count }}</el-tag>
                <span v-if="!vulnSeverity.length" class="muted">无</span>
              </el-descriptions-item>
              <el-descriptions-item label="引擎发现等级">
                <el-tag v-for="row in findingSeverity" :key="String(row.severity)" size="small"
                        type="warning" style="margin-right: 4px">{{ row.severity }} {{ row.count }}</el-tag>
                <span v-if="!findingSeverity.length" class="muted">无</span>
              </el-descriptions-item>
            </el-descriptions>
            <div class="section-title small">口径与缺口</div>
            <el-table :data="gaps" size="small" max-height="200" empty-text="无">
              <el-table-column prop="label" label="项" width="150" />
              <el-table-column prop="status" label="状态" width="110" />
              <el-table-column prop="detail" label="说明" min-width="200" show-overflow-tooltip />
            </el-table>
          </div>
        </div>
      </template>
    </StateBox>
      </el-tab-pane>
      <el-tab-pane label="网络资产" name="network">
        <NetworkAssets v-if="active === 'network'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.conclusion { display: flex; gap: 10px; align-items: flex-start; }
.section-title { font-weight: 600; margin: 12px 0 8px; }
.section-title.small { font-size: 13px; margin-top: 12px; }
.muted { color: var(--soc-text-dim); font-size: 12px; }
.note { color: var(--soc-text-dim); font-size: 12px; margin-top: 8px; }
</style>
