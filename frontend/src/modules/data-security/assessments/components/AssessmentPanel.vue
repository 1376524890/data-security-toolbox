<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import StateBox from '../../../../components/common/StateBox.vue'
import StatCard from '../../../../components/common/StatCard.vue'
import { getAssessment, type AssessmentEnvelope, type AssessmentKind } from '../../../../api/assessments'

// One renderer for every assessment endpoint: the exact five-段式 skeleton
// (结论条 → KPI 带分母 → 主视图 → 明细 → 口径与缺口). A failed refresh keeps the
// last good payload rather than blanking the panel.
const props = defineProps<{ kind: AssessmentKind }>()

const loading = ref(true)
const error = ref('')
const data = ref<AssessmentEnvelope | null>(null)

const COLUMNS: Record<string, { prop: string; label: string }[]> = {
  level_distribution: [{ prop: 'level', label: '等级' }, { prop: 'name', label: '含义' },
    { prop: 'count', label: '对象数' }],
  types: [{ prop: 'category', label: '类型' }, { prop: 'level', label: '分级' },
    { prop: 'object_count', label: '对象数' }, { prop: 'active_instance_count', label: '活跃实例' }],
  protocols: [{ prop: 'protocol', label: '协议' }, { prop: 'flows', label: '会话' },
    { prop: 'bytes', label: '字节' }],
  regions: [{ prop: 'region', label: '地区' }, { prop: 'count', label: '对象数' }],
  rules: [{ prop: 'rule_id', label: '规则' }, { prop: 'title', label: '标题' },
    { prop: 'severity', label: '严重度' }],
  findings: [{ prop: 'rule_id', label: '规则' }, { prop: 'severity', label: '严重度' },
    { prop: 'count', label: '命中' }],
  vulnerability_severity: [{ prop: 'severity', label: '严重度' }, { prop: 'count', label: '数量' }],
  finding_severity: [{ prop: 'severity', label: '严重度' }, { prop: 'count', label: '数量' }],
  dimensions: [{ prop: 'label', label: '维度' }, { prop: 'title', label: '标题' },
    { prop: 'conclusion', label: '结论' }],
  transfers: [{ prop: 'pcap_id', label: 'PCAP' }, { prop: 'filename', label: '对象' },
    { prop: 'dst_ip', label: '目的地址' }, { prop: 'bucket', label: '判定' },
    { prop: 'region', label: '地区' }, { prop: 'reason', label: '依据' }],
}

const tables = computed(() => {
  const sections = data.value?.sections || {}
  return Object.entries(COLUMNS)
    .filter(([key]) => Array.isArray(sections[key]) && (sections[key] as unknown[]).length)
    .map(([key, columns]) => ({ key, columns, rows: sections[key] as Record<string, unknown>[] }))
})
const direction = computed(() => (data.value?.sections?.direction as Record<string, number>) || null)
const buckets = computed(() => (data.value?.sections?.buckets as Record<string, number>) || null)
const dedup = computed(() => (data.value?.sections?.dedup as Record<string, unknown>) || null)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    data.value = await getAssessment(props.kind)
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
watch(() => props.kind, load)
</script>

<template>
  <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
    <template v-if="data">
      <div class="soc-card conclusion">
        <el-icon><InfoFilled /></el-icon>
        <div><strong>{{ data.title }}</strong><div class="muted">{{ data.conclusion }}</div></div>
      </div>

      <div class="stat-grid cols-4" style="margin-top: 12px">
        <StatCard v-for="item in data.kpis" :key="item.key" :label="item.label"
                  :value="String(item.value)"
                  :sub="`分母 ${item.denominator}${item.unit ? ' ' + item.unit : ''}`"
                  :tone="item.tone as never" />
      </div>

      <div v-if="direction || buckets" class="grid cols-2" style="margin-top: 12px">
        <div v-if="direction" class="soc-card">
          <div class="soc-card-title"><span class="dot" />会话方向</div>
          <el-descriptions :column="3" border size="small">
            <el-descriptions-item label="内网">{{ direction.internal }}</el-descriptions-item>
            <el-descriptions-item label="可判定外网">{{ direction.external }}</el-descriptions-item>
            <el-descriptions-item label="未识别">{{ direction.unknown }}</el-descriptions-item>
          </el-descriptions>
        </div>
        <div v-if="buckets" class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />出境判定</div>
          <el-descriptions :column="3" border size="small">
            <el-descriptions-item v-for="(count, bucket) in buckets" :key="bucket" :label="String(bucket)">
              {{ count }}
            </el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <div v-for="table in tables" :key="table.key" class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />{{ table.key }}</div>
        <el-table :data="table.rows" size="small" max-height="360">
          <el-table-column v-for="column in table.columns" :key="column.prop"
                           :prop="column.prop" :label="column.label" show-overflow-tooltip />
        </el-table>
      </div>

      <div v-if="dedup" class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />去重口径</div>
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="确认副本">{{ dedup.confirmed_duplicates }}</el-descriptions-item>
          <el-descriptions-item label="疑似副本">{{ dedup.candidate_duplicates }}</el-descriptions-item>
          <el-descriptions-item label="待确认身份">{{ dedup.identity_pending }}</el-descriptions-item>
        </el-descriptions>
        <div class="note">{{ dedup.rule }}</div>
      </div>

      <div class="grid cols-2" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />口径与缺口</div>
          <el-table :data="data.gaps" size="small" empty-text="无">
            <el-table-column prop="label" label="项" width="150" />
            <el-table-column prop="status" label="状态" width="110" />
            <el-table-column prop="detail" label="说明" min-width="220" show-overflow-tooltip />
          </el-table>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />覆盖口径</div>
          <el-tag size="small" :type="data.caliber.tls_decryption ? 'info' : 'warning'">
            {{ data.caliber.tls_decryption ? '解密 TLS' : '不解密 TLS' }}
          </el-tag>
          <el-tag size="small" :type="data.caliber.permission_reported ? 'info' : 'warning'"
                  style="margin-left: 6px">权限未上报</el-tag>
          <el-tag size="small" :type="data.caliber.region_table_present ? 'success' : 'danger'"
                  style="margin-left: 6px">
            地区表{{ data.caliber.region_table_present ? '已加载' : '缺失' }}
          </el-tag>
          <ul class="notes"><li v-for="(note, index) in data.caliber.notes" :key="index">{{ note }}</li></ul>
        </div>
      </div>
    </template>
  </StateBox>
</template>

<style scoped>
.conclusion { display: flex; gap: 10px; align-items: flex-start; }
.muted { color: var(--soc-text-dim); font-size: 12px; margin-top: 4px; line-height: 1.5; }
.note { color: var(--soc-text-dim); font-size: 12px; margin-top: 8px; }
.notes { color: var(--soc-text-dim); font-size: 12px; margin: 10px 0 0; padding-left: 18px; line-height: 1.6; }
</style>
