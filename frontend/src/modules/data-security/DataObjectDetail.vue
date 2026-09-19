<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  getDataObject, getDetectionEvidence, listObjectDetections,
  type AssetInstanceRow, type DetectionRow, type EvidenceRow, type ObjectDetail,
} from '../../api/dataCatalog'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'

const route = useRoute()
const router = useRouter()
const objectId = computed(() => Number(route.params.id))

const loading = ref(true)
const error = ref('')
const detail = ref<ObjectDetail | null>(null)
const detections = ref<DetectionRow[]>([])
const detectionPage = ref(1)
const detectionTotal = ref(0)
const pageSize = 10

const evidenceOpen = ref(false)
const evidenceLoading = ref(false)
const evidenceError = ref('')
const evidence = ref<{ detection: DetectionRow; items: EvidenceRow[]; note: string } | null>(null)

const identityText = computed(() => {
  const kind = detail.value?.identity_kind
  if (kind === 'confirmed') return '内容一致（完整 SHA256 相同）'
  if (kind === 'candidate') {
    return (detail.value?.active_instance_count ?? 0) >= 2
      ? '疑似副本（部分指纹相同且存在多个实例，需人工确认）'
      : '待确认身份（部分指纹相同，但仅观察到 1 个实例，不称副本）'
  }
  return '作用域内标识（无可靠 Hash，仅在同一探针内可比）'
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [object, detectionResult] = await Promise.all([
      getDataObject(objectId.value),
      listObjectDetections(objectId.value, { page: detectionPage.value, page_size: pageSize }),
    ])
    detail.value = object
    detections.value = detectionResult.items
    detectionTotal.value = detectionResult.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function loadDetections(): Promise<void> {
  const result = await listObjectDetections(objectId.value, { page: detectionPage.value, page_size: pageSize })
  detections.value = result.items
  detectionTotal.value = result.total
}

async function openEvidence(row: DetectionRow): Promise<void> {
  evidenceOpen.value = true
  evidenceLoading.value = true
  evidenceError.value = ''
  evidence.value = null
  try {
    evidence.value = await getDetectionEvidence(row.id)
  } catch (err) {
    evidenceError.value = err instanceof Error ? err.message : String(err)
  } finally {
    evidenceLoading.value = false
  }
}

function openInstance(row: AssetInstanceRow): void {
  router.push({ path: `/asset-instances/${row.id}` })
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <el-button link @click="router.back()">← 返回</el-button>
        <div class="toolbar-title">数据对象 #{{ detail?.id }}</div>
        <el-tag size="small" type="info">{{ detail?.object_type }}</el-tag>
        <el-tag size="small" :type="detail?.identity_kind === 'confirmed' ? 'success' : detail?.identity_kind === 'candidate' ? 'warning' : 'info'">
          {{ identityText }}
        </el-tag>
        <div class="toolbar-spacer" />
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="活跃实例" :value="detail?.active_instance_count ?? 0" sub="当前仍在观测中" />
        <StatCard label="历史实例" :value="detail?.instance_count ?? 0" sub="含已标记未观测到的实例" />
        <StatCard label="数据分级" :value="detail?.level || '—'" :sub="detail?.sensitivity || ''"
                  :tone="detail?.level === 'L4' ? 'danger' : detail?.level === 'L3' ? 'warning' : 'default'" />
        <StatCard label="大小(字节)" :value="detail?.size ?? 0" />
      </div>

      <div class="grid cols-2" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />对象身份</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="对象标识"><code class="key">{{ detail?.object_key }}</code></el-descriptions-item>
            <el-descriptions-item label="Hash 类型">{{ detail?.hash_type }}</el-descriptions-item>
            <el-descriptions-item label="内容 Hash">{{ detail?.content_hash || '无可靠 Hash' }}</el-descriptions-item>
            <el-descriptions-item label="身份置信度">
              {{ detail?.identity_confidence }}
              <span class="muted">（1.0 仅表示完整内容 Hash 一致，不代表业务语义相同，也不是检测置信度）</span>
            </el-descriptions-item>
            <el-descriptions-item v-if="detail?.partial_version" label="部分指纹版本">{{ detail?.partial_version }}</el-descriptions-item>
          </el-descriptions>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />时间与聚合</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="首次发现">{{ detail?.first_seen_at?.replace('T', ' ').slice(0, 19) }}</el-descriptions-item>
            <el-descriptions-item label="最近发现">{{ detail?.last_seen_at?.replace('T', ' ').slice(0, 19) }}</el-descriptions-item>
            <el-descriptions-item label="命中类型">{{ (detail?.categories || []).join('、') || '无' }}</el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />实例（探针上的物理副本）</div>
        <el-table :data="detail?.instances || []" size="small" empty-text="该对象暂无实例" @row-click="openInstance">
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="path" label="路径" min-width="260" show-overflow-tooltip />
          <el-table-column prop="probe_name" label="探针" width="140" />
          <el-table-column prop="host" label="主机" width="140" />
          <el-table-column label="状态" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="row.status === 'ACTIVE' ? 'success' : 'info'">
                {{ row.status === 'ACTIVE' ? '观测中' : '未观测到' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="level" label="分级" width="80" />
          <el-table-column label="最近扫描" width="170">
            <template #default="{ row }">{{ row.last_seen_at?.replace('T', ' ').slice(0, 19) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="80" fixed="right">
            <template #default><el-button link type="primary" size="small">详情</el-button></template>
          </el-table-column>
        </el-table>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />该对象上的检测</div>
        <el-table :data="detections" size="small" empty-text="暂无检测">
          <el-table-column prop="category" label="类型" width="140" />
          <el-table-column prop="sensitivity_level" label="分级" width="90" />
          <el-table-column prop="severity" label="旧严重度" width="110" />
          <el-table-column prop="hit_count" label="命中数" width="90" />
          <el-table-column prop="sample_size" label="样本量" width="90" />
          <el-table-column prop="confidence" label="置信度" width="90" />
          <el-table-column prop="ruleset_version" label="规则版本" width="140" show-overflow-tooltip />
          <el-table-column label="最近更新" width="170">
            <template #default="{ row }">{{ row.last_seen_at?.replace('T', ' ').slice(0, 19) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="openEvidence(row)">证据</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-pagination class="pagination" layout="total, prev, pager, next" :total="detectionTotal"
                       :current-page="detectionPage" :page-size="pageSize"
                       @current-change="(value: number) => { detectionPage = value; loadDetections() }" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot warn" />尚未接入（P1）</div>
        <el-alert type="warning" :closable="false" show-icon
                  title="该对象所属的业务系统、数据流向与网络关系未采集，平台不做任何推断或连线绘制。" />
      </div>

      <el-drawer v-model="evidenceOpen" title="检测证据" size="620px">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px"
                  title="证据只包含规则、识别器、字段位置与命中次数；平台从不保存或展示匹配到的原始值。" />
        <div v-if="evidenceLoading">加载中…</div>
        <div v-else-if="evidenceError" class="danger-text">{{ evidenceError }}</div>
        <template v-else-if="evidence">
          <el-descriptions :column="1" border size="small" style="margin-bottom: 12px">
            <el-descriptions-item label="类型">{{ evidence.detection.category }}</el-descriptions-item>
            <el-descriptions-item label="分级">{{ evidence.detection.sensitivity_level }}</el-descriptions-item>
            <el-descriptions-item label="命中数">{{ evidence.detection.hit_count }}</el-descriptions-item>
          </el-descriptions>
          <el-table :data="evidence.items" size="small" empty-text="该检测没有结构化证据（旧版探针报告只上报计数，不含逐条证据）">
            <el-table-column prop="rule_id" label="规则 ID" min-width="150" show-overflow-tooltip />
            <el-table-column prop="rule_source" label="来源" width="110" />
            <el-table-column prop="recognizer" label="识别器" width="120" />
            <el-table-column prop="evidence_type" label="证据类型" width="110" />
            <el-table-column prop="field_name" label="字段" width="120" />
            <el-table-column prop="sheet_name" label="工作表" width="110" />
            <el-table-column prop="column_index" label="列号" width="70" />
            <el-table-column prop="hit_count" label="命中" width="70" />
          </el-table>
          <div class="note">{{ evidence.note }}</div>
        </template>
      </el-drawer>
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.key { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.muted { color: var(--soc-text-dim); }
.note { color: var(--soc-text-dim); font-size: 12px; margin-top: 8px; }
.danger-text { color: #ef4444; }
:deep(.el-table__row) { cursor: pointer; }
</style>
