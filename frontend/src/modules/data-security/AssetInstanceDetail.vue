<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  getAssetInstance, getDetectionEvidence,
  type DetectionRow, type EvidenceRow, type InstanceDetail,
} from '../../api/dataCatalog'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'

const route = useRoute()
const router = useRouter()
const instanceId = computed(() => Number(route.params.id))

const loading = ref(true)
const error = ref('')
const detail = ref<InstanceDetail | null>(null)
const includeHistory = ref(false)

const evidenceOpen = ref(false)
const evidenceLoading = ref(false)
const evidenceError = ref('')
const evidence = ref<{ detection: DetectionRow; items: EvidenceRow[]; note: string } | null>(null)

function formatTime(value: string | null | undefined): string {
  return value ? value.replace('T', ' ').slice(0, 19) : '—'
}

function formatMtime(ns: number | null): string {
  if (!ns) return '—'
  // The probe reports mtime in nanoseconds since the epoch.
  const date = new Date(Math.floor(ns / 1e6))
  return Number.isNaN(date.getTime()) ? '—' : date.toISOString().replace('T', ' ').slice(0, 19)
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    detail.value = await getAssetInstance(instanceId.value, includeHistory.value)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
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

async function toggleHistory(): Promise<void> {
  includeHistory.value = !includeHistory.value
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <el-button link @click="router.back()">← 返回</el-button>
        <div class="toolbar-title">实例 #{{ detail?.id }}</div>
        <el-tag size="small" :type="detail?.status === 'ACTIVE' ? 'success' : 'info'">
          {{ detail?.status === 'ACTIVE' ? '观测中' : '本次未观测到（不代表已删除）' }}
        </el-tag>
        <el-tag v-if="detail?.coverage !== 'complete'" size="small" type="warning">
          扫描覆盖：{{ detail?.coverage }} / {{ detail?.termination_reason }}
        </el-tag>
        <div class="toolbar-spacer" />
        <el-button @click="toggleHistory">{{ includeHistory ? '只看当前' : '包含历史' }}</el-button>
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="文件大小(字节)" :value="detail?.size ?? 0" />
        <StatCard label="数据分级" :value="detail?.level || '—'" :sub="detail?.sensitivity || ''"
                  :tone="detail?.level === 'L4' ? 'danger' : detail?.level === 'L3' ? 'warning' : 'default'" />
        <StatCard label="检测类型数" :value="detail?.detections?.length ?? 0" />
        <StatCard label="最近扫描" :value="formatTime(detail?.last_scan_at).slice(0, 10)"
                  :sub="formatTime(detail?.last_scan_at).slice(11)" />
      </div>

      <div class="grid cols-2" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />位置与主机</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="路径"><code class="key">{{ detail?.path }}</code></el-descriptions-item>
            <el-descriptions-item label="文件名">{{ detail?.name }}</el-descriptions-item>
            <el-descriptions-item label="实例类型">{{ detail?.instance_type }}</el-descriptions-item>
            <el-descriptions-item label="探针">
              {{ detail?.probe_name }}（{{ detail?.host }}）
              <el-tag size="small" type="info" style="margin-left: 6px">probe_id={{ detail?.probe_id }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="关联对象">
              <el-button link type="primary" @click="router.push(`/data-objects/${detail?.object_id}`)">
                #{{ detail?.object_id }}
              </el-button>
              <code class="key" style="margin-left: 8px">{{ detail?.object_key }}</code>
            </el-descriptions-item>
          </el-descriptions>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />文件属性与版本</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="inode / device">
              {{ detail?.inode ?? '—' }} / {{ detail?.device ?? '—' }}
            </el-descriptions-item>
            <el-descriptions-item label="mtime">{{ formatMtime(detail?.mtime_ns ?? null) }}</el-descriptions-item>
            <el-descriptions-item label="属主 / 属组">{{ detail?.owner || '—' }} / {{ detail?.group || '—' }}</el-descriptions-item>
            <el-descriptions-item label="权限">{{ detail?.permission || '—' }}</el-descriptions-item>
            <el-descriptions-item label="内容 Hash">
              {{ detail?.content_hash || '无可靠 Hash' }} <span class="muted">（{{ detail?.hash_type }}）</span>
            </el-descriptions-item>
            <el-descriptions-item label="规则 / 引擎 / Profile 版本">
              {{ detail?.ruleset_version || '—' }} / {{ detail?.engine_version || '—' }} / {{ detail?.profile_version || '—' }}
            </el-descriptions-item>
            <el-descriptions-item label="scan_id">{{ detail?.last_scan_id || '—' }}</el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title">
          <span class="dot" />检测{{ includeHistory ? '（含历史对象）' : '（当前对象）' }}
        </div>
        <el-alert v-if="includeHistory" type="info" :closable="false" show-icon style="margin-bottom: 10px"
                  title="已包含该路径上此前内容的检测记录：同一路径内容变化后，旧对象及其证据仍然保留，便于回溯。" />
        <el-table :data="detail?.detections || []" size="small" empty-text="该实例当前没有检测">
          <el-table-column prop="category" label="类型" width="140" />
          <el-table-column prop="sensitivity_level" label="分级" width="90" />
          <el-table-column prop="severity" label="旧严重度" width="110" />
          <el-table-column prop="hit_count" label="命中数" width="90" />
          <el-table-column prop="sample_size" label="样本行" width="90" />
          <el-table-column prop="confidence" label="置信度" width="90" />
          <el-table-column prop="object_id" label="所属对象" width="100" />
          <el-table-column prop="ruleset_version" label="规则版本" width="140" show-overflow-tooltip />
          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="openEvidence(row)">证据</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot warn" />尚未接入（P1）</div>
        <el-alert type="warning" :closable="false" show-icon
                  title="该文件的业务归属、外部访问路径与主机间关系属于 P1，平台未采集，不会伪造。" />
      </div>

      <el-drawer v-model="evidenceOpen" title="检测证据" size="620px">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px"
                  title="规则、识别器、字段与命中次数；不含匹配到的原始值。" />
        <div v-if="evidenceLoading">加载中…</div>
        <div v-else-if="evidenceError" class="danger-text">{{ evidenceError }}</div>
        <template v-else-if="evidence">
          <el-table :data="evidence.items" size="small" empty-text="该检测没有结构化证据（旧版探针只上报计数）">
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
</style>
