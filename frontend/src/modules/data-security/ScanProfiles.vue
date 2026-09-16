<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  createScanProfile, deleteScanProfile, listScanProfiles, runScanProfile, updateScanProfile,
  type ScanProfile, type ScanProfileDraft,
} from '../../api/scanProfiles'
import { listProbes, type Probe } from '../../api/probes'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'

// A ScanProfile is a versioned scan configuration. `enabled` only means "usable
// for a job" - it never turns scheduled collection on, and the probe's own
// `[data].enabled` remains the switch that decides whether the host scans.
const loading = ref(true)
const error = ref('')
const profiles = ref<ScanProfile[]>([])
const probes = ref<Probe[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)

const dialog = ref(false)
const saving = ref(false)
const editingId = ref<number | null>(null)
const runDialog = ref(false)
const runProfile = ref<ScanProfile | null>(null)
const runProbeId = ref<number | null>(null)

function emptyDraft(): ScanProfileDraft {
  return {
    name: '', description: '', include_paths: [], exclude_paths: [], file_types: [],
    max_files: 200, max_dirs: 500, max_depth: 3, max_runtime_seconds: 120,
    max_bytes_read: 512 * 1024 * 1024, max_single_file_size: 2 * 1024 * 1024,
    max_full_hash_size: 8 * 1024 * 1024, large_file_sampling: true,
    sample_block_size: 64 * 1024, max_sample_rows: 25, max_cpu_seconds: 0, max_rss_mb: 0,
    xlsx_max_entries: 512, xlsx_max_uncompressed_bytes: 64 * 1024 * 1024,
    xlsx_max_compression_ratio: 200, xlsx_max_shared_strings: 200000,
    xlsx_max_sheets: 32, xlsx_max_columns: 256, xlsx_max_rows: 200,
    enabled: true, scheduled: false, interval_seconds: 3600,
  }
}

const draft = reactive<ScanProfileDraft>(emptyDraft())
const includePathsText = ref('')
const excludePathsText = ref('')

const activeProfiles = computed(() => profiles.value.filter((item) => item.enabled).length)
const scheduledProfiles = computed(() => profiles.value.filter((item) => item.scheduled).length)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [profileResult, probeResult] = await Promise.all([
      listScanProfiles({ page: page.value, page_size: pageSize.value }),
      listProbes({ page: 1, page_size: 200 }),
    ])
    profiles.value = profileResult.items
    total.value = profileResult.total
    probes.value = probeResult.items
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function openCreate(): void {
  editingId.value = null
  Object.assign(draft, emptyDraft())
  includePathsText.value = ''
  excludePathsText.value = ''
  dialog.value = true
}

function openEdit(row: ScanProfile): void {
  editingId.value = row.id
  Object.assign(draft, { ...emptyDraft(), ...row })
  includePathsText.value = row.include_paths.join('\n')
  excludePathsText.value = row.exclude_paths.join('\n')
  dialog.value = true
}

function splitLines(value: string): string[] {
  return value.split('\n').map((line) => line.trim()).filter(Boolean)
}

async function save(): Promise<void> {
  saving.value = true
  try {
    const payload: Partial<ScanProfileDraft> = {
      ...draft,
      include_paths: splitLines(includePathsText.value),
      exclude_paths: splitLines(excludePathsText.value),
    }
    if (editingId.value === null) {
      await createScanProfile(payload)
      ElMessage.success('已创建扫描配置')
    } else {
      await updateScanProfile(editingId.value, payload)
      ElMessage.success('已更新扫描配置（版本号 +1，已登记任务仍按旧快照执行）')
    }
    dialog.value = false
    await load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    saving.value = false
  }
}

async function remove(row: ScanProfile): Promise<void> {
  try {
    await ElMessageBox.confirm(`删除扫描配置「${row.name}」？已下发的任务不受影响。`, '确认删除')
  } catch {
    return
  }
  try {
    await deleteScanProfile(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function openRun(row: ScanProfile): void {
  runProfile.value = row
  runProbeId.value = probes.value[0]?.id ?? null
  runDialog.value = true
}

async function dispatch(): Promise<void> {
  if (!runProfile.value || !runProbeId.value) return
  try {
    const task = await runScanProfile(runProfile.value.id, runProbeId.value)
    runDialog.value = false
    ElMessage.success(`已下发任务 #${task.id}，可在数据资产任务页查看进度`)
  } catch (err) {
    // 409/400 here are real refusals (probe busy, empty include_paths), so the
    // server reason is surfaced instead of a generic failure.
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <div class="toolbar-title">扫描配置（ScanProfile）</div>
        <div class="toolbar-spacer" />
        <el-button type="primary" @click="openCreate">新建配置</el-button>
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="配置总数" :value="total" />
        <StatCard label="已启用" :value="activeProfiles" sub="仅表示可用于建任务" />
        <StatCard label="标记为定时" :value="scheduledProfiles" tone="warning"
                  sub="平台不会自动巡检；探针 [data].enabled 仍为最终开关" />
        <StatCard label="可用探针" :value="probes.length" />
      </div>

      <el-alert type="info" :closable="false" show-icon style="margin: 12px 0"
                title="任务保存配置快照：配置在任务登记后被修改，不会改变探针已经执行的内容。exclude_paths 与 file_types 已保存但探针暂未执行，报告不会声称已过滤。" />

      <div class="soc-card">
        <el-table :data="profiles" size="small" empty-text="尚未创建扫描配置">
          <el-table-column prop="name" label="名称" min-width="150" />
          <el-table-column prop="version" label="版本" width="70" />
          <el-table-column label="包含路径" min-width="220">
            <template #default="{ row }">
              <span v-if="row.include_paths.length"><code class="key">{{ row.include_paths.join('  ') }}</code></span>
              <span v-else class="danger-text">未设置（无法下发）</span>
            </template>
          </el-table-column>
          <el-table-column label="预算" width="230">
            <template #default="{ row }">
              <span class="muted">{{ row.max_files }} 文件 / 深度 {{ row.max_depth }} / {{ row.max_runtime_seconds }}s / Hash≤{{ Math.round(row.max_full_hash_size / 1048576) }}MiB</span>
            </template>
          </el-table-column>
          <el-table-column label="启用" width="80">
            <template #default="{ row }">
              <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '是' : '否' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="定时" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.scheduled ? 'warning' : 'info'">{{ row.scheduled ? '已标记' : '未启用' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="updated_at" label="更新时间" width="170">
            <template #default="{ row }">{{ row.updated_at?.replace('T', ' ').slice(0, 19) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="200" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" :disabled="!row.enabled" @click="openRun(row)">下发</el-button>
              <el-button link size="small" @click="openEdit(row)">编辑</el-button>
              <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-pagination class="pagination" layout="total, prev, pager, next" :total="total"
                       :current-page="page" :page-size="pageSize"
                       @current-change="(value: number) => { page = value; load() }" />
      </div>

      <el-dialog v-model="dialog" :title="editingId === null ? '新建扫描配置' : '编辑扫描配置'" width="760px">
        <el-form label-width="150px">
          <el-form-item label="名称">
            <el-input v-model="draft.name" placeholder="例如 业务服务器-敏感数据" />
          </el-form-item>
          <el-form-item label="说明">
            <el-input v-model="draft.description" />
          </el-form-item>
          <el-form-item label="包含路径">
            <el-input v-model="includePathsText" type="textarea" :rows="3"
                      placeholder="每行一个绝对路径，例如 /srv/data" />
          </el-form-item>
          <el-form-item label="排除路径">
            <el-input v-model="excludePathsText" type="textarea" :rows="2"
                      placeholder="每行一个；已保存但当前探针版本尚未执行，报告会如实说明" />
          </el-form-item>
          <el-row :gutter="12">
            <el-col :span="8"><el-form-item label="最大文件数"><el-input-number v-model="draft.max_files" :min="1" :max="2000" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="最大目录数"><el-input-number v-model="draft.max_dirs" :min="1" :max="20000" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="最大深度"><el-input-number v-model="draft.max_depth" :min="0" :max="8" /></el-form-item></el-col>
          </el-row>
          <el-row :gutter="12">
            <el-col :span="8"><el-form-item label="运行秒数"><el-input-number v-model="draft.max_runtime_seconds" :min="5" :max="1800" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="单文件样本(字节)"><el-input-number v-model="draft.max_single_file_size" :min="1024" :step="1048576" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="完整 Hash 上限(字节)"><el-input-number v-model="draft.max_full_hash_size" :min="0" :step="1048576" /></el-form-item></el-col>
          </el-row>
          <el-row :gutter="12">
            <el-col :span="8"><el-form-item label="采样块大小"><el-input-number v-model="draft.sample_block_size" :min="4096" :step="4096" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="最大样本行"><el-input-number v-model="draft.max_sample_rows" :min="1" :max="500" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="读取字节上限"><el-input-number v-model="draft.max_bytes_read" :min="1048576" :step="10485760" /></el-form-item></el-col>
          </el-row>
          <el-row :gutter="12">
            <el-col :span="8"><el-form-item label="大文件采样"><el-switch v-model="draft.large_file_sampling" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="启用"><el-switch v-model="draft.enabled" /></el-form-item></el-col>
            <el-col :span="8"><el-form-item label="标记定时"><el-switch v-model="draft.scheduled" /></el-form-item></el-col>
          </el-row>
          <el-form-item label="CPU / 内存上限">
            <el-input-number v-model="draft.max_cpu_seconds" :min="0" /> 秒
            <el-input-number v-model="draft.max_rss_mb" :min="0" style="margin-left: 8px" /> MiB
            <span class="muted" style="margin-left: 8px">0 表示关闭</span>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="dialog = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="save">保存</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="runDialog" title="下发采集任务" width="480px">
        <el-form label-width="110px">
          <el-form-item label="配置">
            <el-tag size="small" type="info">{{ runProfile?.name }} v{{ runProfile?.version }}</el-tag>
          </el-form-item>
          <el-form-item label="包含路径">
            <code class="key">{{ (runProfile?.include_paths || []).join('  ') }}</code>
          </el-form-item>
          <el-form-item label="目标探针">
            <el-select v-model="runProbeId" placeholder="选择探针" style="width: 100%">
              <el-option v-for="probe in probes" :key="probe.id" :label="`${probe.name}（${probe.ip_address || probe.hostname}）`"
                         :value="probe.id" />
            </el-select>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="runDialog = false">取消</el-button>
          <el-button type="primary" :disabled="!runProbeId" @click="dispatch">下发</el-button>
        </template>
      </el-dialog>
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.key { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.muted { color: var(--soc-text-dim); }
.danger-text { color: #ef4444; }
</style>
