<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getEngineRegistry, syncEngineRules, type EngineInfo, type RuleSyncResult } from '../../api/engine'
import { Refresh } from '@element-plus/icons-vue'
import { listIntegrations } from '../../api/integrations'
import type { IntegrationStatus } from '../../types/integration'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const engines = ref<EngineInfo[]>([])
const integrations = ref<IntegrationStatus[]>([])
const keyword = ref('')
const syncing = ref('')
const syncResults = ref<RuleSyncResult[]>([])

async function updateRules(entry: EngineInfo): Promise<void> {
  syncing.value = entry.name
  try {
    const result = await syncEngineRules(entry.name)
    syncResults.value = result.results
    await load()
  } catch (err) {
    syncResults.value = [{ engine: entry.name, status: 'failed', files: 0,
      detail: err instanceof Error ? err.message : String(err) }]
  } finally {
    syncing.value = ''
  }
}

const totalRules = computed(() => engines.value.reduce((sum, item) => sum + (item.rule_count || 0), 0))
const totalDetections = computed(() => engines.value.reduce((sum, item) => sum + (item.detection_count || 0), 0))

function adapterStatus(entry: EngineInfo): string {
  const adapter = integrations.value.find((item) => item.name.toLowerCase() === entry.name.toLowerCase())
  if (!adapter) return 'ready'
  return adapter.installed && adapter.enabled ? adapter.status : 'disabled'
}

const rows = computed(() => {
  const text = keyword.value.trim().toLowerCase()
  return engines.value.filter((item) => {
    if (!text) return true
    return [item.name, item.label, item.slug].some((field) => String(field || '').toLowerCase().includes(text))
  })
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [registry, adapters] = await Promise.all([getEngineRegistry(), listIntegrations()])
    engines.value = [...registry].sort((a, b) => (b.detection_count || 0) - (a.detection_count || 0) || a.name.localeCompare(b.name))
    integrations.value = adapters
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function open(entry: EngineInfo): void {
  router.push(`/engines/${entry.slug || entry.name}`)
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-input v-model="keyword" placeholder="搜索引擎名称或标识" clearable style="width: 240px" />
      <div class="toolbar-spacer" />
      <el-button @click="load">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="stat-grid cols-3" style="margin-bottom: 12px">
        <StatCard label="引擎" :value="engines.length" tone="info" />
        <StatCard label="规则资源" :value="totalRules" tone="warning" />
        <StatCard label="累计检测" :value="totalDetections" tone="danger" />
      </div>

      <div class="soc-card">
        <div class="soc-card-title"><span class="dot" />全部检测引擎</div>
        <el-table :data="rows" size="small" @row-click="open">
          <el-table-column label="引擎" min-width="200">
            <template #default="{ row }">
              <div class="eng-name">{{ row.label || row.name }}</div>
              <div class="eng-id mono">{{ row.name }}</div>
            </template>
          </el-table-column>
          <el-table-column label="类型" width="120">
            <template #default="{ row }">
              <el-tag size="small" effect="plain" :type="row.bridge ? 'warning' : 'primary'">
                {{ row.bridge ? '第三方适配器' : '平台内置' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="version" label="版本" width="90" />
          <el-table-column label="状态" width="110">
            <template #default="{ row }"><StatusBadge :value="adapterStatus(row)" /></template>
          </el-table-column>
          <el-table-column label="规则资源" width="100" align="right">
            <template #default="{ row }"><span class="mono">{{ row.rule_count ?? 0 }}</span></template>
          </el-table-column>
          <el-table-column prop="active_rule_files" label="已接入资源" width="110" align="right" />
          <el-table-column label="检测数" width="100" align="right">
            <template #default="{ row }"><span class="mono">{{ row.detection_count ?? 0 }}</span></template>
          </el-table-column>
          <el-table-column label="规则来源" min-width="220">
            <template #default="{ row }">
              <span class="text-dim">{{ row.rule_source || '平台检查规则' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="210">
            <template #default="{ row }">
              <el-button link @click.stop="open(row)">查看规则</el-button>
              <el-button v-if="row.refreshable" link :icon="Refresh" :loading="syncing === row.name"
                :disabled="!!syncing" @click.stop="updateRules(row)">在线更新</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div v-if="!rows.length" class="text-dim">没有匹配的引擎。</div>
      </div>
      <el-table v-if="syncResults.length" :data="syncResults" size="small" style="margin-top: 12px">
        <el-table-column prop="engine" label="更新引擎" width="180" />
        <el-table-column label="结果" width="90"><template #default="{ row }">{{ row.status === 'updated' ? '已更新' : '未更新' }}</template></el-table-column>
        <el-table-column prop="files" label="文件/识别器" width="110" />
        <el-table-column prop="detail" label="更新详情" min-width="240" />
      </el-table>
    </StateBox>
  </div>
</template>

<style scoped>
.eng-name { font-weight: 600; color: var(--soc-text-strong); }
.eng-id { font-size: 11px; color: var(--soc-text-dim); }
.link { color: var(--soc-primary); font-size: 12px; }
:deep(.el-table__row) { cursor: pointer; }
</style>
