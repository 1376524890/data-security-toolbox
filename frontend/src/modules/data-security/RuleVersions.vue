<script setup lang="ts">
import { onMounted, ref, computed, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import {
  listRuleSets, listRuleSetVersions, publishRuleSetVersion, rollbackRuleSetVersion,
  type RuleSetSummary, type RuleSetVersion,
} from '../../api/ruleSets'
import { listProbes, type Probe } from '../../api/probes'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'

// The central rule set is the single source of truth for detection rules. This
// page shows the published versions and the *observed* sync result per probe, so
// a failed hot update is visible here instead of only in a probe log.
const loading = ref(true)
const error = ref('')
const ruleSet = ref<RuleSetSummary | null>(null)
const versions = ref<RuleSetVersion[]>([])
const probes = ref<Probe[]>([])

const dialog = ref(false)
const saving = ref(false)
const draft = reactive({ version: '', changelog: '', min_agent_version: '' })

const activeVersion = computed(() => ruleSet.value?.active_version || null)
const syncedProbes = computed(() => probes.value.filter((p) => probedVersion(p) !== ''))
const outOfDateProbes = computed(() =>
  probes.value.filter((p) => {
    const current = probedVersion(p)
    return current !== '' && activeVersion.value !== null && current !== activeVersion.value.version
  }),
)
const failedProbes = computed(() => probes.value.filter((p) => String(probeField(p, 'ruleset_last_error') || '') !== ''))

function md(probe: Probe): Record<string, unknown> {
  return (probe.metadata || {}) as Record<string, unknown>
}
function probeField(probe: Probe, key: string): unknown {
  return md(probe)[key]
}
function probedVersion(probe: Probe): string {
  return String(probeField(probe, 'current_ruleset_version') || '')
}
function shortHash(value: string): string {
  return value ? `${value.slice(0, 12)}…` : '—'
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const sets = await listRuleSets()
    ruleSet.value = sets.items[0] || null
    if (!ruleSet.value) {
      versions.value = []
      probes.value = []
      return
    }
    const [versionResult, probeResult] = await Promise.all([
      listRuleSetVersions(ruleSet.value.id),
      listProbes({ page: 1, page_size: 200 }),
    ])
    versions.value = versionResult.items
    probes.value = probeResult.items
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function openPublish(): void {
  const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')
  draft.version = `rel-${stamp}`
  draft.changelog = ''
  draft.min_agent_version = ''
  dialog.value = true
}

async function publish(): Promise<void> {
  if (!ruleSet.value) return
  saving.value = true
  try {
    const created = await publishRuleSetVersion(ruleSet.value.id, {
      version: draft.version, changelog: draft.changelog, min_agent_version: draft.min_agent_version,
    })
    dialog.value = false
    await load()
    ElMessage.success(`已发布 ${created.version}（${created.rule_count} 条规则），探针将在下次同步时更新`)
  } catch (err) {
    // A rejected publish is a real validation failure (bad rule, duplicate
    // version); the server reason is shown instead of a generic message.
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    saving.value = false
  }
}

async function rollback(row: RuleSetVersion): Promise<void> {
  if (!ruleSet.value) return
  try {
    const created = await rollbackRuleSetVersion(ruleSet.value.id, {
      to_version: row.version, changelog: `回滚到 ${row.version}`,
    })
    await load()
    ElMessage.success(`已回滚并发布新版本 ${created.version}（来源 ${created.origin_version}）`)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <div class="toolbar-title">检测规则版本</div>
        <el-tag v-if="ruleSet" size="small" type="info">{{ ruleSet.name }}</el-tag>
        <div class="toolbar-spacer" />
        <el-button :disabled="!ruleSet" @click="openPublish">发布新版本</el-button>
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4" style="margin-top: 12px">
        <StatCard label="当前生效版本" :value="activeVersion?.version || '尚无'" tone="primary"
                  :sub="activeVersion ? `${activeVersion.rule_count} 条规则` : '规则集未初始化'" />
        <StatCard label="工作副本规则" :value="ruleSet?.working_rule_count ?? 0"
                  sub="编辑中的规则，发布后才会下发" />
        <StatCard label="已发布版本" :value="versions.length" sub="不可变快照，含回滚记录" />
        <StatCard label="探针已同步" :value="`${syncedProbes.length}/${probes.length}`" tone="success"
                  :sub="outOfDateProbes.length ? `${outOfDateProbes.length} 台待更新` : '全部为当前版本'" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />探针规则同步状态</div>
        <el-table :data="probes" size="small" empty-text="尚未登记探针">
          <el-table-column prop="name" label="探针" min-width="140" />
          <el-table-column label="在线状态" width="100">
            <template #default="{ row }">
              <el-tag size="small" :type="row.status === 'online' ? 'success' : 'info'">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="当前规则版本" min-width="150">
            <template #default="{ row }">
              <template v-if="probedVersion(row)">
                <span>{{ probedVersion(row) }}</span>
                <el-tag v-if="activeVersion && probedVersion(row) !== activeVersion.version" size="small" type="warning"
                        style="margin-left: 6px">待更新</el-tag>
              </template>
              <span v-else class="muted">尚未上报（旧版探针不支持规则版本）</span>
            </template>
          </el-table-column>
          <el-table-column label="规则来源" width="110">
            <template #default="{ row }">
              <span v-if="probeField(row, 'ruleset_source')">
                {{ probeField(row, 'ruleset_source') === 'server' ? '平台下发' : '随包内置' }}
              </span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column label="热更新能力" width="110">
            <template #default="{ row }">
              <span v-if="!probeField(row, 'capabilities')" class="muted">未上报</span>
              <el-tag v-else size="small"
                      :type="(probeField(row, 'capabilities') as Record<string, unknown>).ruleset_hot_update ? 'success' : 'danger'">
                {{ (probeField(row, 'capabilities') as Record<string, unknown>).ruleset_hot_update ? '支持' : '不支持' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="最近一次同步失败原因" min-width="220">
            <template #default="{ row }">
              <span v-if="probeField(row, 'ruleset_last_error')" class="danger-text">
                {{ probeField(row, 'ruleset_last_error') }}
              </span>
              <span v-else class="muted">无</span>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />发布记录（不可变）</div>
        <el-table :data="versions" size="small" empty-text="尚未发布任何版本">
          <el-table-column prop="version" label="版本" min-width="150">
            <template #default="{ row }">
              <strong>{{ row.version }}</strong>
              <el-tag v-if="activeVersion && row.id === activeVersion.id" size="small" type="success"
                      style="margin-left: 6px">当前生效</el-tag>
              <el-tag v-else-if="row.status === 'superseded'" size="small" type="info" style="margin-left: 6px">已被取代</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="rule_count" label="规则数" width="80" />
          <el-table-column label="SHA256" min-width="140">
            <template #default="{ row }"><code>{{ shortHash(row.sha256) }}</code></template>
          </el-table-column>
          <el-table-column label="引擎/模式" width="120">
            <template #default="{ row }">{{ row.engine_version }} / {{ row.schema_version }}</template>
          </el-table-column>
          <el-table-column label="最低探针版本" width="120">
            <template #default="{ row }">
              <span v-if="row.min_agent_version">{{ row.min_agent_version }}</span>
              <span v-else class="muted">不限</span>
            </template>
          </el-table-column>
          <el-table-column label="来源版本" width="120">
            <template #default="{ row }">
              <span v-if="row.origin_version">{{ row.origin_version }}</span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="published_by" label="发布人" width="110" />
          <el-table-column prop="changelog" label="说明" min-width="160" show-overflow-tooltip />
          <el-table-column label="发布时间" width="170">
            <template #default="{ row }">{{ row.created_at?.replace('T', ' ').slice(0, 19) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="90" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small"
                         :disabled="activeVersion ? row.id === activeVersion.id : false"
                         @click="rollback(row)">回滚</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <el-dialog v-model="dialog" title="发布规则版本" width="620px">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px"
                  title="发布后版本不可修改；编辑规则后再次发布会产生新版本，回滚同样生成新的可追溯版本。" />
        <el-form label-width="120px">
          <el-form-item label="版本号">
            <el-input v-model="draft.version" placeholder="例如 rel-202609161200" />
          </el-form-item>
          <el-form-item label="最低探针版本">
            <el-input v-model="draft.min_agent_version" placeholder="留空表示不限；低于该版本的探针将拒绝下载" />
          </el-form-item>
          <el-form-item label="变更说明">
            <el-input v-model="draft.changelog" type="textarea" :rows="3" placeholder="本次变更内容" />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="dialog = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="publish">发布</el-button>
        </template>
      </el-dialog>
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.muted { color: var(--soc-text-dim); }
.danger-text { color: #ef4444; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
</style>
