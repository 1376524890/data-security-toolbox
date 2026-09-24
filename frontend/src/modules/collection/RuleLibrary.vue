<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import StateBox from '../../components/common/StateBox.vue'
import { apiGet, apiPatch, apiPost } from '../../api/client'
import { useAutoRefresh } from '../../composables/useAutoRefresh'
import { useTableSort, sortRows } from '../../composables/useTableSort'

// The rule set: the regular expressions that drive sensitive-data discovery and
// network traffic monitoring. This is the single place a rule is written;
// 数据流动与防护 only shows an on/off switch.
interface Rule {
  id: string; name: string; entity: string; pattern: string; source: string
  enabled: boolean; confidence?: number; sensitive?: boolean; alertable?: boolean; version?: string
}

const loading = ref(true)
const error = ref('')
const rules = ref<Rule[]>([])
const busy = ref(false)
const dialog = ref(false)
const draft = reactive({ name: '', entity: '', pattern: '', enabled: true })
// The whole rule set arrives in one response (no paging), so filtering and
// sorting happen here rather than costing a round trip per keystroke.
const filters = reactive({ search: '', source: '', enabled: '' })
const { sort, onSortChange } = useTableSort()
const sources = computed(() => [...new Set(rules.value.map((rule) => rule.source).filter(Boolean))].sort())
const visibleRules = computed(() => {
  const needle = filters.search.trim().toLowerCase()
  const rows = rules.value.filter((rule) => {
    if (filters.source && rule.source !== filters.source) return false
    if (filters.enabled === 'yes' && !rule.enabled) return false
    if (filters.enabled === 'no' && rule.enabled) return false
    if (!needle) return true
    return [rule.name, rule.entity, rule.pattern].some(
      (field) => String(field || '').toLowerCase().includes(needle))
  })
  return sortRows(rows, sort.prop, sort.order, (rule, prop) => (rule as unknown as Record<string, unknown>)[prop])
})
/** Categories already in use, so a new rule can reuse one instead of inventing a
 *  near-duplicate spelling. Free text stays possible. */
const entities = computed(() => [...new Set(rules.value.map((rule) => rule.entity).filter(Boolean))].sort())

async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
  if (!silent) { loading.value = true; error.value = '' }
  try {
    rules.value = (await apiGet<{ items: Rule[] }>('/dlp/rules')).items
    error.value = ''
  } catch (err) {
    if (!silent) error.value = String(err)
  } finally {
    if (!silent) loading.value = false
  }
}

// Rules only change when an operator edits them, so this is a slow poll on
// purpose: it exists to pick up another analyst's edit, not to chase data.
useAutoRefresh(load, { intervalMs: 120000 })

async function toggle(rule: Rule, enabled: boolean): Promise<void> {
  try {
    await apiPatch(`/dlp/rules/${rule.id}`, { enabled })
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  }
}

async function add(): Promise<void> {
  busy.value = true
  try {
    await apiPost('/dlp/rules', { ...draft })
    dialog.value = false
    draft.name = ''
    draft.entity = ''
    draft.pattern = ''
    ElMessage.success('规则已添加，对后续分析生效')
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  } finally {
    busy.value = false
  }
}

async function importPresidio(): Promise<void> {
  busy.value = true
  try {
    const result = await apiPost<{ imported: number; version: string }>('/dlp/rules/presidio/update')
    ElMessage.success(`已导入 Presidio ${result.version}：${result.imported} 条正则规则`)
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <strong>规则集与规则</strong>
      <span class="muted">敏感数据发现与网络流量监控的正则匹配规则</span>
      <div class="toolbar-spacer" />
      <el-button :loading="busy" @click="importPresidio">导入 / 更新 Presidio 规则库</el-button>
      <el-button @click="load()">刷新</el-button>
      <el-button type="primary" @click="dialog = true">手动添加规则</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar" style="margin-bottom: 10px">
        <el-input v-model="filters.search" clearable placeholder="规则名称 / 类别 / 正则" style="width: 260px" />
        <el-select v-model="filters.source" clearable placeholder="全部来源" style="width: 150px">
          <el-option v-for="item in sources" :key="item" :label="item" :value="item" />
        </el-select>
        <el-select v-model="filters.enabled" clearable placeholder="全部状态" style="width: 130px">
          <el-option label="已启用" value="yes" />
          <el-option label="已停用" value="no" />
        </el-select>
        <span class="muted">显示 {{ visibleRules.length }} / {{ rules.length }} 条</span>
      </div>
      <el-table :data="visibleRules" size="small" max-height="460" empty-text="尚无规则" @sort-change="onSortChange">
        <el-table-column prop="name" label="规则名称" min-width="200" sortable="custom" />
        <el-table-column prop="source" label="来源" width="120" sortable="custom" />
        <el-table-column prop="entity" label="敏感类别" min-width="140" sortable="custom" />
        <el-table-column prop="confidence" label="置信度" width="100" sortable="custom" />
        <el-table-column label="可告警" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.alertable ? 'success' : 'info'">{{ row.alertable ? '是' : '仅证据' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="启用" width="90">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled" @change="(v: boolean | string | number) => toggle(row, Boolean(v))" />
          </template>
        </el-table-column>
        <el-table-column prop="pattern" label="正则表达式" min-width="260" show-overflow-tooltip />
      </el-table>
    </StateBox>

    <el-dialog v-model="dialog" title="添加规则" width="640px">
      <el-form label-width="100px">
        <el-form-item label="规则名称"><el-input v-model="draft.name" maxlength="200" /></el-form-item>
        <el-form-item label="敏感类别">
          <el-select v-model="draft.entity" filterable allow-create default-first-option
                     placeholder="选择已用类别，或输入新的类别名" style="width: 320px">
            <el-option v-for="entity in entities" :key="entity" :label="entity" :value="entity" />
          </el-select>
        </el-form-item>
        <el-form-item label="正则表达式"><el-input v-model="draft.pattern" type="textarea" :rows="5" placeholder="例如：内部编号：[A-Z]{2}-[0-9]{6}" /></el-form-item>
        <el-form-item label="立即启用"><el-switch v-model="draft.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="add">校验并保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; margin-left: 8px; }
</style>
