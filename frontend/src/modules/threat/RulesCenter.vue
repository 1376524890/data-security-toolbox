<script setup lang="ts">
import { onMounted, ref, computed, reactive, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { apiPost } from '../../api/client'
import { listRules, getRuleContent, type RuleItem } from '../../api/rules'
import { getEngineRegistry, type EngineInfo } from '../../api/engine'
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'

const loading = ref(true)
const error = ref('')
const rules = ref<RuleItem[]>([])
const activeType = ref('')
const activeEngine = ref('')
const engines = ref<EngineInfo[]>([])
const keyword = ref('')
const page = ref(1)
const dialog = ref(false), saving = ref(false)
const draft = reactive({rule_type:'suricata' as 'suricata'|'yara', name:'', content:''})
function openAdd() { draft.rule_type = activeType.value === 'yara' ? 'yara' : 'suricata'; dialog.value = true }
async function readRule(file: {raw?:File}) {
  if (!file.raw) return
  if (file.raw.size > 1024 * 1024) { ElMessage.error('规则文件不能超过 1 MB'); return }
  draft.content = await file.raw.text()
  draft.name = file.raw.name.replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9_-]/g, '_')
}
async function saveRule() {
  saving.value = true
  try { await apiPost('/rules', draft); activeType.value = draft.rule_type; dialog.value = false; await load(); ElMessage.success('规则已校验并添加，对新检测任务生效') }
  catch(e) { ElMessage.error(String(e)) } finally { saving.value = false }
}

const filtered = computed(() => rules.value.filter((r: RuleItem) =>
  (!activeType.value || r.type === activeType.value) &&
  (!activeEngine.value || r.engine === activeEngine.value) &&
  `${r.name} ${r.rule_id || ''} ${r.path}`.toLowerCase().includes(keyword.value.toLowerCase())))
const visible = computed(() => filtered.value.slice((page.value - 1) * 30, page.value * 30))
const types = computed(() => [...new Set(rules.value.map(r => r.type))].sort())
const executionLabels: Record<string, string> = {
  active: '已接入执行', external: '待外部部署', unsupported: '语法不兼容', incomplete: '缺少依赖',
}
watch([activeType, activeEngine, keyword], () => { page.value = 1 })
async function expandRule(row: RuleItem, expanded: RuleItem[]): Promise<void> {
  if (!expanded.includes(row) || row.content) return
  try { row.content = (await getRuleContent(row)).content }
  catch (err) { ElMessage.error(err instanceof Error ? err.message : String(err)) }
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [result, registry] = await Promise.all([listRules({ include_content: false }), getEngineRegistry()])
    rules.value = result.items
    engines.value = registry
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-select v-model="activeEngine" clearable filterable placeholder="全部引擎" style="width: 230px">
        <el-option v-for="engine in engines" :key="engine.name" :value="engine.name" :label="`${engine.label || engine.name} (${engine.rule_count || 0})`" />
      </el-select>
      <el-select v-model="activeType" clearable placeholder="全部类型" style="width: 150px">
        <el-option v-for="type in types" :key="type" :value="type" :label="type" />
      </el-select>
      <el-input v-model="keyword" clearable placeholder="搜索规则名称或 ID" style="width: 230px" />
      <div class="toolbar-spacer" />
      <el-button type="primary" @click="openAdd">添加 / 导入检查规则</el-button>
    </div>
    <el-dialog v-model="dialog" title="添加检查规则" width="760px">
      <el-form label-width="100px">
        <el-form-item label="规则类型"><el-select v-model="draft.rule_type"><el-option label="Suricata 网络规则" value="suricata" /><el-option label="YARA 文件规则" value="yara" /></el-select></el-form-item>
        <el-form-item label="规则库名称"><el-input v-model="draft.name" placeholder="英文字母、数字、下划线或连字符" maxlength="100" /></el-form-item>
        <el-form-item label="导入文件"><el-upload :auto-upload="false" :show-file-list="false" :on-change="readRule" accept=".rules,.yar,.yara"><el-button>选择本地规则文件</el-button></el-upload></el-form-item>
        <el-form-item label="规则内容"><el-input v-model="draft.content" type="textarea" :rows="12" placeholder="输入完整 Suricata 或 YARA 规则" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog=false">取消</el-button><el-button :loading="saving" type="primary" @click="saveRule">校验并添加</el-button></template>
    </el-dialog>
    <StateBox :loading="loading" :error="error" :empty="!filtered.length" @retry="load">
      <el-table :data="visible" :row-key="(row: RuleItem) => `${row.engine}:${row.path}`" @expand-change="expandRule">
        <el-table-column type="expand"><template #default="{ row }"><RawViewer :value="row.content" language="plaintext" :height="280" /></template></el-table-column>
        <el-table-column prop="name" label="规则 / 文件" min-width="260" show-overflow-tooltip />
        <el-table-column prop="engine" label="引擎" min-width="170" />
        <el-table-column prop="type" label="类型" width="110" />
        <el-table-column label="接入状态" width="140"><template #default="{ row }">{{ executionLabels[row.execution] || '待核实' }}</template></el-table-column>
        <el-table-column prop="size" label="大小 (B)" width="120" />
      </el-table>
      <el-pagination v-model:current-page="page" :page-size="30" :total="filtered.length" layout="total, prev, pager, next" style="margin-top: 12px" />
    </StateBox>
  </div>
</template>

<style scoped>
.rule-card { display: flex; flex-direction: column; gap: 8px; }
.rule-head { display: flex; align-items: center; justify-content: space-between; }
.rule-name { font-weight: 700; color: var(--soc-text-strong); }
.rule-meta { display: flex; gap: 16px; color: var(--soc-text-muted); font-size: 12px; }
.rule-path { color: var(--soc-text-dim); font-size: 11px; word-break: break-all; }
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
