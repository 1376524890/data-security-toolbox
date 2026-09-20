/**
 * Rules-centre state: the rule inventory, the engine list, the filters and
 * the add/import dialog.
 *
 * The inventory is read with ``include_content: false``; a rule's content is
 * fetched lazily when its row is expanded, and a new rule is validated by the
 * server before the list is reloaded.  The static execution labels stay in the
 * view.
 */
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { apiPost } from '../../../api/client'
import { listRules, getRuleContent, type RuleItem } from '../../../api/rules'
import { getEngineRegistry, type EngineInfo } from '../../../api/engine'

export function useRulesCenter() {
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

  return {
    loading, error, rules, activeType, activeEngine, engines, keyword, page, dialog, saving, draft,
    openAdd, readRule, saveRule, filtered, visible, types, expandRule, load,
  }
}
