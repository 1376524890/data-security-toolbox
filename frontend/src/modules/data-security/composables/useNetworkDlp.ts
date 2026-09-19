/**
 * The network-DLP console: the policy form, the observed transfers and the
 * regex-rule catalogue.
 *
 * Opening a transfer races the evidence fetch: `evidenceRequest` makes an older
 * response a no-op, so a slower first request cannot overwrite the row the user
 * clicked last.  That guard lives here, together with the policy and rule state;
 * the view keeps the template and the two evidence viewers.
 */
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost, apiPatch } from '../../../api/client'

export function useNetworkDlp() {
  type Policy = { enabled: boolean; categories: string[]; keywords: string[]; fingerprints: string[]; min_matches: number; min_confidence: number; exclude_cidrs: string[] }
  type Hit = { kind: string; count: number; samples: string[]; confidence?: number; sensitive?: boolean }
  type Transfer = { task_id: number; binary_available?: boolean; id: number; pcap_id: number; filename: string; src_ip: string; src_port: number; dst_ip: string; dst_port: number; size: number; sha256: string; complete: boolean; content_type: string; matches: Hit[] }
  const config = reactive<Policy>({enabled:true, categories:[], keywords:[], fingerprints:[], min_matches:1, min_confidence:0.6, exclude_cidrs:['127.0.0.0/8','::1/128']})
  const keywords = ref(''), hashes = ref(''), cidrs = ref(''), error = ref(''), busy = ref(false)
  const items = ref<Transfer[]>([]), coverage = ref<unknown[]>([])
  const selected = ref<Transfer | null>(null)
  const drawer = ref(false)
  const binary = ref(''), binaryError = ref(''), binaryLoading = ref(false)
  let evidenceRequest = 0
  async function openTransfer(row: Transfer) {
    selected.value = row; drawer.value = true; binary.value = ''; binaryError.value = ''
    const request = ++evidenceRequest
    binaryLoading.value = false
    if (!row.binary_available) return
    binaryLoading.value = true
    try {
      const data = await apiGet<{hex:string}>(`/dlp/transfers/${row.task_id}/${row.id}/content`)
      if (request === evidenceRequest) binary.value = data.hex
    } catch(e) { if (request === evidenceRequest) binaryError.value = String(e) }
    finally { if (request === evidenceRequest) binaryLoading.value = false }
  }
  type DlpRule = { id:string; name:string; entity:string; pattern:string; source:string; enabled:boolean; confidence?:number; sensitive?:boolean; alertable?:boolean; version?:string }
  const rules = ref<DlpRule[]>([]), ruleDialog = ref(false), ruleBusy = ref(false)
  const newRule = reactive({name:'', entity:'', pattern:'', enabled:true})
  // Infrastructure metadata (IP/日期等) and weak rules stay visible as evidence
  // but never raise an alert, exactly as the backend decides it.
  function alertableHit(hit: Hit) { return hit.sensitive !== false && (hit.confidence ?? 1) >= config.min_confidence }
  async function loadRules() { rules.value = (await apiGet<{items:DlpRule[]}>('/dlp/rules')).items }
  async function toggleRule(rule:DlpRule, enabled:boolean) {
    try {
      await apiPatch(`/dlp/rules/${rule.id}`, {enabled})
      if (rule.source === 'builtin') config.categories = enabled ? [...new Set([...config.categories, rule.id])] : config.categories.filter(id=>id!==rule.id)
      await loadRules()
    } catch(e) { ElMessage.error(String(e)) }
  }
  async function addRule() {
    ruleBusy.value = true
    try { await apiPost('/dlp/rules', newRule); ruleDialog.value = false; await loadRules(); ElMessage.success('规则已添加，对新分析任务生效') }
    catch(e) { ElMessage.error(String(e)) } finally { ruleBusy.value = false }
  }
  async function importPresidio() {
    ruleBusy.value = true
    try {
      const result = await apiPost<{imported:number; version:string}>('/dlp/rules/presidio/update')
      await loadRules(); ElMessage.success(`已导入 Presidio ${result.version}：${result.imported} 条正则规则`)
    } catch(e) { ElMessage.error(String(e)) } finally { ruleBusy.value = false }
  }
  async function load() {
    busy.value = true
    try {
      const [policy, data] = await Promise.all([apiGet<Policy>('/dlp/policy'), apiGet<{items:Transfer[]; coverage:unknown[]}>('/dlp/transfers')])
      Object.assign(config, policy); keywords.value = policy.keywords.join('\n'); hashes.value = policy.fingerprints.join('\n')
      cidrs.value = (policy.exclude_cidrs || []).join('\n'); items.value = data.items; coverage.value = data.coverage; error.value = ''
      await loadRules()
    } catch(e) { error.value = String(e) }
    finally { busy.value = false }
  }
  async function save() {
    busy.value = true
    try { await apiPost('/dlp/policy', {...config, keywords:keywords.value.split('\n').filter(v=>v.trim()), fingerprints:hashes.value.split('\n').map(v=>v.trim()).filter(Boolean), exclude_cidrs:cidrs.value.split('\n').map(v=>v.trim()).filter(Boolean)}); await loadRules(); ElMessage.success('策略已保存，对新分析任务生效；历史 PCAP 可重新分析') }
    catch(e) { ElMessage.error(String(e)) }
    finally { busy.value = false }
  }
  onMounted(load)
  return {
    config,
    keywords,
    hashes,
    cidrs,
    error,
    busy,
    items,
    coverage,
    selected,
    drawer,
    binary,
    binaryError,
    binaryLoading,
    rules,
    ruleDialog,
    ruleBusy,
    newRule,
    openTransfer,
    alertableHit,
    toggleRule,
    addRule,
    importPresidio,
    load,
    save,
  }
}
