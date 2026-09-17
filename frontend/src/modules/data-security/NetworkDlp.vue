<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost, apiPatch } from '../../api/client'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import HexViewer from '../../components/evidence/HexViewer.vue'
import { downloadUrl } from '../../api/client'
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
</script>
<template>
  <div v-loading="busy">
    <el-alert title="旁路防泄密检测：重组明文 TCP，识别 HTTP 上传 / 下载、表单、文件指纹及敏感内容。生成告警，不直接阻断；不解密 HTTPS。" type="info" :closable="false" style="margin-bottom:16px" />
    <el-alert v-if="error" :title="error" type="error" />
    <div class="toolbar" style="margin:16px 0"><b>现有规则库（{{rules.length}}）</b><div class="toolbar-spacer" />
      <el-button :loading="ruleBusy" @click="importPresidio">下载 / 更新 Presidio 规则库并导入</el-button>
      <el-button type="primary" @click="ruleDialog=true">手动添加规则</el-button>
    </div>
    <el-alert title="Presidio 导入官方静态正则，不包含 NLP、上下文评分和 Python 校验器；置信度低于告警阈值的规则默认停用，可按业务启用。IP、MAC、日期等定位符与弱规则只作为传输证据，不会单独触发告警；重新导入 Presidio 可刷新各规则置信度。所有变更对后续分析生效。" type="info" :closable="false" />
    <el-table :data="rules" max-height="320" size="small">
      <el-table-column prop="name" label="规则名称" min-width="220" />
      <el-table-column prop="source" label="来源" width="100" />
      <el-table-column prop="entity" label="敏感类别" min-width="140" />
      <el-table-column prop="confidence" label="置信度" width="90" />
      <el-table-column label="可告警" width="90"><template #default="{row}"><el-tag :type="row.alertable ? 'success' : 'info'" size="small">{{row.alertable ? '是' : '仅证据'}}</el-tag></template></el-table-column>
      <el-table-column label="启用" width="80"><template #default="{row}"><el-switch :model-value="row.enabled" @change="(value: boolean | string | number)=>toggleRule(row, Boolean(value))" /></template></el-table-column>
      <el-table-column prop="pattern" label="正则表达式" min-width="260" show-overflow-tooltip />
    </el-table>
    <el-dialog v-model="ruleDialog" title="添加防泄密规则" width="650px">
      <el-form label-width="100px">
        <el-form-item label="规则名称"><el-input v-model="newRule.name" maxlength="200" /></el-form-item>
        <el-form-item label="敏感类别"><el-input v-model="newRule.entity" placeholder="例如：INTERNAL_DOCUMENT" /></el-form-item>
        <el-form-item label="正则表达式"><el-input v-model="newRule.pattern" type="textarea" :rows="5" placeholder="例如：内部编号：[A-Z]{2}-[0-9]{6}" /></el-form-item>
        <el-form-item label="立即启用"><el-switch v-model="newRule.enabled" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="ruleDialog=false">取消</el-button><el-button type="primary" :loading="ruleBusy" @click="addRule">校验并保存</el-button></template>
    </el-dialog>
    <el-collapse><el-collapse-item title="检测策略" name="policy">
      <el-form label-width="120px">
        <el-form-item label="开启检测"><el-switch v-model="config.enabled" /></el-form-item>
        <el-form-item label="敏感类别"><el-checkbox-group v-model="config.categories"><el-checkbox v-for="item in [['phone','手机号'],['id_card','身份证'],['email','邮箱'],['bank_card','银行卡'],['api_key','API 密钥'],['token','长 Token']]" :key="item[0]" :value="item[0]">{{item[1]}}</el-checkbox></el-checkbox-group></el-form-item>
        <el-form-item label="最少命中次数"><el-input-number v-model="config.min_matches" :min="1" :max="1000" /></el-form-item>
        <el-form-item label="告警最低置信度"><el-input-number v-model="config.min_confidence" :min="0" :max="1" :step="0.05" :precision="2" /><span style="margin-left:8px;color:var(--el-text-color-secondary)">命中置信度低于该值的规则只记录证据，不产生告警</span></el-form-item>
        <el-form-item label="忽略网段"><el-input v-model="cidrs" type="textarea" :rows="3" placeholder="每行一个网段，例如：127.0.0.0/8；回环、链路本地与组播地址始终忽略" /></el-form-item>
        <el-form-item label="敏感关键词"><el-input v-model="keywords" type="textarea" :rows="3" placeholder="每行一个关键词，例如：内部机密" /></el-form-item>
        <el-form-item label="文件 SHA256"><el-input v-model="hashes" type="textarea" :rows="3" placeholder="每行一个受保护文件的 SHA256，完整文件传输时精确匹配" /></el-form-item>
        <el-form-item><el-button type="primary" @click="save">保存策略</el-button></el-form-item>
      </el-form>
    </el-collapse-item></el-collapse>
    <div style="margin:16px 0"><b>传输对象与匹配结果</b><el-button style="float:right" @click="load">刷新</el-button></div>
    <el-table :data="items" size="small" @row-click="openTransfer">
      <el-table-column prop="pcap_id" label="PCAP" width="70" />
      <el-table-column prop="filename" label="对象 / 文件" min-width="170" show-overflow-tooltip />
      <el-table-column label="传输方向" min-width="230"><template #default="{row}">{{row.src_ip}}:{{row.src_port}} → {{row.dst_ip}}:{{row.dst_port}}</template></el-table-column>
      <el-table-column prop="sha256" label="SHA256（捕获内容）" min-width="200" show-overflow-tooltip />
      <el-table-column prop="size" label="字节数" width="90" />
      <el-table-column label="完整性" width="100"><template #default="{row}">{{row.complete ? '完整' : '部分 / 未确认'}}</template></el-table-column>
      <el-table-column label="命中"><template #default="{row}"><el-tag v-for="(hit,index) in row.matches" :key="index" :type="alertableHit(hit) ? 'danger' : 'info'" size="small">{{hit.kind}} × {{hit.count}}{{alertableHit(hit) ? '' : '（仅证据）'}}</el-tag><span v-if="!row.matches.length">未命中当前策略</span></template></el-table-column>
    </el-table>
    <el-empty v-if="!items.length" description="上传并分析 PCAP 后显示传输内容；也可导入演示场景" />
    <el-collapse style="margin-top:16px"><el-collapse-item title="检测覆盖范围与截断信息"><JsonViewer :value="coverage" /></el-collapse-item></el-collapse>
    <el-drawer v-model="drawer" title="传输文件证据" size="70%">
      <template v-if="selected">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="SHA256"><span style="overflow-wrap:anywhere">{{selected.sha256}}</span></el-descriptions-item>
          <el-descriptions-item label="哈希范围">{{selected.complete ? '完整重组文件' : '已捕获片段，不能作为完整文件哈希'}}</el-descriptions-item>
        </el-descriptions>
        <div v-if="selected.binary_available" style="margin:16px 0">
          <el-link :href="downloadUrl(`/dlp/transfers/${selected.task_id}/${selected.id}/content?download=true`)" type="primary">下载捕获二进制（{{selected.size}} 字节）</el-link>
          <p>原始字节预览（最多 4096 字节，未脱敏）</p>
          <el-alert v-if="binaryError" :title="binaryError" type="error" />
          <div v-loading="binaryLoading" style="max-height:360px;overflow:auto"><HexViewer :data="binary" /></div>
        </div>
        <el-alert v-else title="未保留二进制证据；敏感传输的历史 PCAP 需重新分析。" type="info" />
        <JsonViewer :value="selected" />
      </template>
    </el-drawer>
  </div>
</template>
