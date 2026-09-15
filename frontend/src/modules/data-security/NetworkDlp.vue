<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost } from '../../api/client'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
type Policy = { enabled: boolean; categories: string[]; keywords: string[]; fingerprints: string[]; min_matches: number }
type Transfer = { id: number; pcap_id: number; filename: string; src_ip: string; src_port: number; dst_ip: string; dst_port: number; size: number; sha256: string; complete: boolean; content_type: string; matches: {kind: string; count: number; samples: string[]}[] }
const config = reactive<Policy>({enabled:true, categories:[], keywords:[], fingerprints:[], min_matches:1})
const keywords = ref(''), hashes = ref(''), error = ref(''), busy = ref(false)
const items = ref<Transfer[]>([]), coverage = ref<unknown[]>([])
const selected = ref<Transfer | null>(null)
const drawer = ref(false)
async function load() {
  busy.value = true
  try {
    const [policy, data] = await Promise.all([apiGet<Policy>('/dlp/policy'), apiGet<{items:Transfer[]; coverage:unknown[]}>('/dlp/transfers')])
    Object.assign(config, policy); keywords.value = policy.keywords.join('\n'); hashes.value = policy.fingerprints.join('\n'); items.value = data.items; coverage.value = data.coverage; error.value = ''
  } catch(e) { error.value = String(e) }
  finally { busy.value = false }
}
async function save() {
  busy.value = true
  try { await apiPost('/dlp/policy', {...config, keywords:keywords.value.split('\n').filter(v=>v.trim()), fingerprints:hashes.value.split('\n').map(v=>v.trim()).filter(Boolean)}); ElMessage.success('策略已保存，对新分析任务生效；历史 PCAP 可重新分析') }
  catch(e) { ElMessage.error(String(e)) }
  finally { busy.value = false }
}
onMounted(load)
</script>
<template>
  <div v-loading="busy">
    <el-alert title="旁路防泄密检测：重组明文 TCP，识别 HTTP 上传 / 下载、表单、文件指纹及敏感内容。生成告警，不直接阻断；不解密 HTTPS。" type="info" :closable="false" style="margin-bottom:16px" />
    <el-alert v-if="error" :title="error" type="error" />
    <el-collapse><el-collapse-item title="检测策略" name="policy">
      <el-form label-width="120px">
        <el-form-item label="开启检测"><el-switch v-model="config.enabled" /></el-form-item>
        <el-form-item label="敏感类别"><el-checkbox-group v-model="config.categories"><el-checkbox v-for="item in [['phone','手机号'],['id_card','身份证'],['email','邮箱'],['bank_card','银行卡'],['api_key','API 密钥'],['token','长 Token']]" :key="item[0]" :value="item[0]">{{item[1]}}</el-checkbox></el-checkbox-group></el-form-item>
        <el-form-item label="最少命中次数"><el-input-number v-model="config.min_matches" :min="1" :max="1000" /></el-form-item>
        <el-form-item label="敏感关键词"><el-input v-model="keywords" type="textarea" :rows="3" placeholder="每行一个关键词，例如：内部机密" /></el-form-item>
        <el-form-item label="文件 SHA256"><el-input v-model="hashes" type="textarea" :rows="3" placeholder="每行一个受保护文件的 SHA256，完整文件传输时精确匹配" /></el-form-item>
        <el-form-item><el-button type="primary" @click="save">保存策略</el-button></el-form-item>
      </el-form>
    </el-collapse-item></el-collapse>
    <div style="margin:16px 0"><b>传输对象与匹配结果</b><el-button style="float:right" @click="load">刷新</el-button></div>
    <el-table :data="items" size="small" @row-click="(row:Transfer)=>{ selected=row; drawer=true }">
      <el-table-column prop="pcap_id" label="PCAP" width="70" />
      <el-table-column prop="filename" label="对象 / 文件" min-width="170" show-overflow-tooltip />
      <el-table-column label="传输方向" min-width="230"><template #default="{row}">{{row.src_ip}}:{{row.src_port}} → {{row.dst_ip}}:{{row.dst_port}}</template></el-table-column>
      <el-table-column prop="size" label="字节数" width="90" />
      <el-table-column label="完整性" width="100"><template #default="{row}">{{row.complete ? '完整' : '部分 / 未确认'}}</template></el-table-column>
      <el-table-column label="命中"><template #default="{row}"><el-tag v-for="(hit,index) in row.matches" :key="index" type="danger" size="small">{{hit.kind}} × {{hit.count}}</el-tag><span v-if="!row.matches.length">未命中当前策略</span></template></el-table-column>
    </el-table>
    <el-empty v-if="!items.length" description="上传并分析 PCAP 后显示传输内容；也可导入演示场景" />
    <el-collapse style="margin-top:16px"><el-collapse-item title="检测覆盖范围与截断信息"><JsonViewer :value="coverage" /></el-collapse-item></el-collapse>
    <el-drawer v-model="drawer" title="传输证据（敏感样本已脱敏）" size="55%"><JsonViewer v-if="selected" :value="selected" /></el-drawer>
  </div>
</template>
