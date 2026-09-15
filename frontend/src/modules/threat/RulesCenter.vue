<script setup lang="ts">
import { onMounted, ref, computed, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { apiPost } from '../../api/client'
import { listRules, type RuleItem } from '../../api/rules'
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'

const loading = ref(true)
const error = ref('')
const rules = ref<RuleItem[]>([])
const activeType = ref<'sigma' | 'suricata' | 'yara'>('sigma')
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

const filtered = computed(() => rules.value.filter((r: RuleItem) => r.type === activeType.value))
const types = computed(() => ['sigma', 'suricata', 'yara'].map((t) => ({ label: t, value: t, count: rules.value.filter((r: RuleItem) => r.type === t).length })))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listRules()
    rules.value = result.items
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
      <el-radio-group v-model="activeType">
        <el-radio-button v-for="t in types" :key="t.value" :value="t.value">{{ t.label }} ({{ t.count }})</el-radio-button>
      </el-radio-group>
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
      <div class="grid cols-2">
        <div v-for="(r, idx) in filtered" :key="r.path" class="soc-card rule-card">
          <div class="rule-head">
            <div class="rule-name">{{ r.name }}</div>
            <StatusBadge :value="r.type" />
          </div>
          <div class="rule-meta">
            <span>类型 <span class="mono">{{ r.type }}</span></span>
            <span>大小 <span class="mono">{{ r.size }} B</span></span>
          </div>
          <div class="rule-path mono">{{ r.path }}</div>
          <RawViewer :value="r.content" language="yaml" :height="220" />
        </div>
      </div>
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
