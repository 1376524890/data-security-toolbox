<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import StateBox from '../../components/common/StateBox.vue'
import {
  createPolicyGroup, deletePolicyGroup, listPolicyGroups, updatePolicyGroup,
  type PolicyGroup, type PolicyGroupDraft,
} from '../../api/policyGroups'

// A policy group is the selectable unit at task dispatch: which rules apply,
// their scope and thresholds. Rules themselves live in the rule library.
const loading = ref(true)
const error = ref('')
const items = ref<PolicyGroup[]>([])
const dialog = ref(false)
const busy = ref(false)
const editingId = ref<number | null>(null)
const draft = reactive({
  name: '', description: '', enabled: true, scope: ['file', 'network', 'database'] as string[],
  rules: '', categories: '', keywords: '', min_confidence: 0.6, min_matches: 1,
})

function open(row?: PolicyGroup): void {
  editingId.value = row?.id ?? null
  draft.name = row?.name ?? ''
  draft.description = row?.description ?? ''
  draft.enabled = row?.enabled ?? true
  draft.scope = row?.scope?.length ? [...row.scope] : ['file', 'network', 'database']
  draft.rules = (row?.rule_ids ?? []).join('\n')
  draft.categories = (row?.categories ?? []).join('\n')
  draft.keywords = (row?.keywords ?? []).join('\n')
  draft.min_confidence = row?.min_confidence ?? 0.6
  draft.min_matches = row?.min_matches ?? 1
  dialog.value = true
}

function lines(text: string): string[] {
  return text.split(/[\n,]/).map((value) => value.trim()).filter(Boolean)
}

function payload(): PolicyGroupDraft {
  return {
    name: draft.name.trim(), description: draft.description, enabled: draft.enabled,
    scope: draft.scope, rule_ids: lines(draft.rules), categories: lines(draft.categories),
    keywords: lines(draft.keywords), min_confidence: draft.min_confidence,
    min_matches: draft.min_matches,
  }
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = (await listPolicyGroups({ page: 1, page_size: 200 })).items
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

async function save(): Promise<void> {
  if (!draft.name.trim()) { ElMessage.warning('请填写策略组名称'); return }
  busy.value = true
  try {
    if (editingId.value) await updatePolicyGroup(editingId.value, payload())
    else await createPolicyGroup(payload())
    dialog.value = false
    ElMessage.success('已保存')
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  } finally {
    busy.value = false
  }
}

async function remove(row: PolicyGroup): Promise<void> {
  try {
    await deletePolicyGroup(row.id)
    ElMessage.success('已删除')
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar"><strong>策略分组</strong>
      <span class="muted">下发任务时勾选使用哪些策略组进行检查或监测</span>
      <div class="toolbar-spacer" />
      <el-button @click="load">刷新</el-button>
      <el-button type="primary" @click="open()">新建策略组</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <el-table :data="items" size="small" empty-text="尚无策略组">
        <el-table-column prop="name" label="名称" min-width="160" />
        <el-table-column prop="description" label="说明" min-width="200" show-overflow-tooltip />
        <el-table-column label="适用范围" width="180">
          <template #default="{ row }">
            <el-tag v-for="scope in row.scope" :key="scope" size="small" style="margin: 2px">{{ scope }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="规则 / 类别" width="150">
          <template #default="{ row }">{{ row.rule_ids.length }} / {{ row.categories.length }}</template>
        </el-table-column>
        <el-table-column label="阈值" width="150">
          <template #default="{ row }">置信度 ≥ {{ row.min_confidence }} · 命中 ≥ {{ row.min_matches }}</template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }"><el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '停用' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="open(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </StateBox>

    <el-dialog v-model="dialog" :title="editingId ? '编辑策略组' : '新建策略组'" width="640px">
      <el-form label-width="110px">
        <el-form-item label="名称"><el-input v-model="draft.name" maxlength="128" /></el-form-item>
        <el-form-item label="说明"><el-input v-model="draft.description" maxlength="512" /></el-form-item>
        <el-form-item label="适用范围">
          <el-checkbox-group v-model="draft.scope">
            <el-checkbox value="file">文件</el-checkbox>
            <el-checkbox value="network">网络</el-checkbox>
            <el-checkbox value="database">数据库</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="规则 ID"><el-input v-model="draft.rules" type="textarea" :rows="4" placeholder="每行一个规则 ID（来自规则库）" /></el-form-item>
        <el-form-item label="敏感类别"><el-input v-model="draft.categories" type="textarea" :rows="2" placeholder="每行一个类别，例如 ID_CARD" /></el-form-item>
        <el-form-item label="关键词"><el-input v-model="draft.keywords" type="textarea" :rows="2" placeholder="每行一个关键词" /></el-form-item>
        <el-form-item label="最低置信度">
          <el-select v-model="draft.min_confidence" style="width: 220px">
            <el-option v-for="item in [{ l: '宽松 0.50', v: 0.5 }, { l: '默认 0.60', v: 0.6 }, { l: '较严 0.70', v: 0.7 }, { l: '严格 0.80', v: 0.8 }, { l: '最严 0.90', v: 0.9 }]"
                       :key="item.v" :label="item.l" :value="item.v" />
          </el-select>
        </el-form-item>
        <el-form-item label="最少命中">
          <el-select v-model="draft.min_matches" style="width: 220px">
            <el-option v-for="item in [{ l: '1 次', v: 1 }, { l: '2 次', v: 2 }, { l: '3 次', v: 3 }, { l: '5 次', v: 5 }, { l: '10 次', v: 10 }]"
                       :key="item.v" :label="item.l" :value="item.v" />
          </el-select>
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="draft.enabled" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog = false">取消</el-button><el-button type="primary" :loading="busy" @click="save">保存</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; margin-left: 8px; }
</style>
