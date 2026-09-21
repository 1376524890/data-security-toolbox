<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getEgressPolicy, saveEgressPolicy } from '../../../api/egress'

// The only egress control: manual white/black lists and extra internal ranges.
// The default judgement is the static CIDR→region table; when that table is not
// loaded the verdict degrades to "无法判定", it never becomes "无出境".
const busy = ref(false)
const regionTablePresent = ref(false)
const tablePath = ref('')
const draft = reactive({ whitelist: '', blacklist: '', internal_cidrs: '' })

async function load(): Promise<void> {
  const data = await getEgressPolicy()
  regionTablePresent.value = data.region_table_present
  tablePath.value = data.table_path
  draft.whitelist = data.whitelist.join('\n')
  draft.blacklist = data.blacklist.join('\n')
  draft.internal_cidrs = data.internal_cidrs.join('\n')
}

function lines(text: string): string[] {
  return text.split('\n').map((value) => value.trim()).filter(Boolean)
}

async function save(): Promise<void> {
  busy.value = true
  try {
    await saveEgressPolicy({
      whitelist: lines(draft.whitelist), blacklist: lines(draft.blacklist),
      internal_cidrs: lines(draft.internal_cidrs),
    })
    ElMessage.success('出境策略已保存')
  } catch (err) {
    ElMessage.error(String(err))
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="soc-card">
    <div class="soc-card-title"><span class="dot warn" />出境判定策略</div>
    <el-alert :closable="false" show-icon
              :type="regionTablePresent ? 'success' : 'warning'"
              :title="regionTablePresent
                ? '已加载 CIDR→地区表：白名单优先，其次黑名单，再查地区表。'
                : '未加载 CIDR→地区表：白名单/黑名单与内网仍可判定，其余目的地址一律“无法判定”，不表示无出境。'" />
    <div class="muted">地区表文件：{{ tablePath }}</div>
    <el-form label-width="120px" style="margin-top: 10px">
      <el-form-item label="白名单"><el-input v-model="draft.whitelist" type="textarea" :rows="3" placeholder="每行一个 IP 或 CIDR，命中即放行，不计出境" /></el-form-item>
      <el-form-item label="黑名单"><el-input v-model="draft.blacklist" type="textarea" :rows="3" placeholder="每行一个 IP 或 CIDR，命中即标红" /></el-form-item>
      <el-form-item label="内网段"><el-input v-model="draft.internal_cidrs" type="textarea" :rows="3" placeholder="每行一个 CIDR，命中即视为内网" /></el-form-item>
      <el-form-item><el-button type="primary" :loading="busy" @click="save">保存策略</el-button></el-form-item>
    </el-form>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; margin: 8px 0; }
</style>
