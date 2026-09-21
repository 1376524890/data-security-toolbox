<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import OpsTaskCenter from '../operations-admin/TaskCenter.vue'
import { useTaskDispatch, type TargetKind } from './composables/useTaskDispatch'

// 任务中心 is the single place a scan is dispatched and watched: pick the target
// and how it is reached (probe / no probe), the file scope, which policy groups
// apply, and whether the task is one-shot or scheduled. Rules live in 采集与规则.
const { targetKind, draft, targets, groups, busy, load, submit } = useTaskDispatch()
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'dispatch'))
watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name === 'dispatch' ? undefined : name } })
}

const KINDS: { value: TargetKind; label: string; hint: string }[] = [
  { value: 'probe', label: '探针', hint: '在目标主机上由探针采集' },
  { value: 'file_source', label: '共享文件（无探针）', hint: '平台直连 FTP/FTPS/SFTP 只读采集' },
  { value: 'database', label: '数据库（无探针）', hint: '平台只读直连目标库按列检测' },
]
</script>

<template>
  <div>
    <div class="hub-title">任务中心</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="任务下发" name="dispatch">
        <div class="soc-card">
          <el-form label-width="130px" style="max-width: 760px">
            <el-form-item label="连接方式">
              <el-radio-group v-model="targetKind" @change="load">
                <el-radio-button v-for="kind in KINDS" :key="kind.value" :value="kind.value">{{ kind.label }}</el-radio-button>
              </el-radio-group>
              <div class="hint">{{ KINDS.find((k) => k.value === targetKind)?.hint }}</div>
            </el-form-item>
            <el-form-item :label="targetKind === 'probe' ? '目标探针' : targetKind === 'file_source' ? '共享文件来源' : '数据库连接'">
              <el-select v-if="targetKind === 'probe'" v-model="draft.probeId" filterable placeholder="选择探针" style="width: 420px">
                <el-option v-for="item in targets" :key="item.id" :label="item.label" :value="item.id" />
              </el-select>
              <el-select v-else-if="targetKind === 'file_source'" v-model="draft.sourceId" filterable placeholder="选择来源" style="width: 420px">
                <el-option v-for="item in targets" :key="item.id" :label="item.label" :value="item.id" />
              </el-select>
              <el-select v-else v-model="draft.connectionId" filterable placeholder="选择连接" style="width: 420px">
                <el-option v-for="item in targets" :key="item.id" :label="item.label" :value="item.id" />
              </el-select>
            </el-form-item>
            <template v-if="targetKind === 'probe'">
              <el-form-item label="检测文件范围">
                <el-input v-model="draft.paths" type="textarea" :rows="3" placeholder="每行一个绝对目录，例如 /srv/data" />
              </el-form-item>
              <el-form-item label="排除路径">
                <el-input v-model="draft.excludePaths" type="textarea" :rows="2" placeholder="每行一个目录名或绝对路径，可空" />
              </el-form-item>
              <el-form-item label="文件类型">
                <el-input v-model="draft.fileTypes" placeholder="扩展名白名单，逗号分隔，留空为全部，例如 .csv,.xlsx,.pdf" />
              </el-form-item>
            </template>
            <el-form-item label="检测项（策略组）">
              <el-select v-model="draft.policyGroupIds" multiple filterable placeholder="留空使用默认规则" style="width: 420px">
                <el-option v-for="group in groups" :key="group.id" :label="group.name" :value="group.id" />
              </el-select>
              <div class="hint">策略组在「采集与规则 · 策略分组」里维护</div>
            </el-form-item>
            <el-form-item label="任务属性">
              <el-radio-group v-model="draft.mode">
                <el-radio-button value="once">单次检测</el-radio-button>
                <el-radio-button value="scheduled">定时持续监测</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item v-if="draft.mode === 'scheduled'" label="间隔（秒）">
              <el-input-number v-model="draft.intervalSeconds" :min="60" :max="2592000" :step="600" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="busy" @click="submit">下发任务</el-button>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>
      <el-tab-pane label="进度监控" name="monitor">
        <OpsTaskCenter v-if="active === 'monitor'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
.hint { color: var(--soc-text-dim); font-size: 12px; margin-top: 4px; }
</style>
