<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import OpsTaskCenter from '../operations-admin/TaskCenter.vue'
import DataAssetJobs from '../data-security/DataAssetJobs.vue'
import SourceManagement from '../data-security/SourceManagement.vue'
import ScanProfiles from '../data-security/ScanProfiles.vue'

// 任务中心 owns everything an operator needs to dispatch and watch work: the
// task queue, the collection jobs, the sources a task can target, and the scan
// configuration a task runs with. Rules live in 策略中心, results in 数据流动与防护.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'tasks'))

watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">任务中心</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="任务队列" name="tasks">
        <OpsTaskCenter v-if="active === 'tasks'" />
      </el-tab-pane>
      <el-tab-pane label="采集任务" name="jobs">
        <DataAssetJobs v-if="active === 'jobs'" />
      </el-tab-pane>
      <el-tab-pane label="采集来源" name="sources">
        <SourceManagement v-if="active === 'sources'" />
      </el-tab-pane>
      <el-tab-pane label="扫描配置" name="profiles">
        <ScanProfiles v-if="active === 'profiles'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
