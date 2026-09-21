<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import SourceManagement from './SourceManagement.vue'
import ScanProfiles from './ScanProfiles.vue'
import DataAssetJobs from './DataAssetJobs.vue'
import RuleVersions from './RuleVersions.vue'
import PolicyGroups from './PolicyGroups.vue'
import RulesCenter from '../threat/RulesCenter.vue'

// 采集与规则 owns every management surface that is not task dispatch: where the
// platform collects from, how a scan is configured, the collection jobs already
// run, and all rule management (versions, the dispatch-time policy groups, the
// detection-rule library). Task dispatch itself lives in 任务中心.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'sources'))

watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">采集与规则</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="来源管理" name="sources">
        <SourceManagement v-if="active === 'sources'" />
      </el-tab-pane>
      <el-tab-pane label="扫描配置" name="profiles">
        <ScanProfiles v-if="active === 'profiles'" />
      </el-tab-pane>
      <el-tab-pane label="采集任务" name="jobs">
        <DataAssetJobs v-if="active === 'jobs'" />
      </el-tab-pane>
      <el-tab-pane label="规则版本" name="versions">
        <RuleVersions v-if="active === 'versions'" />
      </el-tab-pane>
      <el-tab-pane label="策略分组" name="groups">
        <PolicyGroups v-if="active === 'groups'" />
      </el-tab-pane>
      <el-tab-pane label="检测规则库" name="library">
        <RulesCenter v-if="active === 'library'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
