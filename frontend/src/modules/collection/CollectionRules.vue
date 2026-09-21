<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import RuleLibrary from './RuleLibrary.vue'
import RuleVersions from './RuleVersions.vue'
import PolicyGroups from './PolicyGroups.vue'
import EgressPolicyForm from './EgressPolicyForm.vue'

// 采集与规则 owns every rule configuration and nothing else: the rule set (the
// regexes for sensitive-data discovery and traffic monitoring), the versioned
// rule packages handed to probes, the dispatch-time policy groups, and the
// egress allow/deny lists. Task dispatch lives in 任务中心; results live in
// 数据流动与防护 / 文件证据.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'library'))
watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">采集与规则</div>
    <el-tabs :model-value="active"
             @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="规则集与规则" name="library">
        <RuleLibrary v-if="active === 'library'" />
      </el-tab-pane>
      <el-tab-pane label="规则版本" name="versions">
        <RuleVersions v-if="active === 'versions'" />
      </el-tab-pane>
      <el-tab-pane label="策略分组" name="groups">
        <PolicyGroups v-if="active === 'groups'" />
      </el-tab-pane>
      <el-tab-pane label="出境判定名单" name="egress">
        <EgressPolicyForm v-if="active === 'egress'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
