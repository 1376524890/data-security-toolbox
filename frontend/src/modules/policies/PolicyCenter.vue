<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PolicyGroups from './PolicyGroups.vue'
import RuleVersions from '../data-security/RuleVersions.vue'
import RulesCenter from '../threat/RulesCenter.vue'

// 策略中心 owns every rule surface: the detection-rule corpus, the policy groups
// an operator selects at dispatch, and the versioned rule sets handed to probes.
// The sensitive-data regex rules stay editable where they always were (the
// network DLP rule catalogue reuses the same library), so nothing is duplicated.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'groups'))

watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">策略中心</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="策略分组" name="groups">
        <PolicyGroups v-if="active === 'groups'" />
      </el-tab-pane>
      <el-tab-pane label="检测规则库" name="library">
        <RulesCenter v-if="active === 'library'" />
      </el-tab-pane>
      <el-tab-pane label="规则版本" name="versions">
        <RuleVersions v-if="active === 'versions'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
