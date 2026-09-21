<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import NetworkDlp from '../NetworkDlp.vue'
import AssessmentPanel from '../assessments/components/AssessmentPanel.vue'
import EgressPolicyForm from './EgressPolicyForm.vue'

// 数据流动与防护 keeps only results and the egress verdict. Rule/threshold
// controls live in 策略中心, task controls in 任务中心. 数据出境 appears here and
// nowhere else.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'transfers'))

watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">数据流动与防护</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="传输结果" name="transfers">
        <NetworkDlp v-if="active === 'transfers'" />
      </el-tab-pane>
      <el-tab-pane label="数据流动" name="flow">
        <AssessmentPanel v-if="active === 'flow'" kind="flow" />
      </el-tab-pane>
      <el-tab-pane label="数据出境" name="egress">
        <template v-if="active === 'egress'">
          <EgressPolicyForm />
          <AssessmentPanel kind="egress" />
        </template>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
