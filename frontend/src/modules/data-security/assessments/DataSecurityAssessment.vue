<script setup lang="ts">
import { ref } from 'vue'
import AssessmentPanel from './components/AssessmentPanel.vue'
import { ASSESSMENT_TABS } from './composables/useDataSecurityAssessment'
import type { AssessmentKind } from '../../../api/assessments'

// 数据安全评估 is a tab inside 数据资产, not a page of its own. Each sub-tab renders
// the shared five-段式 skeleton; 数据流动/数据出境 live only in 数据流动与防护 so
// nothing is shown twice.
const active = ref<AssessmentKind>('overview')
</script>

<template>
  <el-tabs v-model="active">
    <el-tab-pane v-for="tab in ASSESSMENT_TABS" :key="tab.key" :label="tab.label" :name="tab.key" />
  </el-tabs>
  <AssessmentPanel :key="active" :kind="active" />
</template>
