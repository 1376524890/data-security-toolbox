<script setup lang="ts">
import { ref } from 'vue'
import AssessmentPanel from './components/AssessmentPanel.vue'
import type { AssessmentKind } from '../../../api/assessments'

// 数据安全评估 is a tab inside 数据资产, not a page of its own. Each sub-tab renders
// the shared five-段式 skeleton; 数据流动/数据出境 live only in 数据流动与防护 so
// nothing is shown twice.
const ASSESSMENT_TABS: { key: AssessmentKind; label: string }[] = [
  { key: 'overview', label: '评估总览' },
  { key: 'classification', label: '分级评估' },
  { key: 'exposure', label: '脆弱性检测' },
  { key: 'compliance', label: '合规基线' },
]
const active = ref<AssessmentKind>('overview')
</script>

<template>
  <el-tabs v-model="active">
    <el-tab-pane v-for="tab in ASSESSMENT_TABS" :key="tab.key" :label="tab.label" :name="tab.key" />
  </el-tabs>
  <AssessmentPanel :key="active" :kind="active" />
</template>
