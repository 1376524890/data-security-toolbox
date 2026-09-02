<script setup lang="ts">
import { computed } from 'vue'
import { statusColors } from '../utils/mapping'

const props = defineProps<{ stages: string[] }>()
const items = computed(() => {
  const order = ['recon', 'exploit', 'credential', 'c2', 'exfil', 'impact']
  return order.filter((stage) => props.stages.includes(stage)).map((stage) => ({ stage, color: statusColors.ready }))
})
</script>

<template>
  <el-timeline v-if="items.length">
    <el-timeline-item v-for="item in items" :key="item.stage" :color="item.color">{{ item.stage }}</el-timeline-item>
  </el-timeline>
  <el-empty v-else description="无已知攻击阶段" />
</template>
