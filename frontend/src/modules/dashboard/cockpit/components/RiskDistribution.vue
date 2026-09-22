<script setup lang="ts">
/** 风险等级分布: the finding severities as a ring, with the finding total. */
import CockpitCard from './CockpitCard.vue'
import DistributionDonut from './DistributionDonut.vue'
import type { DonutSlice } from '../composables/useDashboardCockpit'

defineProps<{ slices: DonutSlice[]; total: number }>()
</script>

<template>
  <CockpitCard title="风险等级分布">
    <DistributionDonut :slices="slices" :total="total" total-label="发现项总数" />
  </CockpitCard>
</template>
