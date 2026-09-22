<script setup lang="ts">
/** 风险等级分布: the same four-level scale the severity tags use. */
import { computed } from 'vue'
import DonutPanel from './DonutPanel.vue'
import type { RiskDistribution } from '../../../types/dashboard'

const props = defineProps<{ risk: RiskDistribution | null; slices: Array<{ name: string; value: number; color?: string }> }>()

const total = computed(() => props.slices.reduce((sum, item) => sum + Number(item.value || 0), 0))
</script>

<template>
  <DonutPanel title="风险等级分布" :slices="slices" :total="total"
              :empty-text="risk ? '暂无检测发现' : '风险数据加载中…'" />
</template>
