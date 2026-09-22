<script setup lang="ts">
/** 资产类型分布, straight from ``Asset.asset_type`` (unknown slugs stay raw). */
import { computed } from 'vue'
import DonutPanel from './DonutPanel.vue'
import type { RiskDistribution } from '../../../types/dashboard'

const props = defineProps<{ risk: RiskDistribution | null; slices: Array<{ name: string; value: number; color?: string }> }>()

const total = computed(() => props.slices.reduce((sum, item) => sum + Number(item.value || 0), 0))
</script>

<template>
  <DonutPanel title="资产类型分布" :slices="slices" :total="total"
              :empty-text="risk ? '暂无纳管资产' : '资产数据加载中…'" />
</template>
