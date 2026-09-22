<script setup lang="ts">
/**
 * 资产分布: one ring with a tab strip over the three inventories the server
 * groups by (资产类型 / 数据资产分类 / 网络资产类型).
 *
 * The tab is view state, not a second query: all three groups arrive in the one
 * overview response, so switching tabs never re-fetches or re-numbers.
 */
import { computed, ref, watch } from 'vue'
import CockpitCard from './CockpitCard.vue'
import DistributionDonut from './DistributionDonut.vue'
import type { DistributionTab } from '../composables/useDashboardCockpit'

const props = defineProps<{ tabs: DistributionTab[] }>()
const active = ref(props.tabs[0]?.key || '')
watch(() => props.tabs, (tabs) => {
  if (!tabs.some((tab) => tab.key === active.value)) active.value = tabs[0]?.key || ''
})

const current = computed(() => props.tabs.find((tab) => tab.key === active.value) || props.tabs[0])
</script>

<template>
  <CockpitCard title="资产分布">
    <template #actions>
      <div class="ad-tabs">
        <button v-for="tab in tabs" :key="tab.key" type="button" class="ad-tab"
                :class="{ active: tab.key === active }" @click="active = tab.key">
          {{ tab.label }}
        </button>
      </div>
    </template>
    <DistributionDonut v-if="current" :slices="current.slices" :total="current.total"
                       :total-label="current.totalLabel" />
  </CockpitCard>
</template>

<style scoped>
.ad-tabs { display: inline-flex; gap: 4px; }
.ad-tab {
  border: 1px solid var(--soc-border); background: var(--soc-panel); cursor: pointer;
  font-size: 12px; color: var(--soc-text-muted); padding: 3px 10px; border-radius: 6px;
  font-family: inherit;
}
.ad-tab:hover { color: var(--soc-primary); border-color: var(--soc-primary); }
.ad-tab.active {
  color: #fff; border-color: var(--soc-primary); background: var(--soc-primary);
}
</style>
