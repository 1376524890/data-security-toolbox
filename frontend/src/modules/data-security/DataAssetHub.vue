<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import DataAsset from './DataAsset.vue'
import AssetInventory from './AssetInventory.vue'
import DataTypeCenter from './DataTypeCenter.vue'
import DataSecurityAssessment from './assessments/DataSecurityAssessment.vue'

// One menu entry, four views. The old /data-assets, /asset-inventory and
// /data-types pages and the new 数据安全评估 are tabs here, so nothing is
// reachable from two places and no surface is duplicated.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'assets'))

watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">数据资产</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="数据资产" name="assets">
        <DataAsset v-if="active === 'assets'" />
      </el-tab-pane>
      <el-tab-pane label="资产目录" name="inventory">
        <AssetInventory v-if="active === 'inventory'" />
      </el-tab-pane>
      <el-tab-pane label="数据类型" name="types">
        <DataTypeCenter v-if="active === 'types'" />
      </el-tab-pane>
      <el-tab-pane label="数据安全评估" name="assessment">
        <DataSecurityAssessment v-if="active === 'assessment'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
