<script setup lang="ts">
import { onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import { get } from '../api'

const summary = ref<Record<string, number>>({})
const assetRisk = ref<Record<string, number>>({})

onMounted(async () => {
  summary.value = await get('/dashboard/summary')
  const data = await get<{ count: number; risk: Record<string, number> }>('/assets/summary')
  assetRisk.value = data.risk
  const el = document.getElementById('risk-chart')
  if (el) {
    const chart = echarts.init(el)
    chart.setOption({
      title: { text: '资产风险分布' },
      tooltip: {},
      series: [{ type: 'pie', radius: '70%', data: Object.entries(assetRisk.value).map(([name, value]) => ({ name, value })) }],
    })
  }
})
</script>

<template>
  <div>
    <el-row :gutter="16">
      <el-col v-for="(value, key) in summary" :key="key" :span="6" style="margin-bottom: 16px">
        <el-card shadow="hover"><div class="stat-label">{{ key }}</div><div class="stat-value">{{ value }}</div></el-card>
      </el-col>
    </el-row>
    <el-card><div id="risk-chart" style="height: 360px" /></el-card>
  </div>
</template>

<style scoped>
.stat-label { color: #64748b; text-transform: capitalize; }
.stat-value { font-size: 30px; font-weight: 700; color: #0f172a; }
</style>

