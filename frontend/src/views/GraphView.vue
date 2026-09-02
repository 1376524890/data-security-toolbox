<script setup lang="ts">
import { ref } from 'vue'
import { apiGet } from '../api/client'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { useEcharts } from '../composables/useEcharts'
import { nodeTypeColors } from '../utils/mapping'

interface GraphNode { id: string; name: string; type: string; risk: string; metadata?: Record<string, unknown> }
interface GraphRelation { source_node: string; source_type: string; target_node: string; target_type: string; relation: string; risk: string }
interface GraphData { nodes: GraphNode[]; relations: GraphRelation[] }

const loading = ref(true)
const error = ref('')
const graphEl = ref<HTMLElement | null>(null)
const chart = useEcharts(graphEl)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const data = await apiGet<GraphData>('/graph')
    const links = data.relations.map((item) => ({ source: item.source_node, target: item.target_node, value: 1 }))
    chart.setOption({
      tooltip: {},
      legend: { data: Object.keys(nodeTypeColors) },
      series: [{
        type: 'graph',
        layout: 'force',
        roam: true,
        draggable: true,
        data: data.nodes.map((node) => ({
          id: node.id,
          name: node.name,
          category: node.type,
          symbolSize: node.risk === 'Critical' ? 48 : node.risk === 'High' ? 40 : 30,
          itemStyle: { color: nodeTypeColors[node.type] || '#64748b', borderColor: node.risk === 'Critical' ? '#b91c1c' : node.risk === 'High' ? '#ea580c' : '#94a3b8', borderWidth: node.risk === 'Critical' ? 4 : 2 },
          value: node.risk,
        })),
        links,
        categories: Object.entries(nodeTypeColors).map(([name]) => ({ name })),
        force: { repulsion: 220, edgeLength: 80 },
        label: { show: true, formatter: '{b}' },
      }],
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

void load()
</script>

<template>
  <div class="page-card">
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <div v-else ref="graphEl" class="graph" />
  </div>
</template>

<style scoped>.graph { height: calc(100vh - 140px); min-height: 600px; }</style>
