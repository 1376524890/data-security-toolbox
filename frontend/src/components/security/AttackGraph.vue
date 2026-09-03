<script setup lang="ts">
import { computed } from 'vue'
import { VueFlow, type Node, type Edge } from '@vue-flow/core'
import { Background } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import '@vue-flow/controls/dist/style.css'
import '@vue-flow/minimap/dist/style.css'

export interface GraphNode { id: string; name: string; type: string; risk: string }
export interface GraphEdge { source: string; target: string; label?: string }

const props = defineProps<{ nodes: GraphNode[]; edges: GraphEdge[]; height?: number | string }>()
const emit = defineEmits<{ 'node-click': [node: GraphNode] }>()

const typeColors: Record<string, string> = {
  probe: '#0ea5e9', host: '#3b82f6', data_asset: '#f59e0b', ioc: '#ef4444', incident: '#f97316', file: '#8b5cf6', service: '#16a34a',
}
const riskColors: Record<string, string> = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6' }

const flowNodes = computed<Node[]>(() => {
  const layers: Record<string, string[]> = {}
  props.nodes.forEach((n) => { (layers[n.type] = layers[n.type] || []).push(n.id) })
  const positions: Record<string, { x: number; y: number }> = {}
  Object.keys(layers).forEach((type, col) => {
    layers[type].forEach((id, row) => { positions[id] = { x: 60 + col * 220, y: 40 + row * 90 } })
  })
  return props.nodes.map((n) => ({
    id: n.id,
    label: n.name,
    position: positions[n.id] || { x: 0, y: 0 },
    style: {
      background: `${typeColors[n.type] || '#64748b'}1f`,
      border: `1px solid ${riskColors[n.risk] || typeColors[n.type] || '#64748b'}`,
      color: '#e5e7eb', fontSize: '12px', padding: '6px 10px', borderRadius: '6px', width: '160px',
    },
    data: { node: n },
  }))
})

const flowEdges = computed<Edge[]>(() =>
  props.edges.map((e, i) => ({
    id: `e${i}`,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: true,
    style: { stroke: '#38bdf8', strokeWidth: 1.4 },
    labelStyle: { fill: '#9ca3af', fontSize: 10 },
  })),
)

function onNodeClick(event: any): void {
  const node = event?.node?.data?.node
  if (node) emit('node-click', node)
}
</script>

<template>
  <div class="attack-graph" :style="{ height: typeof height === 'number' ? `${height}px` : height || '420px' }">
    <VueFlow :nodes="flowNodes" :edges="flowEdges" :fit-view-on-init="true" :nodes-draggable="true" :min-zoom="0.3" @node-click="onNodeClick">
      <Background :gap="18" :color="'#1f2937'" />
      <Controls />
      <MiniMap pannable zoomable :node-color="'#1f2937'" />
    </VueFlow>
  </div>
</template>

<style scoped>
.attack-graph { border: 1px solid var(--soc-border); border-radius: var(--soc-radius); background: #0e1626; overflow: hidden; }
</style>
