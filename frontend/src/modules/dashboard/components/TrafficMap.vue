<script setup lang="ts">
/**
 * 数据流动态势 — the screen's core.
 *
 * It is a topology, not an attack map: the centre is the busiest internal node
 * (the enterprise core), internal peers sit on the inner ring, outside
 * endpoints on the outer one, and every line is a real session pair from the
 * flow table. A line is red only when the classifier proved the destination is
 * outside the enterprise; "undecidable" destinations stay yellow rather than
 * being dressed up as egress.
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { directionColors, directionLabels, screenColors } from '../chartTheme'
import { formatBytes } from '../../../utils/format'
import type { FlowDirection, FlowLink, FlowNode, TrafficFlow } from '../../../types/dashboard'

const props = defineProps<{ traffic: TrafficFlow | null }>()
const emit = defineEmits<{ select: [node: FlowNode] }>()

const container = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null
let observer: ResizeObserver | null = null
let frame = 0

interface Placed {
  node: FlowNode
  point: [number, number]
}

const totals = computed(() => props.traffic?.totals || null)

function place(nodes: FlowNode[]): Placed[] {
  if (!nodes.length) return []
  const ordered = [...nodes].sort((a, b) => b.bytes - a.bytes)
  const core = ordered.find((item) => item.kind !== 'external') || ordered[0]
  const placed: Placed[] = [{ node: core, point: [50, 50] }]
  const rest = ordered.filter((item) => item.id !== core.id)
  const rings: Array<{ items: FlowNode[]; rx: number; ry: number; offset: number }> = [
    { items: rest.filter((item) => item.kind !== 'external'), rx: 26, ry: 30, offset: -Math.PI / 2 },
    { items: rest.filter((item) => item.kind === 'external'), rx: 41, ry: 37, offset: -Math.PI / 2 + 0.5 },
  ]
  for (const ring of rings) {
    ring.items.forEach((item, index) => {
      const angle = ring.offset + (index * 2 * Math.PI) / Math.max(1, ring.items.length)
      placed.push({
        node: item,
        point: [
          Math.min(94, Math.max(6, 50 + ring.rx * Math.cos(angle))),
          Math.min(92, Math.max(8, 50 + ring.ry * Math.sin(angle))),
        ],
      })
    })
  }
  return placed
}

const nodeColor: Record<string, string> = {
  asset: screenColors.cyan,
  host: screenColors.blue,
  external: screenColors.red,
}

function buildOption(): echarts.EChartsOption {
  const traffic = props.traffic
  const nodes = traffic?.nodes || []
  const links = traffic?.links || []
  const placed = place(nodes)
  const positions = new Map(placed.map((item) => [item.node.id, item.point]))
  const maxBytes = Math.max(1, ...nodes.map((item) => item.bytes))
  const maxLinkBytes = Math.max(1, ...links.map((item) => item.bytes))

  const lineSeries = (direction: FlowDirection) => {
    const rows = links.filter((item) => item.direction === direction)
    return {
      name: directionLabels[direction],
      type: 'lines' as const,
      coordinateSystem: 'cartesian2d' as const,
      polyline: false,
      zlevel: 1,
      effect: {
        show: true,
        period: 5,
        trailLength: 0.32,
        symbol: 'circle',
        symbolSize: 2.6,
        color: directionColors[direction],
      },
      lineStyle: { color: directionColors[direction], opacity: 0.55, curveness: 0.12, width: 1 },
      data: rows
        .map((item) => {
          const from = positions.get(item.source)
          const to = positions.get(item.target)
          if (!from || !to || item.source === item.target) return null
          return {
            coords: [from, to],
            value: item.bytes,
            lineStyle: {
              width: 1 + 2.4 * (Math.log(1 + item.bytes) / Math.log(1 + maxLinkBytes)),
            },
            link: item,
          }
        })
        .filter((item): item is NonNullable<typeof item> => item !== null),
    }
  }

  return {
    animationDuration: 600,
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(8, 22, 42, 0.95)',
      borderColor: 'rgba(56, 189, 248, 0.32)',
      textStyle: { color: screenColors.text, fontSize: 11 },
      formatter: (params: unknown) => {
        const data = (params as { data?: { node?: FlowNode; link?: FlowLink } }).data || {}
        if (data.node) {
          const node = data.node
          return [
            `<b>${node.name}</b> ${node.ip}`,
            `方向判定：${node.kind === 'external' ? '外部端点' : '企业内网'}`,
            `会话 ${node.sessions} · 流量 ${formatBytes(node.bytes)}`,
            `敏感数据 ${node.sensitive_categories.length} 类 · 数据资产 ${node.data_assets}`,
            `风险事件 ${node.incidents} · 检测发现 ${node.findings}（高危 ${node.high_risk_findings}）`,
            '<span style="color:#6f90b3">点击查看节点详情</span>',
          ].join('<br/>')
        }
        if (data.link) {
          const link = data.link
          return [
            `<b>${link.src_ip}</b> → <b>${link.dst_ip}</b>`,
            `方向：${directionLabels[link.direction]}`,
            `会话 ${link.sessions} · 流量 ${formatBytes(link.bytes)}`,
          ].join('<br/>')
        }
        return ''
      },
    },
    grid: { left: 4, right: 4, top: 4, bottom: 4 },
    xAxis: { type: 'value', min: 0, max: 100, show: false },
    yAxis: { type: 'value', min: 0, max: 100, show: false },
    series: [
      lineSeries('internal'),
      lineSeries('unknown'),
      lineSeries('external'),
      {
        name: 'nodes',
        type: 'effectScatter',
        coordinateSystem: 'cartesian2d',
        zlevel: 2,
        rippleEffect: { brushType: 'stroke', scale: 3, period: 4 },
        symbolSize: 30,
        itemStyle: { color: screenColors.cyan, shadowBlur: 18, shadowColor: screenColors.cyan },
        label: { show: false },
        data: placed
          .filter((item) => item.node.kind !== 'external')
          .slice(0, 1)
          .map((item) => ({ value: item.point, node: item.node })),
      },
      {
        name: '流量节点',
        type: 'scatter',
        coordinateSystem: 'cartesian2d',
        zlevel: 3,
        symbol: 'circle',
        data: placed.map((item) => ({
          value: item.point,
          node: item.node,
          symbolSize: 12 + 16 * (Math.log(1 + item.node.bytes) / Math.log(1 + maxBytes)),
        })),
        itemStyle: {
          color: (params: unknown) => {
            const node = (params as { data?: { node?: FlowNode } })?.data?.node
            return nodeColor[node?.kind || 'host'] || screenColors.blue
          },
          borderColor: 'rgba(234, 244, 255, 0.75)',
          borderWidth: 1,
          shadowBlur: 14,
          shadowColor: 'rgba(53, 160, 255, 0.55)',
        },
        label: {
          show: true,
          position: 'bottom',
          distance: 5,
          color: '#c7dcf2',
          fontSize: 10,
          formatter: (params: unknown) =>
            (params as { data?: { node?: FlowNode } })?.data?.node?.name || '',
        },
        emphasis: { scale: 1.25 },
      },
    ],
  }
}

function render(): void {
  if (!container.value) return
  if (!chart) {
    chart = echarts.init(container.value)
    chart.on('click', (params: unknown) => {
      const node = (params as { data?: { node?: FlowNode } })?.data?.node
      if (node) emit('select', node)
    })
  }
  chart.setOption(buildOption(), true)
  chart.resize()
}

const isReady = computed(() => Boolean(props.traffic && props.traffic.nodes.length))
const isEmpty = computed(() => Boolean(props.traffic && props.traffic.nodes.length === 0))

function onResize(): void {
  if (frame) cancelAnimationFrame(frame)
  frame = requestAnimationFrame(() => chart?.resize())
}

watch(() => props.traffic, render, { deep: false })

/**
 * The card has no traffic to draw at mount, so it starts hidden and echarts
 * initialises against a 0x0 element — falling back to a 100x100 canvas. Nothing
 * tells the chart that its box appeared, and a chart left at 100x100 draws the
 * whole topology into one corner. Observing the box is what actually catches
 * that first reveal (and any later re-layout of the wall).
 */
function observeBox(): void {
  if (typeof ResizeObserver === 'undefined' || !container.value) return
  observer = new ResizeObserver(() => chart?.resize())
  observer.observe(container.value)
}

onMounted(() => {
  render()
  window.addEventListener('resize', onResize)
  observeBox()
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  observer?.disconnect()
  observer = null
  if (frame) cancelAnimationFrame(frame)
  chart?.dispose()
  chart = null
})
</script>

<template>
  <section class="ds-panel ds-map">
    <div class="ds-panel-head">
      <span class="ds-panel-title">数据流动势态</span>
      <div class="ds-legend">
        <span v-for="(label, key) in directionLabels" :key="key" class="ds-legend-item">
          <i :style="{ background: directionColors[key as FlowDirection] }" />{{ label }}
          <b>{{ totals ? totals[key as FlowDirection] : 0 }}</b>
        </span>
      </div>
    </div>
    <div class="ds-panel-body">
      <div v-show="isReady" ref="container" class="ds-map-canvas" />
      <div v-if="!isReady" class="ds-empty">
        <div v-if="isEmpty">暂无流量数据<span>分析完成的 PCAP 会话会汇聚到这里</span></div>
        <div v-else>流量数据加载中…</div>
      </div>
      <div v-if="totals && isReady" class="ds-map-totals">
        <span>会话总数 <b>{{ totals.sessions }}</b></span>
        <span>总流量 <b>{{ formatBytes(totals.bytes) }}</b></span>
        <span>数据包 <b>{{ totals.packets }}</b></span>
      </div>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.2); background: rgba(9, 26, 48, 0.86);
  position: relative; overflow: hidden;
}
.ds-panel::after {
  content: ''; position: absolute; inset: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(53, 160, 255, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(53, 160, 255, 0.05) 1px, transparent 1px);
  background-size: 40px 40px;
  mask-image: radial-gradient(circle at 50% 52%, #000 30%, transparent 78%);
}
.ds-panel-head { display: flex; align-items: center; justify-content: space-between; z-index: 1; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-legend { display: flex; gap: 14px; font-size: 11px; color: #9ec2e6; }
.ds-legend-item { display: inline-flex; align-items: center; gap: 5px; }
.ds-legend-item i { width: 14px; height: 2px; border-radius: 2px; }
.ds-legend-item b { color: #eaf4ff; font-variant-numeric: tabular-nums; }
.ds-panel-body { flex: 1; min-height: 0; position: relative; z-index: 1; }
.ds-map-canvas { width: 100%; height: 100%; }
.ds-map-totals {
  position: absolute; left: 8px; bottom: 4px; display: flex; gap: 16px;
  font-size: 11px; color: #7f9bc0; pointer-events: none;
}
.ds-map-totals b { color: #dbeaf9; font-variant-numeric: tabular-nums; }
.ds-empty {
  height: 100%; display: grid; place-items: center; text-align: center;
  font-size: 13px; color: #6f90b3;
}
.ds-empty span { display: block; margin-top: 6px; font-size: 11px; color: #4f6b8a; }
</style>
