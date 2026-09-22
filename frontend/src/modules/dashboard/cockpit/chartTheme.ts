/**
 * The 驾驶舱's chart palette.
 *
 * These are the *console's* colours (light theme tokens), unlike the wall
 * screen's fixed dark literals: the cockpit is a page inside the console shell,
 * so its rings and bars have to follow the theme toggle. The functions below
 * read the current mode through ``themeMode``, which makes any ``computed`` that
 * calls them recompute on a switch — an ECharts option otherwise keeps the
 * literals it was built with.
 */
import type * as echarts from 'echarts'
import type { FlowDirection } from '../../../types/dashboard'
import { chartColors, themeMode } from '../../../utils/theme'

export const cockpitColors = {
  blue: '#2563eb',
  sky: '#0ea5e9',
  cyan: '#06b6d4',
  violet: '#7c3aed',
  green: '#10b981',
  teal: '#14b8a6',
  amber: '#f59e0b',
  orange: '#f97316',
  red: '#ef4444',
  slate: '#94a3b8',
}

/** Slice colours for the two distribution rings, in a fixed order so the same
 *  category keeps one colour across the page. */
export const donutPalette = [
  cockpitColors.blue, cockpitColors.sky, cockpitColors.amber, cockpitColors.violet,
  cockpitColors.green, cockpitColors.cyan, cockpitColors.orange, cockpitColors.slate,
]

export const directionLabels: Record<FlowDirection, string> = {
  internal: '内部流动',
  external: '外部流出',
  unknown: '目的未识别',
}

export const directionColors: Record<FlowDirection, string> = {
  internal: cockpitColors.blue,
  external: cockpitColors.red,
  unknown: cockpitColors.amber,
}

/** A ring with the total in the middle: the cockpit's two distribution cards. */
export function donutOption(
  slices: Array<{ name: string; value: number; itemStyle?: { color?: string } }>,
): echarts.EChartsOption {
  themeMode.value
  const colors = chartColors()
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    color: donutPalette,
    series: [{
      type: 'pie',
      radius: ['62%', '86%'],
      center: ['50%', '50%'],
      avoidLabelOverlap: true,
      itemStyle: { borderColor: 'transparent', borderWidth: 2 },
      label: { show: false },
      labelLine: { show: false },
      emphasis: { scale: true, scaleSize: 4, label: { show: false } },
      data: slices,
      // A ring made of one 100% slice still reads as a ring.
      silent: slices.length === 0,
    }],
    textStyle: { color: colors.muted },
  }
}

/** The flow card's grouped bars: one bar per series per day. */
export function barOption(
  x: string[],
  series: Array<{ name: string; data: number[]; color: string }>,
): echarts.EChartsOption {
  themeMode.value
  const colors = chartColors()
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: {
      data: series.map((item) => item.name),
      top: 0,
      right: 0,
      itemWidth: 8,
      itemHeight: 8,
      textStyle: { color: colors.muted, fontSize: 11 },
    },
    grid: { left: 8, right: 8, top: 30, bottom: 4, containLabel: true },
    xAxis: {
      type: 'category',
      data: x,
      axisTick: { show: false },
      axisLine: { lineStyle: { color: colors.axis } },
      axisLabel: { color: colors.muted, fontSize: 11 },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: colors.grid } },
      axisLabel: { color: colors.muted, fontSize: 11 },
    },
    series: series.map((item) => ({
      name: item.name,
      type: 'bar',
      data: item.data,
      barMaxWidth: 12,
      itemStyle: { color: item.color, borderRadius: [3, 3, 0, 0] },
    })),
  }
}
