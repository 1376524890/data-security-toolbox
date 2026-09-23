/**
 * The 态势大屏's own chart palette.
 *
 * The screen is a fixed dark surface even when the console is in light theme,
 * so these colours are literals rather than theme tokens. They are shared by the
 * topology, the donuts and the two trend cards so a severity keeps one colour
 * across the whole wall.
 */
import * as echarts from 'echarts'
import type { FlowDirection } from '../../types/dashboard'

export const screenColors = {
  bg: '#071426',
  bg2: '#0B1930',
  panel: 'rgba(12, 31, 56, 0.86)',
  grid: 'rgba(64, 128, 196, 0.16)',
  axis: '#5b7799',
  text: '#d7e6f7',
  muted: '#8aa6c6',
  dim: '#5b7799',
  blue: '#35a0ff',
  cyan: '#22d3ee',
  yellow: '#f5b638',
  red: '#ff4d5e',
  green: '#2ee6a8',
  purple: '#8b7cff',
}

export const directionLabels: Record<FlowDirection, string> = {
  internal: '内部流量',
  external: '外部流出',
  unknown: '目的未识别',
}

export const directionColors: Record<FlowDirection, string> = {
  internal: screenColors.blue,
  external: screenColors.red,
  unknown: screenColors.yellow,
}

/**
 * Data-classification levels L1..L4 as the wall colours them.
 *
 * The console labels the same four levels through ``severityTagColors`` (L4 red
 * → L1 blue); repeating the hues here keeps the big screen's own dark palette
 * literal like the rest of this module, without the map and the console's tags
 * drifting into two colour languages for one vocabulary.
 *
 * ``unknown`` is the fifth swatch on purpose: a destination nobody classified
 * is not "low sensitivity", so it must not borrow L1's colour.
 */
export const sensitivityColors: Record<string, string> = {
  L4: '#ff4d5e',
  L3: '#f5b638',
  L2: '#22d3ee',
  L1: '#35a0ff',
  unknown: '#5b7799',
}

/** Palette for the asset-type donut; slices past the end cycle the same hues. */
export const donutPalette = [
  screenColors.blue, screenColors.cyan, screenColors.purple, screenColors.yellow,
  screenColors.green, '#4d7cff', '#f472b6', '#38bdf8',
]

/** A line card body shared by the two trend panels. */
export function lineOption(
  x: string[],
  series: Array<{ name: string; data: number[]; color: string; area?: boolean }>,
  options: { legend?: boolean; maxLabel?: number } = {},
): echarts.EChartsOption {
  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(8, 22, 42, 0.94)',
      borderColor: 'rgba(56, 189, 248, 0.32)',
      textStyle: { color: screenColors.text, fontSize: 11 },
    },
    legend: options.legend === false ? undefined : {
      show: true, right: 4, top: 0, icon: 'roundRect', itemWidth: 8, itemHeight: 8,
      textStyle: { color: screenColors.muted, fontSize: 11 },
      data: series.map((item) => item.name),
    },
    grid: { left: 40, right: 12, top: options.legend === false ? 12 : 28, bottom: 22 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: x,
      axisLine: { lineStyle: { color: screenColors.grid } },
      axisTick: { show: false },
      axisLabel: { color: screenColors.dim, fontSize: 10 },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: screenColors.grid } },
      axisLabel: { color: screenColors.dim, fontSize: 10, showMaxLabel: true },
      max: options.maxLabel,
    },
    series: series.map((item) => ({
      name: item.name,
      type: 'line',
      smooth: true,
      showSymbol: false,
      data: item.data,
      itemStyle: { color: item.color },
      lineStyle: { color: item.color, width: 2 },
      areaStyle: item.area === false ? undefined : {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: `${item.color}66` },
          { offset: 1, color: `${item.color}00` },
        ]),
      },
    })),
  }
}

/** Ring body for the two donuts; the legend itself is rendered in the panel. */
export function donutOption(
  slices: Array<{ name: string; value: number; color?: string }>,
): echarts.EChartsOption {
  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(8, 22, 42, 0.94)',
      borderColor: 'rgba(56, 189, 248, 0.32)',
      textStyle: { color: screenColors.text, fontSize: 11 },
      formatter: '{b}: {c} ({d}%)',
    },
    color: donutPalette,
    series: [{
      type: 'pie',
      radius: ['58%', '82%'],
      center: ['38%', '52%'],
      avoidLabelOverlap: true,
      itemStyle: { borderColor: screenColors.bg2, borderWidth: 2 },
      label: { show: false },
      labelLine: { show: false },
      emphasis: { scale: true, scaleSize: 4 },
      data: slices.map((slice, index) => ({
        name: slice.name,
        value: slice.value,
        itemStyle: { color: slice.color || donutPalette[index % donutPalette.length] },
      })),
    }],
  }
}
