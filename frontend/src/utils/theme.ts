/**
 * The console colour mode, readable outside App.vue.
 *
 * The header toggle is the only writer; the chart wrappers are the readers. They
 * need it because an ECharts option bakes its colours in when it is built, so a
 * theme switch has to rebuild the option or the canvas keeps the previous
 * theme's grid and axis colours on a white card.
 */
import { ref } from 'vue'

export type ThemeMode = 'dark' | 'light'

export const themeMode = ref<ThemeMode>(
  typeof document !== 'undefined' && document.documentElement.classList.contains('light')
    ? 'light'
    : 'dark',
)

export function applyTheme(mode: ThemeMode): void {
  document.documentElement.classList.toggle('dark', mode === 'dark')
  document.documentElement.classList.toggle('light', mode === 'light')
  localStorage.setItem('dst-theme', mode)
  themeMode.value = mode
}

/** The chart palette for the current theme, straight from the design tokens. */
export function chartColors(): {
  axis: string; grid: string; text: string; muted: string; primary: string
} {
  const style = typeof window === 'undefined' ? null : getComputedStyle(document.documentElement)
  const read = (name: string, fallback: string): string =>
    style?.getPropertyValue(name).trim() || fallback
  return {
    // Shared with the tables and the borders, so a chart never introduces a
    // second grey for "the same" line.
    axis: read('--soc-border-2', '#cbd5e1'),
    grid: read('--soc-border', '#e8eef7'),
    text: read('--soc-text-strong', '#0f172a'),
    muted: read('--soc-text-muted', '#64748b'),
    primary: read('--soc-primary', '#2563eb'),
  }
}
