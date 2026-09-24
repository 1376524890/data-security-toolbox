import { getCurrentInstance, onBeforeUnmount, onMounted, ref } from 'vue'

/**
 * A single, shared "keep this page current" timer.
 *
 * Every list and dashboard in the console wants the same three guarantees, so
 * they live here instead of in each page's own `setInterval`:
 *
 * - a tick never starts while the previous one is still running, so a slow
 *   endpoint cannot stack requests the moment the server is unwell;
 * - a hidden tab is not polled at all — a wall screen that is minimized is not
 *   being read, and background polling only burns the data partition;
 * - the timer is cleared when the page unmounts, because a timer that outlives
 *   its component writes into disposed refs.
 *
 * The loader is called with `{ silent: true }` so a periodic refresh can keep
 * the previous numbers on screen instead of flashing the page's loading state.
 */
export interface AutoRefreshLoader {
  (options: { silent: boolean }): unknown
}

export interface AutoRefreshOptions {
  /** Milliseconds between ticks. 0 disables the timer entirely. */
  intervalMs?: number
  /** Skip ticks while the tab is hidden (default true). */
  pauseWhenHidden?: boolean
  /** A tick that throws is reported here; the loader's own error handling wins. */
  onError?: (error: unknown) => void
}

/** Ticks fast enough to feel live, slow enough not to be a load source. */
export const DEFAULT_REFRESH_MS = 30000

export function useAutoRefresh(load: AutoRefreshLoader, options: AutoRefreshOptions = {}) {
  const intervalMs = options.intervalMs ?? DEFAULT_REFRESH_MS
  const pauseWhenHidden = options.pauseWhenHidden ?? true
  const running = ref(false)
  const paused = ref(false)
  let timer = 0
  let disposed = false

  async function tick(): Promise<void> {
    if (disposed || running.value || paused.value) return
    if (pauseWhenHidden && typeof document !== 'undefined' && document.hidden) return
    running.value = true
    try {
      await load({ silent: true })
    } catch (err) {
      options.onError?.(err)
    } finally {
      running.value = false
    }
  }

  function start(): void {
    if (disposed || timer || intervalMs <= 0) return
    timer = window.setInterval(() => { void tick() }, intervalMs)
  }

  function stop(): void {
    if (!timer) return
    window.clearInterval(timer)
    timer = 0
  }

  /** A manual "刷新" click: same in-flight guard, but never silently skipped. */
  async function refreshNow(): Promise<void> {
    if (disposed || running.value) return
    running.value = true
    try {
      await load({ silent: true })
    } catch (err) {
      options.onError?.(err)
    } finally {
      running.value = false
    }
  }

  function pause(): void { paused.value = true }
  function resume(): void { paused.value = false }

  // Lifecycle hooks only exist inside a component's setup(). A composable used
  // from a plain function (a unit test, a script) must still construct without
  // Vue warning about a missing instance, so the timer is simply not armed.
  if (getCurrentInstance()) {
    onMounted(start)
    onBeforeUnmount(() => {
      disposed = true
      stop()
    })
  }

  return { intervalMs, running, paused, start, stop, pause, resume, refreshNow }
}
