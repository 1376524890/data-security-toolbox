<script setup lang="ts">
/**
 * A number that rolls to its new value.
 *
 * The animation is skipped when the platform asks for reduced motion (and when
 * ``duration`` is 0, which the tests use), because a wall of digits rolling on
 * every refresh is the kind of motion that makes a big screen tiring.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'

const props = withDefaults(defineProps<{
  value: number
  duration?: number
  decimals?: number
  separator?: boolean
}>(), { duration: 900, decimals: 0, separator: true })

const shown = ref(Number(props.value) || 0)
let frame = 0

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function animate(to: number): void {
  if (frame) cancelAnimationFrame(frame)
  const from = shown.value
  if (to === from) return
  if (props.duration <= 0 || prefersReducedMotion()) {
    shown.value = to
    return
  }
  const start = performance.now()
  const step = (timestamp: number) => {
    const progress = Math.min(1, (timestamp - start) / props.duration)
    shown.value = from + (to - from) * (1 - (1 - progress) ** 3)
    if (progress < 1) frame = requestAnimationFrame(step)
    else shown.value = to
  }
  frame = requestAnimationFrame(step)
}

watch(() => Number(props.value) || 0, animate, { immediate: true })
onBeforeUnmount(() => { if (frame) cancelAnimationFrame(frame) })

const text = computed(() => {
  const fixed = shown.value.toFixed(props.decimals)
  if (!props.separator) return fixed
  const [whole, fraction] = fixed.split('.')
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  return fraction ? `${grouped}.${fraction}` : grouped
})
</script>

<template>
  <span class="animated-number">{{ text }}</span>
</template>

<style scoped>
.animated-number { font-variant-numeric: tabular-nums; }
</style>
