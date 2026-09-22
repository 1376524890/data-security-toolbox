/**
 * Fit a fixed 1920×1080 design frame into whatever viewport the wall has.
 *
 * The frame keeps its layout size so every panel is laid out once at the design
 * resolution and merely scaled — a screen built from percentage grids reflows
 * differently on a projector, a laptop and the wall itself, which is exactly
 * what a shared screenshot cannot afford.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

export function useScreenScale(width = 1920, height = 1080) {
  const scale = ref(1)

  function apply(): void {
    if (typeof window === 'undefined') return
    const available = { w: window.innerWidth || width, h: window.innerHeight || height }
    scale.value = Math.min(available.w / width, available.h / height)
  }

  onMounted(() => {
    apply()
    window.addEventListener('resize', apply)
  })
  onBeforeUnmount(() => window.removeEventListener('resize', apply))

  const frameStyle = computed(() => ({
    width: `${width}px`,
    height: `${height}px`,
    transform: `scale(${scale.value})`,
  }))

  return { scale, frameStyle, apply }
}
