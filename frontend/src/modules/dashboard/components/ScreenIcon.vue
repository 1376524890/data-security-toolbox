<script setup lang="ts">
/**
 * Inline SVG icons for the big screen.
 *
 * The screen ships its own paths instead of Element Plus' icon set: the wall is
 * rendered on machines where the console bundle's icon components may not be
 * registered, and an inline path cannot fail to resolve.
 */
const props = withDefaults(defineProps<{ name: string; size?: number }>(), { size: 20 })

const paths: Record<string, string> = {
  alert: 'M12 3a5 5 0 0 0-5 5v3.6L5.5 14.4a1 1 0 0 0 .9 1.5h11.2a1 1 0 0 0 .9-1.5L17 11.6V8a5 5 0 0 0-5-5zm0 17a2.6 2.6 0 0 0 2.5-2h-5A2.6 2.6 0 0 0 12 20z',
  event: 'M12 2 4 5.5v6c0 4.6 3.3 8.6 8 10.5 4.7-1.9 8-5.9 8-10.5v-6L12 2zm0 6v4.2l3 1.8-.9 1.5-3.6-2.1V8h1.5z',
  finding: 'M10.5 3a7.5 7.5 0 1 0 4.6 13.4l4.2 4.2 1.4-1.4-4.2-4.2A7.5 7.5 0 0 0 10.5 3zm0 2a5.5 5.5 0 1 1 0 11 5.5 5.5 0 0 1 0-11z',
  asset: 'M4 4h16v5H4V4zm0 7h16v5H4v-5zm0 7h16v2H4v-2zM6 6v1h6V6H6zm0 7v1h6v-1H6z',
  sensitive: 'M12 2 3 6v6c0 5 3.9 9.3 9 10 5.1-.7 9-5 9-10V6l-9-4zm0 5.5a2.5 2.5 0 0 1 2.5 2.5c0 .9-.5 1.7-1.3 2.1V15h-2.4v-2.9A2.5 2.5 0 0 1 12 7.5z',
  probe: 'M12 3a9 9 0 0 0-9 9h2a7 7 0 0 1 14 0h2a9 9 0 0 0-9-9zm0 4a5 5 0 0 0-5 5h2a3 3 0 0 1 6 0h2a5 5 0 0 0-5-5zm0 4.5a1.5 1.5 0 0 0-1.5 1.5c0 .6.3 1 .8 1.3V17h1.4v-3.2c.5-.3.8-.7.8-1.3A1.5 1.5 0 0 0 12 11.5z',
  engine: 'M9 3h6v2h3v3h2v8h-2v3H6v-3H4V8h2V5h3V3zm2 5v8h2V8h-2z',
  flow: 'M5 5h6l3 3h5v2h-5.8l-3-3H5V5zm0 6h6l3 3h5v2h-5.8l-3-3H5v-2zm0 6h6l3 3h5v2h-5.8l-3-3H5v-2z',
  fullscreen: 'M4 4h6v2H6v4H4V4zm10 0h6v6h-2V6h-4V4zM4 14h2v4h4v2H4v-6zm14 0h2v6h-6v-2h4v-4z',
  console: 'M4 4h16v12H4V4zm0 14h16v2H4v-2zm3-11 3.5 3L7 13l1 1.2 4.7-4.2L8 6 7 7z',
}
</script>

<template>
  <svg class="screen-icon" :width="props.size" :height="props.size" viewBox="0 0 24 24"
       fill="currentColor" aria-hidden="true">
    <path :d="paths[props.name] || paths.asset" />
  </svg>
</template>

<style scoped>
.screen-icon { display: block; flex-shrink: 0; }
</style>
