<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import type { MonacoLanguage, MonacoTheme } from './monaco'

const props = withDefaults(defineProps<{
  value: string
  language?: MonacoLanguage
  height?: number
  readOnly?: boolean
  theme?: MonacoTheme
  title?: string
}>(), { language: 'json', height: 360, readOnly: true, theme: 'soc-dark' })

const container = ref<HTMLElement | null>(null)
let editor: any = null
let monacoMod: any = null
let fallback = false

async function loadMonaco(): Promise<void> {
  if (monacoMod || fallback) return
  try {
    monacoMod = await import('./monaco')
  } catch {
    fallback = true
  }
}

async function render(): Promise<void> {
  if (fallback || !container.value) return
  if (!monacoMod) {
    await loadMonaco()
    if (fallback || !monacoMod || !container.value) return
  }
  const monaco = monacoMod.monaco
  try {
    editor = editor || monaco.editor.create(container.value, {
      value: props.value,
      language: props.language,
      theme: props.theme,
      readOnly: props.readOnly,
      minimap: { enabled: false },
      fontSize: 12,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      automaticLayout: true,
      wordWrap: 'on',
      padding: { top: 8, bottom: 8 },
      scrollbar: { verticalScrollbarSize: 8, horizontalScrollbarSize: 8 },
    })
    editor.setValue(props.value)
    monaco.editor.setModelLanguage(editor.getModel(), props.language)
    monaco.editor.setTheme(props.theme)
  } catch {
    fallback = true
  }
}

watch(() => [props.value, props.language, props.theme], () => { render() })
onBeforeUnmount(() => { editor?.dispose() })
</script>

<template>
  <div class="raw-viewer" :style="{ height: `${height}px` }">
    <div v-if="title" class="rv-title">{{ title }}</div>
    <div ref="container" class="rv-container" />
    <pre v-if="fallback" class="rv-fallback">{{ value }}</pre>
  </div>
</template>

<style scoped>
.raw-viewer { border: 1px solid var(--soc-border); border-radius: var(--soc-radius-sm); overflow: hidden; background: #0e1626; display: flex; flex-direction: column; }
.rv-title { padding: 6px 10px; font-size: 11px; color: var(--soc-text-dim); border-bottom: 1px solid var(--soc-border); }
.rv-container { flex: 1; }
.rv-fallback { margin: 0; padding: 10px; font-family: var(--soc-font-mono); font-size: 12px; color: var(--soc-text); white-space: pre-wrap; word-break: break-all; }
</style>
