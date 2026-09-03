<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  data: Uint8Array | string | null
  ascii?: boolean
  offset?: number
}>(), { ascii: true, offset: 0 })

const bytes = computed(() => {
  if (!props.data) return new Uint8Array(0)
  if (typeof props.data === 'string') {
    const clean = props.data.replace(/\s+/g, '')
    if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
      const arr = new Uint8Array(clean.length / 2)
      for (let i = 0; i < arr.length; i++) arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
      return arr
    }
    return new TextEncoder().encode(props.data)
  }
  return props.data
})

const rows = computed(() => {
  const out: Array<{ offset: string; hex: string; ascii: string }> = []
  const data = bytes.value
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.slice(i, i + 16)
    const hex = Array.from(chunk).map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const ascii = Array.from(chunk).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('')
    out.push({ offset: (props.offset + i).toString(16).padStart(8, '0'), hex, ascii })
  }
  return out
})
</script>

<template>
  <div class="hex-viewer">
    <div v-if="!bytes.length" class="hv-empty">无原始数据</div>
    <div v-else class="hv-body">
      <div class="hv-header"><span class="hv-offset">OFFSET</span><span class="hv-hex">00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</span><span v-if="ascii" class="hv-ascii">ASCII</span></div>
      <div v-for="row in rows" :key="row.offset" class="hv-row">
        <span class="hv-offset mono">{{ row.offset }}</span>
        <span class="hv-hex mono">{{ row.hex }}</span>
        <span v-if="ascii" class="hv-ascii mono">{{ row.ascii }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hex-viewer { font-family: var(--soc-font-mono); font-size: 12px; background: #0e1626; border: 1px solid var(--soc-border); border-radius: var(--soc-radius-sm); overflow: auto; max-height: 100%; }
.hv-empty { padding: 20px; color: var(--soc-text-dim); text-align: center; }
.hv-body { padding: 8px; }
.hv-header, .hv-row { display: grid; grid-template-columns: 90px 1fr 1fr; gap: 8px; padding: 1px 0; }
.hv-header { color: var(--soc-text-dim); font-weight: 600; border-bottom: 1px solid var(--soc-border); padding-bottom: 4px; margin-bottom: 4px; }
.hv-offset { color: var(--soc-primary); }
.hv-hex { color: var(--soc-text); word-break: break-all; }
.hv-ascii { color: var(--soc-text-muted); }
</style>
