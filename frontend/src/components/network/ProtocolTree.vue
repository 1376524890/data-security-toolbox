<script setup lang="ts">
import { ref } from 'vue'

export interface LayerItem { label: string; value: string }
export interface Layer { name: string; items: LayerItem[]; note?: string }

defineProps<{ layers: Layer[] }>()
const open = ref<string[]>([])
</script>

<template>
  <el-collapse v-model="open" :accordion="false" class="protocol-tree">
    <el-collapse-item v-for="layer in layers" :key="layer.name" :name="layer.name">
      <template #title><span class="pt-name">{{ layer.name }}</span></template>
      <div v-if="layer.note" class="pt-note">{{ layer.note }}</div>
      <div v-for="item in layer.items" :key="item.label" class="pt-item">
        <span class="pt-label">{{ item.label }}</span>
        <span class="pt-value mono">{{ item.value }}</span>
      </div>
    </el-collapse-item>
  </el-collapse>
</template>

<style scoped>
.protocol-tree { border: 1px solid var(--soc-border); border-radius: var(--soc-radius-sm); }
.pt-name { font-weight: 600; color: var(--soc-primary); font-size: 13px; }
.pt-note { color: var(--soc-warning); font-size: 11px; margin: 4px 0; }
.pt-item { display: flex; justify-content: space-between; gap: 10px; padding: 3px 0; border-bottom: 1px dashed var(--soc-border); }
.pt-label { color: var(--soc-text-muted); }
.pt-value { color: var(--soc-text); }
</style>
