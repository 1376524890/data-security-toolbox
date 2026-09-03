<script setup lang="ts">
defineProps<{ title: string; subtitle?: string }>()
</script>

<template>
  <div class="page-header">
    <div>
      <div class="ph-title">{{ title }}</div>
      <div v-if="subtitle" class="ph-subtitle">{{ subtitle }}</div>
    </div>
    <div class="ph-actions"><slot name="actions" /></div>
  </div>
</template>

<style scoped>
.page-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 14px; }
.ph-title { font-size: 18px; font-weight: 700; color: var(--soc-text-strong); }
.ph-subtitle { color: var(--soc-text-dim); font-size: 12px; margin-top: 2px; }
.ph-actions { display: flex; align-items: center; gap: 8px; }
</style>
