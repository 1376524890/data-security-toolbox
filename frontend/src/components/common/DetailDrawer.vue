<script setup lang="ts">
import { Close } from '@element-plus/icons-vue'

defineProps<{ modelValue: boolean; title: string; width?: string | number }>()
defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <el-drawer
    :model-value="modelValue"
    :title="title"
    :size="width || '58%'"
    destroy-on-close
    @update:model-value="(v: boolean) => $emit('update:modelValue', v)"
  >
    <template #header="{ close }">
      <div class="drawer-head">
        <span class="drawer-title">{{ title }}</span>
        <div class="drawer-actions"><slot name="header-actions" /><el-button link @click="close"><el-icon><Close /></el-icon></el-button></div>
      </div>
    </template>
    <slot />
    <div v-if="$slots.footer" class="drawer-footer"><slot name="footer" /></div>
  </el-drawer>
</template>

<style scoped>
.drawer-head { display: flex; align-items: center; justify-content: space-between; width: 100%; }
.drawer-title { font-weight: 700; font-size: 15px; color: var(--soc-text-strong); }
.drawer-actions { display: flex; align-items: center; gap: 8px; }
.drawer-footer { margin-top: 16px; display: flex; justify-content: flex-end; gap: 8px; }
</style>
