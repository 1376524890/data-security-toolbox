<script setup lang="ts">
defineProps<{ message?: string }>()
defineEmits<{ retry: [] }>()
</script>

<template>
  <el-alert type="error" :closable="false" show-icon>
    <template #title>{{ message || '加载失败' }}</template>
    <el-button size="small" class="retry" @click="$emit('retry')">重试</el-button>
  </el-alert>
</template>

<style scoped>.retry { margin-top: 8px; }</style>
