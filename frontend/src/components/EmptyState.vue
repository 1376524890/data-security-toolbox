<script setup lang="ts">
import { Document } from '@element-plus/icons-vue'

defineProps<{ title?: string; description?: string }>()
</script>

<template>
  <el-empty :description="description || '暂无数据'">
    <template #image><el-icon><Document /></el-icon></template>
    <template #default>{{ title }}</template>
  </el-empty>
</template>
