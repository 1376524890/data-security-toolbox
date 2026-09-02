<script setup lang="ts">
import { ref } from 'vue'

defineProps<{ placeholder?: string }>()
defineEmits<{ search: [value: string] }>()
const value = ref('')
</script>

<template>
  <el-input v-model="value" :placeholder="placeholder || '搜索...'" clearable class="search-toolbar" @keyup.enter="$emit('search', value)" @clear="$emit('search', '')">
    <template #suffix><el-button link type="primary" @click="$emit('search', value)">搜索</el-button></template>
  </el-input>
</template>
