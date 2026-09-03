<script setup lang="ts">
import type { Recordable } from './types'

export interface FilterField {
  key: string
  label: string
  type?: 'input' | 'select'
  options?: Array<{ label: string; value: string }>
  placeholder?: string
  width?: string
}

const props = defineProps<{ filters: FilterField[]; model: Recordable }>()
const emit = defineEmits<{ search: []; reset: [] }>()

function onReset(): void {
  props.filters.forEach((field) => { props.model[field.key] = '' })
  emit('reset')
}
</script>

<template>
  <div class="filter-bar">
    <template v-for="field in filters" :key="field.key">
      <el-input
        v-if="field.type !== 'select'"
        v-model="model[field.key]"
        :placeholder="field.placeholder || field.label"
        :style="field.width ? { width: field.width } : undefined"
        clearable
        @keyup.enter="emit('search')"
        @clear="emit('search')"
      />
      <el-select
        v-else
        v-model="model[field.key]"
        :placeholder="field.placeholder || field.label"
        :style="field.width ? { width: field.width } : undefined"
        clearable
        @change="emit('search')"
      >
        <el-option v-for="opt in field.options || []" :key="opt.value" :label="opt.label" :value="opt.value" />
      </el-select>
    </template>
    <el-button type="primary" @click="emit('search')">查询</el-button>
    <el-button @click="onReset">重置</el-button>
    <div class="filter-bar-spacer" />
    <slot name="actions" />
  </div>
</template>

<style scoped>
.filter-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
.filter-bar-spacer { flex: 1; }
</style>
