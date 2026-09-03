<script setup lang="ts">
import { computed } from 'vue'
import { ElMessage } from 'element-plus'
import StateBox from './StateBox.vue'

export interface Column {
  prop?: string
  label: string
  width?: string | number
  minWidth?: string | number
  sortable?: boolean | 'custom'
  align?: 'left' | 'center' | 'right'
  showOverflowTooltip?: boolean
  fixed?: string | boolean
  formatter?: (row: any, column: any, cell: any) => string
  type?: 'index' | 'selection' | 'expand'
}

const props = withDefaults(defineProps<{
  columns: Column[]
  data: any[]
  loading?: boolean
  error?: string
  emptyText?: string
  total?: number
  page?: number
  pageSize?: number
  rowKey?: string
  stripe?: boolean
  exportName?: string
  selectable?: boolean
}>(), { rowKey: 'id', stripe: true, pageSize: 50, total: 0, page: 1 })

const emit = defineEmits<{
  'page-change': [page: number]
  'page-size-change': [size: number]
  'sort-change': [sort: { prop: string; order: 'ascending' | 'descending' | null }]
  'row-click': [row: any]
  retry: []
}>()

const hasPagination = computed(() => props.total > 0)

function handleSort({ prop, order }: { prop: string; order: 'ascending' | 'descending' | null }): void {
  emit('sort-change', { prop, order })
}

function exportCsv(): void {
  const cols = props.columns.filter((c) => c.prop)
  const header = cols.map((c) => c.label).join(',')
  const rows = props.data.map((row) => cols.map((c) => `"${String(row[c.prop as string] ?? '').replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([`\uFEFF${header}\n${rows}`], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${props.exportName || 'export'}.csv`
  link.click()
  URL.revokeObjectURL(url)
  ElMessage.success('已导出当前页')
}
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="!data.length" :empty-text="emptyText" @retry="emit('retry')">
      <el-table v-if="columns.length" :data="data" :row-key="rowKey" :stripe="stripe" style="width: 100%" @sort-change="handleSort" @row-click="(row: any) => emit('row-click', row)">
        <el-table-column v-if="selectable" type="selection" width="42" />
        <el-table-column v-for="col in columns" :key="col.prop || col.label" :prop="col.prop" :label="col.label" :width="col.width" :min-width="col.minWidth" :sortable="col.sortable" :align="col.align" :type="col.type" :show-overflow-tooltip="col.showOverflowTooltip !== false" :fixed="col.fixed" :formatter="col.formatter">
          <template v-if="col.prop && $slots[`cell-${col.prop}`]" #default="{ row }">
            <slot :name="`cell-${col.prop}`" :row="row" />
          </template>
        </el-table-column>
        <el-table-column v-if="$slots.actions" label="操作" width="120" fixed="right">
          <template #default="{ row }"><slot name="actions" :row="row" /></template>
        </el-table-column>
      </el-table>
    </StateBox>
    <div v-if="hasPagination" class="data-table-footer">
      <el-button v-if="exportName" size="small" @click="exportCsv">导出</el-button>
      <el-pagination class="pagination" layout="total, sizes, prev, pager, next" :total="total" :page-size="pageSize" :current-page="page" :page-sizes="[20, 50, 100, 200]" @current-change="(p: number) => emit('page-change', p)" @size-change="(s: number) => emit('page-size-change', s)" />
    </div>
  </div>
</template>
