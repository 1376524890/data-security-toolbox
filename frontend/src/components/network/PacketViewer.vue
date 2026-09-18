<script setup lang="ts">
import type { Packet } from '../../types/pcap'

function endpoint(address: string, port: number): string {
  if (!address) return '-'
  if (!port) return address
  return `${address.includes(':') ? `[${address}]` : address}:${port}`
}

function timestamp(value: number): string {
  if (!Number.isFinite(value)) return '-'
  const date = new Date(value * 1000)
  return `${date.toLocaleTimeString('zh-CN', { hour12: false })}.${String(Math.floor((value % 1) * 1000000)).padStart(6, '0')}`
}

defineProps<{ packets: Packet[]; selected?: number | null }>()
defineEmits<{ select: [packet: Packet] }>()
</script>

<template>
  <el-table :data="packets" row-key="id" size="small" height="100%" :row-class-name="({ row }: any) => row.id === selected ? 'packet-selected' : ''" @row-click="(row: Packet) => $emit('select', row)">
    <el-table-column prop="number" label="#" width="64" sortable />
    <el-table-column label="时间" width="155" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ timestamp(row.timestamp) }}</span></template></el-table-column>
    <el-table-column label="源地址" min-width="180" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ endpoint(row.src_ip, row.src_port) }}</span></template></el-table-column>
    <el-table-column label="目的地址" min-width="180" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ endpoint(row.dst_ip, row.dst_port) }}</span></template></el-table-column>
    <el-table-column prop="protocol" label="协议" width="90" />
    <el-table-column prop="length" label="长度" width="70" sortable />
    <el-table-column prop="info" label="信息" min-width="220" show-overflow-tooltip />
  </el-table>
</template>

<style scoped>
:deep(.packet-selected) td.el-table__cell { background: var(--soc-primary-dim) !important; }
</style>
