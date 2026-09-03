<script setup lang="ts">
import type { Packet } from '../../types/pcap'
import { formatDateTime } from '../../utils/format'

defineProps<{ packets: Packet[]; selected?: number | null }>()
defineEmits<{ select: [packet: Packet] }>()
</script>

<template>
  <el-table :data="packets" size="small" height="100%" :row-class-name="({ row }: any) => row.id === selected ? 'packet-selected' : ''" @row-click="(row: Packet) => $emit('select', row)">
    <el-table-column prop="number" label="#" width="64" sortable />
    <el-table-column label="时间" width="120"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
    <el-table-column label="源地址" width="150"><template #default="{ row }"><span class="mono">{{ row.src_ip }}:{{ row.src_port }}</span></template></el-table-column>
    <el-table-column label="目的地址" width="150"><template #default="{ row }"><span class="mono">{{ row.dst_ip }}:{{ row.dst_port }}</span></template></el-table-column>
    <el-table-column prop="protocol" label="协议" width="90" />
    <el-table-column prop="length" label="长度" width="70" sortable />
    <el-table-column prop="info" label="信息" min-width="220" show-overflow-tooltip />
  </el-table>
</template>

<style scoped>
:deep(.packet-selected) td.el-table__cell { background: var(--soc-primary-dim) !important; }
</style>
