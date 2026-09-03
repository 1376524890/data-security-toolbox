<script setup lang="ts">
import type { Flow } from '../../types/pcap'
import { formatBytes } from '../../utils/format'

defineProps<{ flows: Flow[] }>()
defineEmits<{ select: [flow: Flow] }>()
</script>

<template>
  <el-table :data="flows" size="small" height="100%" @row-click="(row: Flow) => $emit('select', row)">
    <el-table-column label="源地址" width="160"><template #default="{ row }"><span class="mono">{{ row.src_ip }}:{{ row.src_port }}</span></template></el-table-column>
    <el-table-column label="目的地址" width="160"><template #default="{ row }"><span class="mono">{{ row.dst_ip }}:{{ row.dst_port }}</span></template></el-table-column>
    <el-table-column prop="protocol" label="协议" width="80" />
    <el-table-column prop="app_protocol" label="应用层" width="90" />
    <el-table-column prop="packets" label="包数" width="80" sortable />
    <el-table-column label="字节" width="100" sortable><template #default="{ row }">{{ formatBytes(row.bytes) }}</template></el-table-column>
  </el-table>
</template>
