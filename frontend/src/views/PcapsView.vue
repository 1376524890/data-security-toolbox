<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { get, post, upload } from '../api'

const rows = ref<Array<Record<string, unknown>>>([])
const detail = ref<Record<string, unknown>>({})
const flows = ref<Array<Record<string, unknown>>>([])
const anomalies = ref<Array<Record<string, unknown>>>([])

async function refresh() { rows.value = await get('/pcaps') }
async function handleFile(file: File) {
  await upload('/pcaps/upload', file)
  ElMessage.success('PCAP 已上传')
  await refresh()
}
async function analyze(id: number) {
  await post(`/pcaps/${id}/analyze`)
  ElMessage.success('已触发分析')
  await refresh()
}
async function open(id: number) {
  detail.value = await get(`/pcaps/${id}`)
  flows.value = await get(`/pcaps/${id}/flows`)
  anomalies.value = await get(`/pcaps/${id}/anomalies`)
}
onMounted(refresh)
</script>

<template>
  <el-card>
    <template #header>PCAP 协议与流量分析</template>
    <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleFile(file.raw as File)">
      <el-button>上传 PCAP/PCAPNG</el-button>
    </el-upload>
    <el-table :data="rows" stripe style="margin-top: 16px">
      <el-table-column prop="filename" label="文件" />
      <el-table-column prop="size" label="大小" />
      <el-table-column prop="packet_count" label="包数" />
      <el-table-column prop="status" label="状态" />
      <el-table-column label="操作">
        <template #default="{ row }">
          <el-button size="small" @click="analyze(row.id)">分析</el-button>
          <el-button size="small" @click="open(row.id)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
  <el-card v-if="detail.filename" style="margin-top: 16px">
    <template #header>PCAP 详情：{{ detail.filename }}</template>
    <el-descriptions :column="4" border>
      <el-descriptions-item label="包数">{{ detail.packet_count }}</el-descriptions-item>
      <el-descriptions-item label="时长">{{ detail.duration }}</el-descriptions-item>
      <el-descriptions-item label="开始">{{ detail.capture_start }}</el-descriptions-item>
      <el-descriptions-item label="结束">{{ detail.capture_end }}</el-descriptions-item>
    </el-descriptions>
    <h3>协议分布</h3>
    <el-table :data="flows" stripe><el-table-column prop="src_ip" label="源 IP" /><el-table-column prop="dst_ip" label="目标 IP" /><el-table-column prop="protocol" label="协议" /><el-table-column prop="packets" label="包数" /><el-table-column prop="bytes" label="字节" /></el-table>
    <h3>异常</h3>
    <el-table :data="anomalies" stripe><el-table-column prop="rule" label="规则" /><el-table-column prop="severity" label="严重度" /><el-table-column prop="description" label="描述" /></el-table>
  </el-card>
</template>

