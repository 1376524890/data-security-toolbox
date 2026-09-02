<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { get, upload } from '../api'

const rows = ref<Array<Record<string, unknown>>>([])
const uploading = ref(false)

async function refresh() { rows.value = await get('/files') }
async function handleFile(file: File) {
  uploading.value = true
  try { await upload('/files/upload', file); ElMessage.success('上传成功'); await refresh() }
  finally { uploading.value = false }
}
onMounted(refresh)
</script>

<template>
  <el-card>
    <template #header>文件元数据分析</template>
    <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleFile(file.raw as File)">
      <el-button :loading="uploading">上传 JPG/PNG/PDF/DOCX</el-button>
    </el-upload>
    <el-table :data="rows" stripe style="margin-top: 16px">
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="file_type" label="类型" />
      <el-table-column prop="size" label="大小" />
      <el-table-column prop="sha256" label="SHA256" />
      <el-table-column prop="risk_level" label="风险" />
      <el-table-column label="隐藏信息">
        <template #default="{ row }">{{ row.metadata_json?.hidden_info?.hidden ? '是' : '否' }}</template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

