<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { post } from '../api'

const data = ref('hello world 123456')
const result = ref<Record<string, unknown>>({})

async function run() {
  result.value = await post('/algorithms/randomness', { data: data.value })
  ElMessage.success('评估完成')
}
</script>

<template>
  <el-card>
    <template #header>算法评估</template>
    <el-input v-model="data" type="textarea" :rows="5" placeholder="输入待评估数据" />
    <el-button type="primary" style="margin-top: 12px" @click="run">运行随机性评估</el-button>
    <pre style="margin-top: 12px">{{ result }}</pre>
  </el-card>
</template>

