<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { login } from '../api/auth'

const router = useRouter()
const username = ref('admin')
const password = ref('')
const loading = ref(false)

async function submit(): Promise<void> {
  loading.value = true
  try {
    await login(username.value, password.value)
    ElMessage.success('登录成功')
    router.push('/')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login">
    <el-card class="card">
      <h2>Data Security Toolbox</h2>
      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="用户名"><el-input v-model="username" autocomplete="username" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="password" type="password" autocomplete="current-password" @keyup.enter="submit" /></el-form-item>
        <el-button type="primary" :loading="loading" @click="submit">登录</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<style scoped>
.login { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0f172a; }
.card { width: 360px; }
</style>
