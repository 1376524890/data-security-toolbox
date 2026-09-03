<script setup lang="ts">
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const username = ref('admin')
const password = ref('')
const loading = ref(false)

async function submit(): Promise<void> {
  loading.value = true
  try {
    await auth.login(username.value, password.value)
    ElMessage.success('登录成功')
    const redirect = String(route.query.redirect || '/')
    router.push(redirect)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login">
    <div class="login-card">
      <div class="brand">
        <div class="brand-logo">D</div>
        <div>
          <div class="brand-name">Data Security Toolbox</div>
          <div class="brand-sub">SOC · NDR · DATA SECURITY</div>
        </div>
      </div>
      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="用户名"><el-input v-model="username" autocomplete="username" placeholder="admin" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="password" type="password" autocomplete="current-password" placeholder="输入密码" @keyup.enter="submit" /></el-form-item>
        <el-button type="primary" class="login-btn" :loading="loading" @click="submit">登录</el-button>
      </el-form>
    </div>
  </div>
</template>

<style scoped>
.login { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: radial-gradient(circle at 30% 20%, #0e1626, #0b1220 60%); }
.login-card { width: 380px; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: 12px; padding: 32px; box-shadow: var(--soc-shadow-lg); }
.brand { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
.brand-logo { width: 40px; height: 40px; border-radius: 8px; background: linear-gradient(135deg, var(--soc-primary), var(--soc-primary-2)); display: flex; align-items: center; justify-content: center; color: #06121f; font-weight: 800; font-size: 20px; }
.brand-name { font-weight: 700; color: var(--soc-text-strong); font-size: 16px; }
.brand-sub { color: var(--soc-text-dim); font-size: 11px; letter-spacing: 0.08em; }
.login-btn { width: 100%; margin-top: 8px; }
</style>
