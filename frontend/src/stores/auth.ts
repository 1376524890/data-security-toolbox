import { defineStore } from 'pinia'
import { ref } from 'vue'
import { login as apiLogin, logout as apiLogout, me, type AuthUser } from '../api/auth'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<AuthUser | null>(null)
  const loaded = ref(false)

  async function login(username: string, password: string): Promise<void> {
    user.value = await apiLogin(username, password)
    loaded.value = true
  }

  async function load(): Promise<void> {
    try {
      user.value = await me()
    } catch {
      user.value = null
    } finally {
      loaded.value = true
    }
  }

  async function logout(): Promise<void> {
    try { await apiLogout() } finally {
      user.value = null
      loaded.value = true
    }
  }

  return { user, loaded, login, load, logout }
})
