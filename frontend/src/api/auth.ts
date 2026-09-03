import { apiGet, apiPost } from './client'

export interface AuthUser {
  id: number
  username: string
  role: string
}

export function login(username: string, password: string): Promise<AuthUser> {
  return apiPost('/auth/login', { username, password })
}

export function logout(): Promise<{ status: string }> {
  return apiPost('/auth/logout')
}

export function me(): Promise<AuthUser> {
  return apiGet('/auth/me')
}
