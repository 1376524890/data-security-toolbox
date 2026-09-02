import axios from 'axios'

export const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1'

const client = axios.create({ baseURL: API_BASE, timeout: 120000 })

export async function get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
  const response = await client.get<T>(path, { params })
  return response.data
}

export async function post<T>(path: string, body?: unknown): Promise<T> {
  const response = await client.post<T>(path, body)
  return response.data
}

export async function upload<T>(path: string, file: File, extra?: Record<string, unknown>): Promise<T> {
  const form = new FormData()
  form.append('file', file)
  Object.entries(extra || {}).forEach(([key, value]) => form.append(key, String(value)))
  const response = await client.post<T>(path, form)
  return response.data
}

export function downloadUrl(path: string): string {
  return `${API_BASE}${path}`
}

