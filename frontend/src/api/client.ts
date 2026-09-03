import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios'
import { mockAdapter } from '../mocks/adapter'

export const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1'
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'

const client: AxiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
})

// Demo mode (5174): serve realistic mock data. Rollup tree-shakes the mock
// out of the real 5173 bundle because DEMO_MODE is a build-time constant.
if (DEMO_MODE) {
  client.defaults.adapter = mockAdapter as any
}

client.interceptors.response.use(
  (response) => response,
  (error) => {
    const message = error?.response?.data?.detail || error?.message || '请求失败'
    return Promise.reject(new Error(message))
  },
)

export async function apiGet<T>(path: string, params?: Record<string, unknown>, config?: AxiosRequestConfig): Promise<T> {
  const response = await client.get<T>(path, { params, ...config })
  return response.data
}

export async function apiPost<T>(path: string, body?: unknown, config?: AxiosRequestConfig): Promise<T> {
  const response = await client.post<T>(path, body, config)
  return response.data
}

export async function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  const response = await client.patch<T>(path, body)
  return response.data
}

export async function apiUpload<T>(path: string, file: File, fields?: Record<string, string | number | boolean>): Promise<T> {
  const form = new FormData()
  form.append('file', file)
  Object.entries(fields || {}).forEach(([key, value]) => form.append(key, String(value)))
  const response = await client.post<T>(path, form)
  return response.data
}

export function downloadUrl(path: string): string {
  return `${API_BASE}${path}`
}

export default client
