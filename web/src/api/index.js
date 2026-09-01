import axios from 'axios'

const http = axios.create({
  baseURL: '/api',
  timeout: 60000
})

// 请求拦截：附加 JWT（阶段二起预留）
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export default http

// 常用接口封装
export const api = {
  dashboard: () => http.get('/dashboard/stats'),
  probes: () => http.get('/dashboard/stats'),
  createTask: (data) => http.post('/tasks', data),
  listTasks: (params) => http.get('/tasks', { params }),
  cancelTask: (id) => http.delete(`/tasks/${id}`),
  listResults: (type) => http.get(`/results/${type}`),
  modules: () => http.get('/modules'),
  analyzeAsset: (formData) => http.post('/asset/analyze', formData),
  regexGen: (formData) => http.post('/tools/regex-gen', formData),
  analyzeProtocol: (formData) => http.post('/protocol/analyze', formData),
  protocolPackets: (reportId) => http.get(`/protocol/packets/${reportId}`),
  analyzeTraffic: (formData) => http.post('/traffic/analyze', formData),
  trafficReport: (reportId) => http.get(`/traffic/report/${reportId}`),
  analyzeMetadata: (formData) => http.post('/metadata/analyze', formData),
  analyzeAlgo: (formData) => http.post('/algo/analyze', formData),
  resultSummary: () => http.get('/results/summary'),
  results: (rtype) => http.get(`/results/${rtype}`),
  resultDetail: (id) => http.get(`/results/detail/${id}`),
  moduleCaps: (name) => http.get(`/modules/${name}/capabilities`)
}