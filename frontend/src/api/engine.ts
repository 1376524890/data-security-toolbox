import { apiGet } from './client'

export interface EngineInfo {
  name: string
  version: string
  description?: string
  capabilities?: string[]
}

export function getEngineRegistry(): Promise<EngineInfo[]> {
  return apiGet('/engine/registry')
}
