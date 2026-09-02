import { apiGet, apiPost } from './client'
import type { IntegrationStatus } from '../types/integration'

export function listIntegrations(): Promise<IntegrationStatus[]> {
  return apiGet('/integrations')
}

export function runIntegration(name: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  return apiPost(`/integrations/${name}/analyze`, payload)
}
