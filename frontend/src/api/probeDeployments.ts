import client, { apiGet, apiPost } from './client'
import type { PageResult } from '../types/common'
import type {
  CreateDeploymentPayload,
  CreateRemovalPayload,
  PreflightPayload,
  PreflightResult,
  ProbeDeployment,
  ProbeDeploymentDetail,
  ProbeDeploymentEvent,
} from '../types/probeDeployment'

export function listDeployments(query: { search?: string; status?: string; page: number; page_size: number }): Promise<PageResult<ProbeDeployment>> {
  return apiGet('/probe-deployments', query as unknown as Record<string, unknown>)
}

export function getDeployment(id: number): Promise<ProbeDeploymentDetail> {
  return apiGet(`/probe-deployments/${id}`)
}

export function getDeploymentEvents(id: number, after = 0): Promise<{ items: ProbeDeploymentEvent[] }> {
  return apiGet(`/probe-deployments/${id}/events`, { after })
}

export function preflight(payload: PreflightPayload): Promise<PreflightResult> {
  return apiPost('/probe-deployments/preflight', payload)
}

export function createDeployment(payload: CreateDeploymentPayload): Promise<ProbeDeployment> {
  return apiPost('/probe-deployments', payload)
}

export function retryDeployment(id: number, payload: CreateDeploymentPayload): Promise<ProbeDeployment> {
  return apiPost(`/probe-deployments/${id}/retry`, payload)
}

/** Take a probe back off a target host. Returns the removal row to poll. */
export function createRemoval(payload: CreateRemovalPayload): Promise<ProbeDeployment> {
  return apiPost('/probe-deployments/removal', payload)
}

/** Drop a finished deployment or removal row. Never touches the host. */
export async function deleteDeployment(id: number): Promise<void> {
  await client.delete(`/probe-deployments/${id}`)
}

export function listPackages(): Promise<{ items: { version: string; arch: string; sha256: string }[]; version: string }> {
  return apiGet('/probe-deployments/packages')
}
