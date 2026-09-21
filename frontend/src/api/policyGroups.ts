import client, { apiGet, apiPatch, apiPost } from './client'
import type { PageResult } from '../types/common'

export interface PolicyGroup {
  id: number
  name: string
  description: string
  enabled: boolean
  version: number
  scope: string[]
  rule_ids: string[]
  categories: string[]
  keywords: string[]
  min_confidence: number
  min_matches: number
  created_by: string
  created_at: string
  updated_at: string
}

export type PolicyGroupDraft = Pick<PolicyGroup, 'name' | 'description' | 'enabled' | 'scope' |
  'rule_ids' | 'categories' | 'keywords' | 'min_confidence' | 'min_matches'>

export interface PolicyGroupQuery {
  name?: string
  enabled?: boolean
  page: number
  page_size: number
}

export function listPolicyGroups(query: PolicyGroupQuery): Promise<PageResult<PolicyGroup>> {
  return apiGet('/policy-groups', query as unknown as Record<string, unknown>)
}

export function createPolicyGroup(draft: PolicyGroupDraft): Promise<PolicyGroup> {
  return apiPost('/policy-groups', draft)
}

export function updatePolicyGroup(id: number, draft: Partial<PolicyGroupDraft>): Promise<PolicyGroup> {
  return apiPatch(`/policy-groups/${id}`, draft)
}

export async function deletePolicyGroup(id: number): Promise<void> {
  await client.delete(`/policy-groups/${id}`)
}
