import client, { apiGet } from './client'
import type { PageResult } from '../types/common'

/**
 * The 风险文件 surface: risky files, why they are risky, and reading the file
 * itself back from its source.
 *
 * The rows are asset instances with at least one value-level detection, so the
 * page cannot drift from the scan results. Nothing here stores or caches a file
 * body: browsing re-reads a bounded window, downloading re-reads the whole file,
 * and both only work for a source the platform can reach on its own.
 */

export interface RiskFile {
  id: number
  object_id: number
  name: string
  path: string
  owner_key?: string
  source_kind: string
  source_name: string
  host: string
  level: string
  sensitivity: string
  categories: string[]
  size: number
  coverage: string
  termination_reason: string
  status: string
  permission: string
  last_seen_at: string
  /** Detections on this instance's current object, and their total hits. */
  risk_point_count: number
  risk_hit_count: number
}

export interface RiskFileQuery {
  search?: string
  source_kind?: string
  severity?: string
  /** `field` ascending, `-field` descending; see `useTableSort`. */
  order_by?: string
  page: number
  page_size: number
}

/** One matched原文: the value plus the line it sat on. */
export interface RiskMatch {
  value: string
  context?: string
}

/** One rule/recogniser that fired, with the原文 it returned. */
export interface RiskEvidence {
  id: number
  rule_id: string
  rule_name: string
  rule_source: string
  recognizer: string
  evidence_type: string
  field_name: string
  sheet_name: string
  column_index: number | null
  confidence: number
  hit_count: number
  matches: RiskMatch[]
}

export interface RiskDetection {
  id: number
  category: string
  subcategory: string
  sensitivity_level: string
  severity: string
  confidence: number
  hit_count: number
  first_seen_at: string
  last_seen_at: string
}

/** A risk point: what fired, and the proof behind it. */
export interface RiskPoint {
  detection: RiskDetection
  evidence: RiskEvidence[]
}

export interface RiskPoints {
  instance_id: number
  object_id: number
  path: string
  name: string
  level: string
  items: RiskPoint[]
  detection_count: number
  hit_count: number
  matches_returned: number
  note: string
}

export interface RiskContent {
  instance_id: number
  path: string
  name: string
  source_name: string
  size: number
  preview_bytes: number
  truncated: boolean
  encoding: string
  text: string | null
  hex: string | null
  /** True when the response had matched values replaced by their masked form. */
  masked: boolean
  masked_values: number
}

export function listRiskFiles(query: RiskFileQuery): Promise<PageResult<RiskFile>> {
  return apiGet('/asset-instances', {
    sensitive_only: true, page: query.page, page_size: query.page_size,
    search: query.search || undefined, source_kind: query.source_kind || undefined,
    severity: query.severity || undefined, order_by: query.order_by || undefined,
  })
}

export function getRiskPoints(instanceId: number): Promise<RiskPoints> {
  return apiGet(`/asset-instances/${instanceId}/risk-points`)
}

/** Browse the file. ``mask`` replaces every value the rules returned with its
    masked form; ``mask: false`` is the explicit "查看全部". */
export function getRiskContent(instanceId: number, mask: boolean): Promise<RiskContent> {
  return apiGet(`/asset-instances/${instanceId}/content`, { mask })
}

/**
 * Download the whole file from its source.
 *
 * Pulled through the API client rather than a bare link so a source that has
 * gone away reports itself in place, instead of replacing the console with a
 * raw error page and losing the operator's place.
 */
export async function downloadRiskFile(instanceId: number, name: string): Promise<void> {
  const response = await client.get(`/asset-instances/${instanceId}/download`, { responseType: 'blob' })
  const url = URL.createObjectURL(response.data as Blob)
  const link = document.createElement('a')
  link.href = url
  link.download = name || `instance-${instanceId}`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
