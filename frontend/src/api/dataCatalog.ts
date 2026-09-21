import { apiGet, apiPost } from './client'
import type { PageResult } from '../types/common'

/**
 * Typed access to the data-type-centric query APIs.
 *
 * Every value here comes from the object model (data_objects / asset_instances /
 * detections / detection_evidence). Evidence carries rule, recogniser, field and
 * count, plus the bounded matched原文 the probe returned for that hit so a
 * reviewer can verify the finding. No response ever carries file content.
 */

export type IdentityKind = 'confirmed' | 'candidate' | 'scoped'

export interface DataTypeRow {
  category: string
  entity: string
  level: string
  level_name: string
  level_description: string
  /** The legacy Critical/High/Medium/Low vocabulary, a different axis. */
  severity: string
  protected: boolean
  source: 'builtin_default' | 'settings_override' | string
  field_only: boolean
  object_count: number
  active_instance_count: number
  host_count: number
  confirmed_duplicate_count: number
  candidate_count: number
  /** Part-fingerprint objects with ≥2 instances: a real suspected copy. */
  candidate_duplicate_count: number
  /** Part-fingerprint objects seen on a single instance: identity unresolved. */
  identity_pending_count: number
  truncated: boolean
}

export interface DataTypeTotals {
  /** Sensitive types that have an object in scope. */
  types: number
  /** De-duplicated objects: an object holding two types still counts once. */
  objects: number
  instances: number
  hosts: number
  confirmed_duplicates: number
  candidate_duplicates: number
  identity_pending: number
  truncated: boolean
}

export interface DataTypeCenter {
  items: DataTypeRow[]
  count: number
  totals: DataTypeTotals
  totals_scope: string
  dedup_rules: Record<string, string>
  levels: Record<string, { name: string; description: string }>
  mapping_source: string
}

export interface DataObjectRow {
  id: number
  object_key: string
  object_type: string
  content_hash: string
  hash_type: string
  identity_confidence: number
  identity_kind: IdentityKind
  partial_version: string
  size: number
  categories: string[]
  sensitivity: string
  level: string
  level_source: string
  instance_count: number
  active_instance_count: number
  first_seen_at: string
  last_seen_at: string
}

export interface AssetInstanceRow {
  id: number
  object_id: number
  probe_id: number
  /** file | database | file_share: which collector observed this copy. */
  source_kind: string
  /** probe:<id> | db:<connection id> | file-source:<id>: the exact collector. */
  owner_key: string
  probe_name: string
  host: string
  path: string
  name: string
  instance_type: string
  size: number
  content_hash: string
  hash_type: string
  status: 'ACTIVE' | 'NOT_OBSERVED' | string
  owner: string
  group: string
  permission: string
  sensitivity: string
  level: string
  level_source: string
  categories: string[]
  coverage: string
  termination_reason: string
  ruleset_version: string
  engine_version: string
  profile_version: string
  last_scan_id: string
  first_seen_at: string
  last_seen_at: string
}

export interface DetectionRow {
  id: number
  object_id: number
  instance_id: number
  probe_id: number
  source_kind: string
  scan_id: string
  category: string
  subcategory: string
  sensitivity_level: string
  severity: string
  confidence: number
  sample_size: number
  sample_hit_count: number
  hit_count: number
  engine_version: string
  ruleset_version: string
  first_seen_at: string
  last_seen_at: string
}

/** One matched原文 the probe returned: the value and the line it sits on. */
export interface MatchText {
  value: string
  context: string
}

export interface EvidenceRow {
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
  engine_version: string
  ruleset_version: string
  /** Bounded by the probe (a few strings per hit, each length-capped). */
  matches: MatchText[]
}

export interface EvidenceResponse {
  detection: DetectionRow
  items: EvidenceRow[]
  count: number
  matches_returned: number
  note: string
}

export interface InstanceDetail extends AssetInstanceRow {
  /** The collector's display name: a probe name, a connection or a share. */
  source_name: string
  inode: number | null
  device: number | null
  mtime_ns: number | null
  object_key: string
  identity_kind: IdentityKind
  last_scan_at: string
  extra: Record<string, unknown>
  detections: DetectionRow[]
  history_included: boolean
}

export interface ObjectDetail extends DataObjectRow {
  partial_layout: Record<string, unknown>
  extra: Record<string, unknown>
  instances: AssetInstanceRow[]
}

export interface SensitivityCatalogEntry {
  category: string
  entity: string
  level: string
  level_name: string
  level_description: string
  severity: string
  protected: boolean
  source: string
  field_only: boolean
}

export interface SensitivityLevels {
  levels: Record<string, { name: string; description: string }>
  items: SensitivityCatalogEntry[]
  non_protected: SensitivityCatalogEntry[]
  note: string
  source: string
}

export function listDataTypes(probeId?: number): Promise<DataTypeCenter> {
  return apiGet('/data-types', probeId ? { probe_id: probeId } : undefined)
}

export function getDataType(category: string, query: { probe_id?: number; page: number; page_size: number }):
  Promise<DataTypeRow & { objects: PageResult<DataObjectRow> }> {
  return apiGet(`/data-types/${encodeURIComponent(category)}`, query as unknown as Record<string, unknown>)
}

export function listDataObjects(query: Record<string, unknown>): Promise<PageResult<DataObjectRow>> {
  return apiGet('/data-objects', query)
}

export function getDataObject(id: number): Promise<ObjectDetail> {
  return apiGet(`/data-objects/${id}`)
}

export function listObjectDetections(id: number, query: { page: number; page_size: number }):
  Promise<PageResult<DetectionRow>> {
  return apiGet(`/data-objects/${id}/detections`, query)
}

export function listAssetInstances(query: Record<string, unknown>): Promise<PageResult<AssetInstanceRow> & { association?: string }> {
  return apiGet('/asset-instances', query)
}

export function getAssetInstance(id: number, includeHistory = false): Promise<InstanceDetail> {
  return apiGet(`/asset-instances/${id}`, includeHistory ? { include_history: true } : undefined)
}

export function getDetectionEvidence(id: number): Promise<EvidenceResponse> {
  return apiGet(`/detections/${id}/evidence`)
}

export function getSensitivityLevels(): Promise<SensitivityLevels> {
  return apiGet('/sensitivity-levels')
}

export function rebuildProjection(probeId?: number): Promise<Record<string, number>> {
  return apiPost('/admin/data-assets/rebuild-projection', probeId ? { probe_id: probeId } : {})
}

export function backfillLegacy(): Promise<Record<string, number>> {
  return apiPost('/admin/data-assets/backfill', {})
}
