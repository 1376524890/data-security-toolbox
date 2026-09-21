import client, { apiGet, apiPatch, apiPost } from './client'
import type { PageResult } from '../types/common'

/**
 * Target-database connections and their collection scans.
 *
 * The platform's worker connects to the target itself, so every field here is a
 * configuration until a real attempt says otherwise. A password is write-only:
 * it is sent once and the API only ever reports `password_set`. Scan progress
 * and results come from the task the server queued, never from a client guess.
 */

export interface DatabaseConnection {
  id: number
  name: string
  engine: string
  engine_label: string
  host: string
  port: number
  database: string
  username: string
  /** True when a password is stored; the password itself is never returned. */
  password_set: boolean
  tls_mode: string
  options: Record<string, unknown>
  enabled: boolean
  last_test_at: string
  last_test_status: string
  last_test_error: string
  last_scan_at: string
  created_at: string
  updated_at: string
}

export interface EngineOption {
  engine: string
  label: string
  default_port: number
}

export interface ConnectionList extends PageResult<DatabaseConnection> {
  engines: EngineOption[]
  note: string
}

export interface ConnectionPayload {
  name?: string
  engine?: string
  host?: string
  port?: number
  database?: string
  username?: string
  password?: string
  tls_mode?: string
  options?: Record<string, unknown>
  enabled?: boolean
}

export interface ScanSummary {
  task_id: number
  status: string
  stage: string
  progress: number
  error: string
  created_at: string
  started_at: string
  finished_at: string
  duration_seconds: number | null
  connection_id: number
  scope: { schemas?: string[]; tables?: string[] }
  config_hash: string
  server_version: string
  engine: string
  host: string
  port: number
  database: string
  schemas: string[]
  tables_total: number
  tables_selected: number
  tables_scanned: number
  tables_failed: number
  rows_read: number
  values_scanned: number
  hits: number
  objects: number
  detections: number
  complete_scope: boolean | null
  termination_reason: string
  read_only: boolean | null
  categories: string[]
  not_observed: number
  engine_version: string
  ruleset_version: string
  sample_rows: number
  notes: string[]
  /** Only the single-task detail endpoint sends the per-table breakdown. */
  tables?: TableScanRow[]
  table_errors?: TableErrorRow[]
}

export interface TableScanRow {
  path: string
  rows_read: number
  values_scanned: number
  hits: number
  detections: number
  categories: string[]
  /** Column names that only looked sensitive; no value confirmed them. */
  candidates: string[]
}

export interface TableErrorRow {
  path: string
  error: string
}

export interface ConnectionDetail extends DatabaseConnection {
  scans: ScanSummary[]
}

export interface TableRow {
  name: string
  kind: string
  schema: string
  columns: number
}

export interface TestResult extends DatabaseConnection {
  result: Record<string, unknown>
}

export interface ScanDetail {
  id: number
  kind: string
  status: string
  progress: number
  current_stage: string
  error: string
  result: Record<string, unknown>
  summary: ScanSummary
}

export function listDatabaseConnections(query: Record<string, unknown> = {}): Promise<ConnectionList> {
  return apiGet('/database-connections', query)
}

export function createDatabaseConnection(payload: ConnectionPayload): Promise<DatabaseConnection> {
  return apiPost('/database-connections', payload)
}

export function getDatabaseConnection(id: number): Promise<ConnectionDetail> {
  return apiGet(`/database-connections/${id}`)
}

export function updateDatabaseConnection(id: number, payload: ConnectionPayload): Promise<DatabaseConnection> {
  return apiPatch(`/database-connections/${id}`, payload)
}

export async function deleteDatabaseConnection(id: number): Promise<{ deleted: boolean; kept_instances: number }> {
  const response = await client.delete(`/database-connections/${id}`)
  return response.data
}

export function testDatabaseConnection(id: number): Promise<TestResult> {
  return apiPost(`/database-connections/${id}/test`)
}

export function listConnectionSchemas(id: number): Promise<{ connection_id: number; schemas: string[]; count: number; default: string }> {
  return apiGet(`/database-connections/${id}/schemas`)
}

export function listConnectionTables(id: number, schema: string): Promise<{ schema: string; tables: TableRow[]; count: number }> {
  return apiGet(`/database-connections/${id}/tables`, { schema })
}

export function startDatabaseScan(id: number, scope: { schemas: string[]; tables: string[] }):
  Promise<{ id: number; status: string; location: string; connection_id: number; config_hash: string }> {
  return apiPost(`/database-connections/${id}/scans`, scope)
}

export function listConnectionScans(id: number, limit = 20): Promise<{ connection_id: number; items: ScanSummary[]; count: number }> {
  return apiGet(`/database-connections/${id}/scans`, { limit })
}

export function getScanDetail(taskId: number): Promise<ScanDetail> {
  return apiGet(`/database-connections/scans/${taskId}`)
}
