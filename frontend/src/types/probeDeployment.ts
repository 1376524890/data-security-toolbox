export type DeploymentStatus =
  | 'CREATED'
  | 'CONNECTING'
  | 'PREFLIGHT'
  | 'UPLOADING'
  | 'INSTALLING'
  | 'STARTING'
  | 'WAIT_CALLBACK'
  | 'REGISTERED'
  | 'ONLINE'
  | 'REMOVING'
  | 'REMOVED'
  | 'FAILED'
  | 'CANCELLED'

/** Install pushes a probe; uninstall takes it back off the host. */
export type DeploymentAction = 'install' | 'uninstall'

/** What the operator asked the uninstaller to leave behind on the host. */
export interface RemovalOptions {
  keep_data?: boolean
  keep_user?: boolean
  remove_user?: boolean
  delete_record?: boolean
}

/** What the uninstaller reported: the audit trail for a removal. */
export interface RemovalAudit {
  ok?: boolean
  exit_code?: number
  finished_at?: string
  removed?: string[]
  kept?: string[]
  absent?: string[]
  failed?: string[]
  bytes_freed?: number
  files_freed?: number
  reason?: string
  probe_status_before?: string
  probe_status_after?: string
}

export interface ProbeDeployment {
  backend_url?: string
  id: number
  name: string
  action: DeploymentAction
  host: string
  port: number
  username: string
  auth_type: 'password' | 'private_key'
  profile: 'lite' | 'standard' | 'sensor'
  status: DeploymentStatus
  progress: number
  current_stage: string
  error_code: string
  error_message: string
  probe_id: number | null
  package_version: string
  created_by: string
  credential_destroyed: boolean
  callback_deadline?: string | null
  registered_at?: string | null
  first_heartbeat_at?: string | null
  preflight_result: Record<string, unknown>
  removal_options: RemovalOptions
  data_config?: { paths?: string[]; interval_seconds?: number; max_files?: number; max_depth?: number; include_databases?: boolean }
  result: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface ProbeDeploymentEvent {
  id: number
  seq: number
  stage: string
  message: string
  created_at: string
}

export interface ProbeDeploymentDetail extends ProbeDeployment {
  events: ProbeDeploymentEvent[]
}

export interface PreflightPayload {
  backend_url?: string
  host: string
  port: number
  username: string
  auth_type: 'password' | 'private_key'
  password?: string
  private_key?: string
  key_passphrase?: string
  profile: 'lite' | 'standard' | 'sensor'
  /** Directories the deployed probe inventories for data assets. */
  data_paths?: string[]
  data_interval_seconds?: number
  data_max_files?: number
  data_max_depth?: number
  data_include_databases?: boolean
}

export interface CreateDeploymentPayload extends PreflightPayload {
  name: string
  idempotency_key: string
}

/** A removal reaches the same host the same way, but installs nothing. */
export interface CreateRemovalPayload {
  name?: string
  host: string
  port: number
  username: string
  auth_type: 'password' | 'private_key'
  password?: string
  private_key?: string
  key_passphrase?: string
  idempotency_key: string
  /** Links the removal to a platform probe record. */
  probe_id?: number
  keep_data?: boolean
  keep_user?: boolean
  remove_user?: boolean
  /** Delete the platform record once the host is clean. */
  delete_record?: boolean
}

/** Body of `DELETE /probes/{id}`: strip the host, then drop the record. */
export interface DeleteProbePayload {
  remove_remote: boolean
  host?: string
  port?: number
  username?: string
  auth_type: 'password' | 'private_key'
  password?: string
  private_key?: string
  key_passphrase?: string
  keep_data?: boolean
  keep_user?: boolean
  remove_user?: boolean
}

export interface PreflightResult {
  compatible: boolean
  checks: { name: string; actual: string; required: string; pass: boolean; reason: string }[]
  os: string
  arch: string
  python: string
  capture_tool: string
  interfaces: string[]
  backend_connectivity: boolean
  sudo: boolean
  capability_score: number
  recommended_profile: string
}
