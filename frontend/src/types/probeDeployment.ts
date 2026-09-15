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
  | 'FAILED'
  | 'CANCELLED'

export interface ProbeDeployment {
  backend_url?: string
  id: number
  name: string
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
}

export interface CreateDeploymentPayload extends PreflightPayload {
  name: string
  idempotency_key: string
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
