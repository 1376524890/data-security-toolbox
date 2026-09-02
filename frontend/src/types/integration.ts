export interface IntegrationStatus {
  name: string
  adapter_version: string
  version: string
  installed: boolean
  enabled: boolean
  healthy: boolean
  runtime_version: string
  supported_types: string[]
  capabilities: string[]
  last_check: string
  status: string
  message: string
}
