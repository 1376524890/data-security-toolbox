import { apiGet } from './client'

export interface CryptoProfileConfig {
  algorithms: string[]
  cipherSuites: string[]
  protocols: string[]
  keyLengths: number[]
  keyManagement: { rotationDays?: number; storage?: string; useHardware?: boolean }
}

export interface CryptoPasswordSignal {
  type: 'weak_auth' | 'weak_password' | 'crypto' | 'secret' | 'info'
  service?: string
  port?: number
  level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Pass'
  detail: string
  recommendation?: string
}

export interface CryptoProbeProfile {
  probe_id: number
  probe_name: string
  hostname: string
  ip_address: string
  config: CryptoProfileConfig
  passwordTypes: string[]
  passwordSignals: CryptoPasswordSignal[]
  tlsHandshakeCount: number
  serviceCount: number
  coverage: Record<string, 'detected' | 'inferred' | 'default'>
  sources: string[]
}

export function getCryptoProbeProfile(probeId: number): Promise<CryptoProbeProfile> {
  return apiGet('/crypto/probe-profile', { probe_id: probeId })
}
