import { apiGet } from './client'

export interface AssessmentKpi {
  key: string
  label: string
  value: number | string
  denominator: number | string
  unit: string
  tone: string
}

export interface AssessmentGap {
  key: string
  label: string
  status: string
  detail: string
}

export interface AssessmentCaliber {
  mode: string
  tls_decryption: boolean
  permission_reported: boolean
  field_only_excluded: boolean
  probe_tmp_isolated: boolean
  region_table_present: boolean
  truncated: boolean
  notes: string[]
}

export interface AssessmentEnvelope {
  title: string
  conclusion: string
  kpis: AssessmentKpi[]
  sections: Record<string, unknown>
  gaps: AssessmentGap[]
  caliber: AssessmentCaliber
}

export type AssessmentKind =
  | 'overview'
  | 'classification'
  | 'exposure'
  | 'flow'
  | 'egress'
  | 'compliance'

export function getAssessment(kind: AssessmentKind): Promise<AssessmentEnvelope> {
  return apiGet<AssessmentEnvelope>(`/assessments/${kind}`)
}
