export interface Task {
  id: number
  kind: string
  status: string
  progress: number
  current_stage: string
  log: string
  payload: Record<string, unknown>
  result: Record<string, unknown>
  error: string
  created_at: string
  started_at?: string | null
  finished_at?: string | null
}
