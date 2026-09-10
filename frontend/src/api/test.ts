import { apiGet, apiPost } from './client'

export interface TestStatus {
  present: boolean
  probe_ids: number[]
  probes: number
  files: number
  pcaps: number
  assets: number
}

export function importTestData(): Promise<{ probe_id: number; probe_name: string; files: number; pcaps: number }> {
  return apiPost('/test/import')
}

export function clearTestData(): Promise<Record<string, number>> {
  return apiPost('/test/clear')
}

export function getTestStatus(): Promise<TestStatus> {
  return apiGet('/test/status')
}

// sessionStorage flag drives "refresh restores original" (auto-clear on next load).
const FLAG = 'dst_test_imported'
export function markTestImported(): void { sessionStorage.setItem(FLAG, '1') }
export function consumeTestImported(): boolean {
  const v = sessionStorage.getItem(FLAG)
  if (v) { sessionStorage.removeItem(FLAG); return true }
  return false
}
