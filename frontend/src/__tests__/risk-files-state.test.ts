import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ElMessage } from 'element-plus'
import {
  downloadRiskFile, getRiskContent, getRiskPoints, listRiskFiles,
} from '../api/riskFiles'
import { useRiskFiles } from '../modules/data-security/composables/useRiskFiles'
import type { RiskFile, RiskPoints } from '../api/riskFiles'

vi.mock('../api/riskFiles', () => ({
  listRiskFiles: vi.fn(), getRiskPoints: vi.fn(), getRiskContent: vi.fn(), downloadRiskFile: vi.fn(),
}))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

beforeEach(() => vi.clearAllMocks())
afterEach(() => vi.restoreAllMocks())

const file: RiskFile = {
  id: 7, object_id: 3, name: 'contacts.csv', path: '/share/contacts.csv',
  source_kind: 'file_share', source_name: '共享', host: 'files', level: 'L3',
  sensitivity: 'High', categories: ['phone'], size: 2048, coverage: 'complete',
  termination_reason: 'complete', status: 'ACTIVE', permission: '0o644',
  last_seen_at: '', risk_point_count: 1, risk_hit_count: 3,
}

const points: RiskPoints = {
  instance_id: 7, object_id: 3, path: file.path, name: file.name, level: 'L3',
  items: [{
    detection: { id: 11, category: 'phone', subcategory: '', sensitivity_level: 'L3',
      severity: 'High', confidence: 0.9, hit_count: 3, first_seen_at: '', last_seen_at: '' },
    evidence: [{ id: 1, rule_id: 'SD_PHONE_001', rule_name: '手机号', rule_source: 'builtin',
      recognizer: 'regex', evidence_type: 'regex', field_name: 'phone', sheet_name: '',
      column_index: null, confidence: 0.9, hit_count: 3,
      matches: [{ value: '13800138000', context: 'ops,13800138000' }] }],
  }],
  detection_count: 1, hit_count: 3, matches_returned: 1, note: '',
}

describe('risk files state', () => {
  it('loads the risk points as soon as a row is opened', async () => {
    vi.mocked(listRiskFiles).mockResolvedValue({ items: [file], total: 1, page: 1, page_size: 50 })
    vi.mocked(getRiskPoints).mockResolvedValue(points)
    const state = useRiskFiles()
    await state.load()
    expect(state.rows.value).toHaveLength(1)
    await state.open(file)
    expect(getRiskPoints).toHaveBeenCalledWith(7)
    expect(state.riskPoints.value?.items[0].evidence[0].matches[0].value).toBe('13800138000')
    expect(state.drawer.value).toBe(true)
    // The browser read is a separate, explicit action - browsing is not implied
    // by looking at the risk points.
    expect(getRiskContent).not.toHaveBeenCalled()
    expect(state.browse.value).toBeNull()
  })

  it('browses masked first and only reveals everything on request', async () => {
    vi.mocked(listRiskFiles).mockResolvedValue({ items: [file], total: 1, page: 1, page_size: 50 })
    vi.mocked(getRiskPoints).mockResolvedValue(points)
    vi.mocked(getRiskContent)
      .mockResolvedValueOnce({ instance_id: 7, path: file.path, name: file.name, source_name: '共享',
        size: 2048, preview_bytes: 20, truncated: false, encoding: 'utf-8',
        text: 'ops,138***0000', hex: null, masked: true, masked_values: 1 })
      .mockResolvedValueOnce({ instance_id: 7, path: file.path, name: file.name, source_name: '共享',
        size: 2048, preview_bytes: 20, truncated: false, encoding: 'utf-8',
        text: 'ops,13800138000', hex: null, masked: false, masked_values: 1 })
    const state = useRiskFiles()
    await state.open(file)

    await state.browseContent()
    expect(getRiskContent).toHaveBeenLastCalledWith(7, true)
    expect(state.browse.value?.masked).toBe(true)
    expect(state.revealAll.value).toBe(false)

    await state.browseContent(false)
    expect(getRiskContent).toHaveBeenLastCalledWith(7, false)
    expect(state.browse.value?.text).toBe('ops,13800138000')
    expect(state.revealAll.value).toBe(true)
  })

  it('asks the server for the rows that were not read in full', async () => {
    vi.mocked(listRiskFiles).mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 })
    const state = useRiskFiles()
    // The generated report points an operator here, so the page has to be able
    // to ask the question the report asks: which objects did we not read?
    state.filters.coverage = 'incomplete'
    await state.load()
    expect(listRiskFiles).toHaveBeenLastCalledWith(expect.objectContaining({ coverage: 'incomplete' }))
  })

  it('reports a failed source read without losing the risk points already shown', async () => {
    vi.mocked(listRiskFiles).mockResolvedValue({ items: [file], total: 1, page: 1, page_size: 50 })
    vi.mocked(getRiskPoints).mockResolvedValue(points)
    vi.mocked(getRiskContent).mockRejectedValue(new Error('read_failed'))
    const state = useRiskFiles()
    await state.open(file)
    await state.browseContent()
    expect(state.browseError.value).toContain('read_failed')
    expect(state.browse.value).toBeNull()
    expect(state.riskPoints.value?.detection_count).toBe(1)
  })

  it('reports a download failure in place instead of navigating away', async () => {
    vi.mocked(listRiskFiles).mockResolvedValue({ items: [file], total: 1, page: 1, page_size: 50 })
    vi.mocked(getRiskPoints).mockResolvedValue(points)
    vi.mocked(downloadRiskFile).mockRejectedValue(new Error('read_failed'))
    const state = useRiskFiles()
    await state.open(file)
    await state.download()
    expect(downloadRiskFile).toHaveBeenCalledWith(7, 'contacts.csv')
    expect(ElMessage.error).toHaveBeenCalled()
  })

  it('clears the previous file reads when another row is opened', async () => {
    vi.mocked(listRiskFiles).mockResolvedValue({ items: [file], total: 1, page: 1, page_size: 50 })
    vi.mocked(getRiskPoints).mockResolvedValue(points)
    vi.mocked(getRiskContent).mockResolvedValue({ instance_id: 7, path: file.path, name: file.name,
      source_name: '共享', size: 1, preview_bytes: 1, truncated: false, encoding: 'utf-8',
      text: 'x', hex: null, masked: true, masked_values: 0 })
    const state = useRiskFiles()
    await state.open(file)
    await state.browseContent()
    expect(state.browse.value).not.toBeNull()
    await state.open({ ...file, id: 8 })
    expect(state.browse.value).toBeNull()
    expect(state.browseError.value).toBe('')
    expect(state.revealAll.value).toBe(false)
  })
})
