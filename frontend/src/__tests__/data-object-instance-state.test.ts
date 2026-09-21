import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { computed, createApp, defineComponent, nextTick, ref, type App } from 'vue'
import { useDataObjectDetail } from '../modules/data-security/composables/useDataObjectDetail'
import { useAssetInstanceDetail } from '../modules/data-security/composables/useAssetInstanceDetail'
import type { AssetInstanceRow, DetectionRow, EvidenceResponse, InstanceDetail, ObjectDetail } from '../api/dataCatalog'
import * as catalog from '../api/dataCatalog'

vi.mock('../api/dataCatalog', () => ({
  getDataObject: vi.fn(), listObjectDetections: vi.fn(),
  getAssetInstance: vi.fn(), getDetectionEvidence: vi.fn(),
}))

const detection = (id: number, category = 'email'): DetectionRow => ({
  id, object_id: 5, instance_id: 9, probe_id: 1, source_kind: 'file', scan_id: 'scan-1',
  category, subcategory: '',
  sensitivity_level: 'L3', severity: 'High', confidence: 0.9, sample_size: 10,
  sample_hit_count: 2, hit_count: 4, engine_version: '1', ruleset_version: '2',
  first_seen_at: '2026-09-18T10:00:00', last_seen_at: '2026-09-19T10:00:00',
})

const instance = (overrides: Partial<InstanceDetail> = {}): InstanceDetail => ({
  id: 9, object_id: 5, probe_id: 1, source_kind: 'file', owner_key: 'probe:1',
  probe_name: 'test123', source_name: 'test123', host: '192.168.191.130',
  path: '/srv/data/a.csv', name: 'a.csv', instance_type: 'file', size: 2048,
  content_hash: 'a'.repeat(64), hash_type: 'sha256', status: 'ACTIVE', owner: 'root',
  group: 'root', permission: '644', sensitivity: 'High', level: 'L3',
  level_source: 'builtin_default', categories: ['email'], coverage: 'complete',
  termination_reason: '', ruleset_version: '2', engine_version: '1', profile_version: '1',
  last_scan_id: 'scan-1', first_seen_at: '2026-09-18T10:00:00', last_seen_at: '2026-09-19T10:00:00',
  inode: 1, device: 2, mtime_ns: 1758000000000000000, object_key: 'sha256:abc',
  identity_kind: 'confirmed', last_scan_at: '2026-09-19T10:00:00', extra: {},
  detections: [detection(31)], history_included: false,
  ...overrides,
})

const object = (overrides: Partial<ObjectDetail> = {}): ObjectDetail => ({
  id: 5, object_key: 'sha256:abc', object_type: 'file', content_hash: 'a'.repeat(64),
  hash_type: 'sha256', partial_version: '', identity_kind: 'confirmed', identity_confidence: 100,
  active_instance_count: 2, instance_count: 3, size: 2048, categories: ['email'], level: 'L3',
  level_source: 'builtin_default', sensitivity: 'High', first_seen_at: '2026-09-18T10:00:00',
  last_seen_at: '2026-09-19T10:00:00', partial_layout: {}, extra: {},
  instances: [instance() as unknown as AssetInstanceRow],
  ...overrides,
})

const evidence: EvidenceResponse = {
  detection: detection(31), items: [], count: 0, matches_returned: 0,
  note: '旧版探针只上报计数',
}

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async <T>(composable: () => T): Promise<T> => {
  let state: T
  const Harness = defineComponent({
    setup() {
      state = composable()
      return () => null
    },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(Harness)
  app.mount(host)
  await flushing()
  return state!
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(catalog.getDataObject).mockResolvedValue(object())
  vi.mocked(catalog.listObjectDetections).mockResolvedValue({ items: [detection(31)], total: 21, page: 1, page_size: 10 })
  vi.mocked(catalog.getAssetInstance).mockResolvedValue(instance())
  vi.mocked(catalog.getDetectionEvidence).mockResolvedValue(evidence)
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('data object detail state', () => {
  it('loads the object and its first detection page for the route id', async () => {
    const state = await mount(() => useDataObjectDetail(computed(() => 5)))
    expect(catalog.getDataObject).toHaveBeenCalledWith(5)
    expect(catalog.listObjectDetections).toHaveBeenCalledWith(5, { page: 1, page_size: 10 })
    expect(state.detail.value?.id).toBe(5)
    expect(state.detections.value.map((item) => item.id)).toEqual([31])
    expect(state.detectionTotal.value).toBe(21)
    expect(state.loading.value).toBe(false)
  })

  it('moves the detection pager and reloads that page', async () => {
    const state = await mount(() => useDataObjectDetail(computed(() => 5)))
    vi.mocked(catalog.listObjectDetections).mockClear()
    vi.mocked(catalog.getDataObject).mockClear()
    state.setDetectionPage(3)
    await flushing()
    expect(state.detectionPage.value).toBe(3)
    expect(catalog.listObjectDetections).toHaveBeenCalledWith(5, { page: 3, page_size: 10 })
    expect(catalog.getDataObject).not.toHaveBeenCalled()
  })

  it('words the identity without calling a lone partial fingerprint a copy', async () => {
    const state = await mount(() => useDataObjectDetail(computed(() => 5)))
    expect(state.identityText.value).toContain('内容一致')
    state.detail.value = object({ identity_kind: 'candidate', active_instance_count: 2 })
    expect(state.identityText.value).toContain('疑似副本')
    state.detail.value = object({ identity_kind: 'candidate', active_instance_count: 1 })
    expect(state.identityText.value).toContain('待确认身份')
    state.detail.value = object({ identity_kind: 'scoped' })
    expect(state.identityText.value).toContain('作用域内标识')
  })

  it('opens the evidence drawer and reports a failure without closing it', async () => {
    const state = await mount(() => useDataObjectDetail(computed(() => 5)))
    await state.openEvidence(detection(31))
    expect(catalog.getDetectionEvidence).toHaveBeenCalledWith(31)
    expect(state.evidenceOpen.value).toBe(true)
    expect(state.evidence.value?.note).toBe('旧版探针只上报计数')

    vi.mocked(catalog.getDetectionEvidence).mockRejectedValue(new Error('证据不可用'))
    await state.openEvidence(detection(32))
    expect(state.evidenceError.value).toBe('证据不可用')
    expect(state.evidence.value).toBeNull()
    expect(state.evidenceOpen.value).toBe(true)
    expect(state.evidenceLoading.value).toBe(false)
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(catalog.getDataObject).mockRejectedValue(new Error('对象不存在'))
    const state = await mount(() => useDataObjectDetail(computed(() => 404)))
    expect(state.error.value).toBe('对象不存在')
    expect(state.loading.value).toBe(false)
    expect(state.detail.value).toBeNull()
  })
})

describe('asset instance detail state', () => {
  it('loads the instance with the history flag the toggle carries', async () => {
    const state = await mount(() => useAssetInstanceDetail(computed(() => 9)))
    expect(catalog.getAssetInstance).toHaveBeenCalledWith(9, false)
    expect(state.detail.value?.id).toBe(9)
    expect(state.includeHistory.value).toBe(false)

    vi.mocked(catalog.getAssetInstance).mockResolvedValue(instance({ history_included: true }))
    await state.toggleHistory()
    expect(state.includeHistory.value).toBe(true)
    expect(catalog.getAssetInstance).toHaveBeenLastCalledWith(9, true)
  })

  it('opens the evidence drawer for an instance detection', async () => {
    const state = await mount(() => useAssetInstanceDetail(computed(() => 9)))
    await state.openEvidence(detection(31))
    expect(catalog.getDetectionEvidence).toHaveBeenCalledWith(31)
    expect(state.evidenceOpen.value).toBe(true)
    expect(state.evidenceLoading.value).toBe(false)
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(catalog.getAssetInstance).mockRejectedValue(new Error('实例不存在'))
    const state = await mount(() => useAssetInstanceDetail(computed(() => 404)))
    expect(state.error.value).toBe('实例不存在')
    expect(state.loading.value).toBe(false)
  })
})
