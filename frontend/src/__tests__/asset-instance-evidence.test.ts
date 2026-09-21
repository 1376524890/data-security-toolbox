/**
 * The operator requirement "回传原文" has to be visible, not just stored: the
 * evidence drawer shows the matched text the probe returned, and says plainly
 * when an older probe returned none instead of implying the value was empty.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import ElementPlus from 'element-plus'
import AssetInstanceDetail from '../modules/data-security/AssetInstanceDetail.vue'
import * as dataCatalog from '../api/dataCatalog'
import type { DetectionRow, EvidenceResponse, InstanceDetail } from '../api/dataCatalog'

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: '7' } }),
  useRouter: () => ({ back: vi.fn(), push: vi.fn() }),
}))
vi.mock('../api/dataCatalog', () => ({
  getAssetInstance: vi.fn(),
  getDetectionEvidence: vi.fn(),
}))

const detection = (overrides: Partial<DetectionRow> = {}): DetectionRow => ({
  id: 31, object_id: 5, instance_id: 7, probe_id: 2, source_kind: 'file', scan_id: 'scan-1',
  category: 'phone', subcategory: '', sensitivity_level: 'L3', severity: 'Medium',
  confidence: 0.9, sample_size: 1, sample_hit_count: 2, hit_count: 2,
  engine_version: '1.0.0', ruleset_version: '2026.09',
  first_seen_at: '2026-09-18T10:00:00', last_seen_at: '2026-09-19T10:00:00',
  ...overrides,
})

const detail = (overrides: Partial<InstanceDetail> = {}): InstanceDetail => ({
  id: 7, object_id: 5, probe_id: 2, source_kind: 'file', owner_key: 'probe:2',
  probe_name: 'probe-2', source_name: 'probe-2', host: '192.168.191.130',
  path: '/home/kali/customers.csv', name: 'customers.csv', instance_type: 'file',
  size: 128, content_hash: 'a'.repeat(64), hash_type: 'sha256', status: 'ACTIVE',
  owner: 'kali', group: 'kali', permission: '644', sensitivity: 'High', level: 'L3',
  level_source: 'builtin_default', categories: ['phone'], coverage: 'complete',
  termination_reason: '', ruleset_version: '2026.09', engine_version: '1.0.0',
  profile_version: '1', last_scan_id: 'scan-1', first_seen_at: '2026-09-18T10:00:00',
  last_seen_at: '2026-09-19T10:00:00', inode: 1, device: 2, mtime_ns: 1758000000000000000,
  object_key: 'sha256:abc', identity_kind: 'confirmed', last_scan_at: '2026-09-19T10:00:00',
  extra: {}, detections: [detection()], history_included: false,
  ...overrides,
})

const evidence = (matches: { value: string; context: string }[]): EvidenceResponse => ({
  detection: detection(),
  items: [{
    id: 91, rule_id: 'SD_PHONE_001', rule_name: '手机号', rule_source: 'builtin',
    recognizer: 'regex', evidence_type: 'value', field_name: 'phone', sheet_name: '',
    column_index: 1, confidence: 0.9, hit_count: 2, engine_version: '1.0.0',
    ruleset_version: '2026.09', matches,
  }],
  count: 1,
  matches_returned: matches.length,
  note: '原文由探针回传，每命中最多 3 条。',
})

let app: App
let host: HTMLElement

const flush = async () => {
  for (let index = 0; index < 4; index += 1) await Promise.resolve()
  await nextTick()
}

const openEvidenceDrawer = async () => {
  const button = Array.from(host.querySelectorAll('button'))
    .find((item) => item.textContent?.trim() === '证据')
  expect(button, 'the detection row exposes its evidence').toBeTruthy()
  button!.click()
  await flush()
  const expand = document.body.querySelector<HTMLElement>('.el-table__expand-icon')
  expect(expand, 'the evidence rows can be expanded').toBeTruthy()
  expand!.click()
  await flush()
}

/** Reload the page with another instance: the mock only answers the next read. */
const reload = async (next: InstanceDetail) => {
  vi.mocked(dataCatalog.getAssetInstance).mockResolvedValue(next)
  const button = Array.from(host.querySelectorAll('button'))
    .find((item) => item.textContent?.trim() === '刷新')
  expect(button, 'the page can be reloaded').toBeTruthy()
  button!.click()
  await flush()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.mocked(dataCatalog.getAssetInstance).mockResolvedValue(detail())
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(AssetInstanceDetail)
  app.use(ElementPlus)
  app.mount(host)
})

afterEach(() => {
  app.unmount()
  host.remove()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('asset instance evidence drawer', () => {
  it('shows the matched原文 the probe returned, value and its line', async () => {
    vi.mocked(dataCatalog.getDetectionEvidence).mockResolvedValue(evidence([
      { value: '13800138000', context: 'phone=13800138000,id=110101199003071234' },
    ]))

    await openEvidenceDrawer()

    expect(dataCatalog.getDetectionEvidence).toHaveBeenCalledWith(31)
    expect(host.querySelector('.toolbar-title')?.textContent).toContain('实例 #7')
    expect(document.body.textContent).toContain('13800138000')
    expect(document.body.textContent).toContain('phone=13800138000,id=110101199003071234')
    expect(document.body.textContent).toContain('1 条')
  })

  it('says the原文 was not returned instead of pretending there was none', async () => {
    vi.mocked(dataCatalog.getDetectionEvidence).mockResolvedValue(evidence([]))

    await openEvidenceDrawer()

    expect(document.body.textContent).toContain('没有回传原文')
    expect(document.body.textContent).toContain('0 条')
  })
})

describe('instance source label', () => {
  it('names the shared file source instead of calling it a probe', async () => {
    await reload(detail({
      probe_id: null as unknown as number, source_kind: 'file_share',
      owner_key: 'file-source:1', source_name: 'kali-ftp-share', probe_name: '',
      host: '192.168.191.130',
    }))

    expect(host.textContent).toContain('共享文件采集')
    expect(host.textContent).toContain('file-source:1')
    expect(host.textContent).toContain('kali-ftp-share（192.168.191.130）')
    expect(host.textContent).not.toContain('探针文件采集')
    expect(host.textContent).not.toContain('probe_id=')
  })

  it('names the target database and keeps the probe row for a probe instance', async () => {
    await reload(detail({
      probe_id: null as unknown as number, source_kind: 'database',
      owner_key: 'db:3', source_name: 'kali-mariadb', probe_name: '', host: '192.168.191.130',
    }))
    expect(host.textContent).toContain('数据库直连盘点')
    expect(host.textContent).toContain('kali-mariadb（192.168.191.130）')

    await reload(detail())
    expect(host.textContent).toContain('探针文件采集')
    expect(host.textContent).toContain('probe_id=2')
  })
})
