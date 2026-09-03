import { describe, expect, it } from 'vitest'
import { incidentStages, type Incident } from '../types/incident'
import { formatBytes, formatDateTime, formatDuration, clamp } from '../utils/format'
import { flatMenu, menuGroups } from '../router/menu'

describe('incident stages', () => {
  it('extracts stages from evidence', () => {
    const inc = { id: 1, title: 't', severity: 'High', confidence: 0.8, status: 'open', findings: { items: [] }, evidence: { stages: ['recon', 'c2', 'exfil'] }, risk_score: 80, risk_level: 'High', timestamp: '2026-01-01', created_at: '2026-01-01' } as unknown as Incident
    expect(incidentStages(inc)).toEqual(['recon', 'c2', 'exfil'])
  })
  it('returns empty when no stages', () => {
    const inc = { id: 1, title: 't', severity: 'High', confidence: 0.8, status: 'open', findings: { items: [] }, evidence: {}, risk_score: 80, risk_level: 'High', timestamp: '2026-01-01', created_at: '2026-01-01' } as unknown as Incident
    expect(incidentStages(inc)).toEqual([])
  })
})

describe('format utils', () => {
  it('formats bytes', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytes(1048576)).toBe('1.0 MB')
  })
  it('formats duration', () => {
    expect(formatDuration(30)).toBe('30.00s')
    expect(formatDuration(90)).toBe('1m 30s')
  })
  it('clamps values', () => {
    expect(clamp(150, 0, 100)).toBe(100)
    expect(clamp(-5, 0, 100)).toBe(0)
  })
  it('formats datetime', () => {
    expect(formatDateTime(null)).toBe('-')
    expect(formatDateTime(0)).toBeTruthy()
  })
})

describe('navigation menu', () => {
  it('produces a flat route list covering all groups', () => {
    const flat = flatMenu()
    expect(flat.length).toBeGreaterThanOrEqual(20)
    expect(flat.some((m) => m.path === '/network/pcap')).toBe(true)
    expect(flat.some((m) => m.path === '/engines/zeek')).toBe(true)
  })
  it('defines security operations group', () => {
    const groups = menuGroups.filter((g) => 'group' in g).map((g) => (g as any).group)
    expect(groups).toContain('安全运营')
    expect(groups).toContain('网络分析')
    expect(groups).toContain('资产与数据安全')
  })
})
