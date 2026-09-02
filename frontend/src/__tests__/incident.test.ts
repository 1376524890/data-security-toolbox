import { describe, expect, it } from 'vitest'
import type { Incident } from '../types/incident'

function stages(incident: Incident): string[] {
  return Array.isArray(incident.evidence?.stages) ? incident.evidence.stages.map(String) : []
}

describe('incident mapping', () => {
  it('extracts findings count and stages', () => {
    const incident = {
      id: 1,
      title: 't',
      severity: 'High',
      confidence: 0.8,
      status: 'open',
      findings: { items: [{}, {}] },
      evidence: { stages: ['recon', 'exploit'] },
      risk_score: 80,
      risk_level: 'High',
      timestamp: '2026-01-01T00:00:00Z',
      created_at: '2026-01-01T00:00:00Z',
    } as unknown as Incident
    expect(incident.findings.items?.length).toBe(2)
    expect(stages(incident)).toEqual(['recon', 'exploit'])
  })
})
