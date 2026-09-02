import { describe, expect, it } from 'vitest'
import { severityColors, statusColors, nodeTypeColors } from '../utils/mapping'

describe('design mapping', () => {
  it('defines severity colors', () => {
    expect(Object.keys(severityColors).sort()).toEqual(['Critical', 'High', 'Low', 'Medium'])
  })

  it('maps integration status', () => {
    expect(statusColors.ready).toBeTruthy()
    expect(statusColors.unavailable).toBeTruthy()
  })

  it('maps graph node types', () => {
    expect(nodeTypeColors.host).toBeTruthy()
    expect(nodeTypeColors.ioc).toBeTruthy()
  })
})
