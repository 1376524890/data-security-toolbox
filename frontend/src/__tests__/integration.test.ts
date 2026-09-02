import { describe, expect, it } from 'vitest'
import type { IntegrationStatus } from '../types/integration'

function healthLabel(item: IntegrationStatus): string {
  if (!item.enabled) return 'disabled'
  if (!item.healthy) return 'unavailable'
  return item.status
}

describe('integration status', () => {
  it('maps enabled healthy integration', () => {
    expect(healthLabel({ enabled: true, healthy: true, status: 'ready' } as IntegrationStatus)).toBe('ready')
  })

  it('maps disabled integration', () => {
    expect(healthLabel({ enabled: false, healthy: false, status: 'ready' } as IntegrationStatus)).toBe('disabled')
  })
})
