import { describe, expect, it, vi } from 'vitest'

vi.mock('axios', () => ({
  default: {
    create: () => ({ get: vi.fn(), post: vi.fn() }),
  },
}))

describe('api client', () => {
  it('exports base url from environment', async () => {
    const { API_BASE } = await import('../api')
    expect(API_BASE).toBeTruthy()
  })
})

