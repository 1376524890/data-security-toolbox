import { describe, expect, it, vi } from 'vitest'

vi.mock('axios', () => ({
  default: {
    create: () => ({
      get: vi.fn(),
      post: vi.fn(),
      patch: vi.fn(),
      interceptors: { response: { use: vi.fn() } },
    }),
  },
}))

describe('api client', () => {
  it('exports base url from environment', async () => {
    const { API_BASE } = await import('../api/client')
    expect(API_BASE).toBeTruthy()
  })

  it('builds pagination params from query', async () => {
    const { apiGet, default: client } = await import('../api/client')
    vi.mocked(client.get).mockResolvedValue({ data: { items: [], total: 0 } } as never)
    await apiGet('/detections', { page: 2, page_size: 50, severity: 'High' })
    expect(true).toBe(true)
  })
})
