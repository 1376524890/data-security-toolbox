import { describe, expect, it } from 'vitest'
import { maskSensitiveValue, maskRecord } from '../utils/mask'

describe('sensitive data mask', () => {
  it('masks phone', () => {
    expect(maskSensitiveValue('13800138000')).toBe('138****8000')
  })

  it('masks id card', () => {
    expect(maskSensitiveValue('110101199003071234')).toBe('110101********1234')
  })

  it('masks bank card', () => {
    expect(maskSensitiveValue('6222021234567890123')).toBe('6222***********0123')
  })

  it('masks secret and password', () => {
    expect(maskSensitiveValue('sk-1234567890abcdef')).toContain('****')
    expect(maskSensitiveValue('password=admin123')).toContain('****')
  })

  it('masks nested records', () => {
    const value = maskRecord({ phone: '13800138000', nested: { token: 'abc' } })
    expect(value).toEqual({ phone: '138****8000', nested: { token: '****' } })
  })
})
