import { describe, expect, it } from 'vitest'
import { assessCrypto, defaultCryptoConfig, weakCryptoConfig } from '../modules/tools/cryptoAssessment'
import { analyzeComplexity, defaultCodeSample } from '../modules/tools/complexityAnalysis'

describe('商用密码应用安全性评估', () => {
  it('合规配置整体评分高', () => {
    const result = assessCrypto(JSON.parse(JSON.stringify(defaultCryptoConfig)))
    expect(result.overallScore).toBeGreaterThanOrEqual(85)
    expect(result.sm4RoundTrip).toBe(true)
    expect(result.findings.some((f) => f.level === 'Pass')).toBe(true)
  })

  it('弱配置识别出违规项', () => {
    const result = assessCrypto(JSON.parse(JSON.stringify(weakCryptoConfig)))
    expect(result.overallScore).toBeLessThan(60)
    expect(result.summary.violations).toBeGreaterThan(0)
    expect(result.findings.some((f) => f.level === 'Critical')).toBe(true)
  })

  it('探针画像自动填充后命中弱算法与无认证信号', () => {
    // 模拟后端 /crypto/probe-profile 对 gb-pc 探针的返回，前端据此自动填充并评估
    const autoConfig = {
      algorithms: ['RSA', 'SHA256', 'AES-128', 'AES-256', 'SHA384', 'ECDSA', 'CHACHA20', 'Ed25519'],
      cipherSuites: [
        'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_CBC_SHA',
      ],
      protocols: ['TLSv1.2', 'TLSv1.3'],
      keyLengths: [128, 256, 2048],
      keyManagement: { rotationDays: 60, storage: 'HSM', useHardware: true },
      sm4Key: '0123456789abcdeffedcba9876543210',
      passwordSignals: [
        { type: 'weak_auth', service: 'mysql', port: 3306, level: 'Critical', detail: 'MYSQL（端口 3306）存在无认证/匿名访问风险：5.7.40 noauth' },
      ],
    } as Parameters<typeof assessCrypto>[0]
    const result = assessCrypto(autoConfig)
    expect(result.findings.some((f) => f.dimension === '密码/认证' && f.level === 'Critical')).toBe(true)
    expect(result.findings.some((f) => f.title.includes('RSA'))).toBe(true)
    expect(result.summary.weakItems).toBeGreaterThanOrEqual(1)
    expect(result.overallScore).toBeLessThan(90)
  })

  it('输出维度分数在 0-100', () => {
    const result = assessCrypto(JSON.parse(JSON.stringify(defaultCryptoConfig)))
    expect(result.complianceScore).toBeGreaterThanOrEqual(0)
    expect(result.correctnessScore).toBeLessThanOrEqual(100)
    expect(result.effectivenessScore).toBeGreaterThanOrEqual(0)
  })
})

describe('代码算法复杂度分析', () => {
  it('分析示例代码识别循环', () => {
    const result = analyzeComplexity(defaultCodeSample, 'javascript')
    expect(result.loops).toBeGreaterThan(0)
    expect(result.bigO.time).toBeTruthy()
    expect(result.functions.length).toBeGreaterThan(0)
  })

  it('空代码返回占位', () => {
    const result = analyzeComplexity('', 'javascript')
    expect(result.bigO.time).toBe('-')
    expect(result.notes.length).toBeGreaterThan(0)
  })

  it('Python 启发式分析', () => {
    const result = analyzeComplexity('def f(arr):\n    for x in arr:\n        for y in arr:\n            print(x, y)', 'python')
    expect(result.bigO.time).toBe('O(n²)')
  })
})
