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
