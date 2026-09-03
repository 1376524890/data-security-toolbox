// 商用密码应用安全性评估 — 合规性 / 正确性 / 有效性
// 采用开源工具与方法：sm-crypto(SM2/SM3/SM4)、OpenSSL 密码套件规范、GM/T & GB/T 标准规则集。

import { sm3, sm4 } from 'sm-crypto'

export interface CryptoConfig {
  algorithms: string[]
  cipherSuites: string[]
  protocols: string[]
  keyLengths: number[]
  keyManagement: { rotationDays?: number; storage?: string; useHardware?: boolean }
  sm4Key?: string
}

export interface CryptoFinding {
  level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Pass'
  dimension: '合规性' | '正确性' | '有效性'
  title: string
  detail: string
  standard: string
  recommendation: string
}

export interface CryptoAssessmentResult {
  complianceScore: number
  correctnessScore: number
  effectivenessScore: number
  overallScore: number
  level: string
  findings: CryptoFinding[]
  summary: { compliant: number; violations: number; weakItems: number }
  sm4RoundTrip: boolean
  sm3Digest: string
  standards: string[]
}

// 弱算法 / 不推荐算法
const WEAK_HASH = ['MD5', 'MD4', 'SHA1', 'SHA-1', 'RIPEMD']
const WEAK_SYMMETRIC = ['DES', '3DES', 'TRIPLE_DES', 'RC4', 'RC2', 'BLOWFISH']
const WEAK_ASYMMETRIC = ['RSA', 'DSA', 'DH']
const STRONG_ASYMMETRIC = ['SM2', 'ECDSA', 'ED25519', 'EC']
const STRONG_SYMMETRIC = ['SM4', 'AES', 'AES-128', 'AES-256', 'CHACHA20']
const STRONG_HASH = ['SM3', 'SHA256', 'SHA-256', 'SHA384', 'SHA512']
// 密码套件中的弱项
const WEAK_CIPHER_TOKENS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON', 'CBC', 'MD5', 'SHA1', 'SHA-1']
// 协议版本
const DEPRECATED_PROTOCOLS = ['TLSV1', 'TLSV1.0', 'TLSV1.1', 'SSLV2', 'SSLV3', 'SSL']
const RECOMMENDED_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']

function norm(s: string): string {
  return s.toUpperCase().replace(/[\s_-]/g, '')
}

function hasAny(list: string[], tokens: string[]): boolean {
  return list.some((item) => tokens.some((t) => norm(item).includes(norm(t))))
}

function detectAlgoFamily(algo: string): string {
  const a = norm(algo)
  if (WEAK_HASH.some((w) => a.includes(norm(w)))) return 'weak-hash'
  if (WEAK_SYMMETRIC.some((w) => a.includes(norm(w)))) return 'weak-symmetric'
  if (WEAK_ASYMMETRIC.some((w) => a.includes(norm(w)))) return 'weak-asymmetric'
  if (STRONG_ASYMMETRIC.some((w) => a.includes(norm(w)))) return 'strong-asymmetric'
  if (STRONG_SYMMETRIC.some((w) => a.includes(norm(w)))) return 'strong-symmetric'
  if (STRONG_HASH.some((w) => a.includes(norm(w)))) return 'strong-hash'
  return 'unknown'
}

export function assessCrypto(config: CryptoConfig): CryptoAssessmentResult {
  const findings: CryptoFinding[] = []
  const algorithms = config.algorithms || []
  const suites = config.cipherSuites || []
  const protocols = config.protocols || []
  const keyLengths = config.keyLengths || []
  const km = config.keyManagement || {}

  // ---- 合规性：算法与密码套件 ----
  let complianceScore = 100
  const weakAlgos = algorithms.filter((a) => ['weak-hash', 'weak-symmetric', 'weak-asymmetric'].includes(detectAlgoFamily(a)))
  if (weakAlgos.length) {
    complianceScore -= weakAlgos.length * 18
    weakAlgos.forEach((a) => findings.push({
      level: 'Critical', dimension: '合规性', title: `使用弱算法 ${a}`,
      detail: `算法 ${a} 属于已弃用或不安全的密码算法，违反商用密码应用合规要求。`,
      standard: 'GB/T 39786-2021 / GM/T 0054', recommendation: `使用 SM2/SM3/SM4 或 AES-256、SHA-256 等受认可的算法替代 ${a}。`,
    }))
  }
  const strongAlgos = algorithms.filter((a) => ['strong-asymmetric', 'strong-symmetric', 'strong-hash'].includes(detectAlgoFamily(a)))
  if (!strongAlgos.length && !weakAlgos.length) {
    complianceScore -= 15
    findings.push({ level: 'Medium', dimension: '合规性', title: '未识别到受认可的算法', detail: '未检测到 SM 系列或国际标准算法，无法确认密码应用合规性。', standard: 'GM/T 0001 / GB/T 39786', recommendation: '配置 SM2/SM3/SM4 或 AES-256、SHA-256 等受认可算法。' })
  }

  // 密码套件
  const weakSuites = suites.filter((s) => WEAK_CIPHER_TOKENS.some((t) => norm(s).includes(norm(t))))
  if (weakSuites.length) {
    complianceScore -= weakSuites.length * 10
    weakSuites.forEach((s) => findings.push({
      level: 'High', dimension: '合规性', title: '密码套件存在弱项', detail: `密码套件 ${s} 使用了 RC4/3DES/CBC/MD5/SHA1 等弱项或匿名/导出套件。`,
      standard: 'GB/T 39786-2021', recommendation: '禁用该套件，改用 ECDHE/SM2 与 AES-GCM/SM4-GCM 套件。',
    }))
  }

  // 协议版本
  const deprecated = protocols.filter((p) => DEPRECATED_PROTOCOLS.includes(norm(p)))
  if (deprecated.length) {
    complianceScore -= deprecated.length * 15
    deprecated.forEach((p) => findings.push({
      level: 'Critical', dimension: '合规性', title: `使用已弃用协议 ${p}`,
      detail: `协议 ${p} 已存在已知漏洞（如 POODLE/Heartbleed），不再满足密码应用安全要求。`,
      standard: 'GB/T 39786-2021 / GM/T 0024', recommendation: `禁用 ${p}，仅启用 TLSv1.2 / TLSv1.3。`,
    }))
  }
  const recommended = protocols.filter((p) => RECOMMENDED_PROTOCOLS.some((r) => norm(p).includes(norm(r))))
  if (recommended.length) {
    findings.push({ level: 'Pass', dimension: '合规性', title: `使用推荐协议 ${recommended.join(', ')}`, detail: '协议版本符合商用密码应用要求。', standard: 'GB/T 39786-2021', recommendation: '保持现状。' })
  }

  // ---- 正确性：SM3 / SM4 测试向量（开源 sm-crypto） ----
  let correctnessScore = 100
  let sm4RoundTrip = false
  let sm3Digest = ''
  const key = config.sm4Key || '0123456789abcdeffedcba9876543210'
  try {
    const ct = sm4.encrypt('data-security-toolbox', key)
    const pt = sm4.decrypt(ct, key)
    sm4RoundTrip = pt === 'data-security-toolbox'
    sm3Digest = sm3('data-security-toolbox')
    if (!sm4RoundTrip) {
      correctnessScore -= 40
      findings.push({ level: 'Critical', dimension: '正确性', title: 'SM4 加解密回环校验失败', detail: 'SM4 加密后无法正确解密，算法实现或密钥配置存在正确性问题。', standard: 'GM/T 0002', recommendation: '检查 SM4 密钥长度（128bit）与实现是否正确。' })
    } else {
      findings.push({ level: 'Pass', dimension: '正确性', title: 'SM4 加解密回环校验通过', detail: 'SM4 加密-解密回环验证正确，算法实现正确。', standard: 'GM/T 0002', recommendation: '保持现状。' })
    }
    findings.push({ level: 'Pass', dimension: '正确性', title: 'SM3 摘要计算正常', detail: `SM3("data-security-toolbox") = ${sm3Digest.slice(0, 16)}...`, standard: 'GM/T 0004', recommendation: '保持现状。' })
  } catch (e) {
    correctnessScore -= 60
    findings.push({ level: 'Critical', dimension: '正确性', title: 'SM3/SM4 计算异常', detail: String(e), standard: 'GM/T 0002 / GM/T 0004', recommendation: '检查密码库实现。' })
  }

  // ---- 有效性：密钥长度与密钥管理 ----
  let effectivenessScore = 100
  const weakKeys = keyLengths.filter((k) => (k > 0 && k < 128) || k === 512 || k === 1024)
  if (weakKeys.length) {
    effectivenessScore -= weakKeys.length * 12
    weakKeys.forEach((k) => findings.push({
      level: 'High', dimension: '有效性', title: `密钥长度不足 ${k}bit`, detail: `密钥长度 ${k}bit 低于推荐强度，易受暴力破解/量子攻击。`,
      standard: 'GM/T 0005 / GB/T 39786', recommendation: `RSA/ECDSA 至少 2048bit（SM2 为 256bit），对称加密至少 128bit。`,
    }))
  }
  if (!km.rotationDays || km.rotationDays > 90) {
    effectivenessScore -= 12
    findings.push({ level: 'Medium', dimension: '有效性', title: '密钥轮换周期过长', detail: `密钥轮换周期 ${km.rotationDays || '未设置'} 天，超过推荐 90 天。`, standard: 'GM/T 0054', recommendation: '将密钥轮换周期设为 30-90 天。' })
  }
  if (km.useHardware === false) {
    effectivenessScore -= 8
    findings.push({ level: 'Low', dimension: '有效性', title: '未使用硬件密码模块', detail: '密钥未存储于硬件密码模块（HSM），存在明文/软件存储风险。', standard: 'GM/T 0028', recommendation: '使用合规 HSM/密码卡保护密钥。' })
  }

  // ---- 汇总 ----
  complianceScore = Math.max(0, complianceScore)
  correctnessScore = Math.max(0, correctnessScore)
  effectivenessScore = Math.max(0, effectivenessScore)
  const overallScore = Math.round(complianceScore * 0.4 + correctnessScore * 0.35 + effectivenessScore * 0.25)
  const violations = findings.filter((f) => f.level !== 'Pass').length
  const weakItems = weakAlgos.length + weakSuites.length + deprecated.length + weakKeys.length
  const level = overallScore >= 90 ? '合规' : overallScore >= 75 ? '基本合规' : overallScore >= 60 ? '部分合规' : '不合规'

  return {
    complianceScore, correctnessScore, effectivenessScore, overallScore, level,
    findings, summary: { compliant: findings.filter((f) => f.level === 'Pass').length, violations, weakItems },
    sm4RoundTrip, sm3Digest, standards: ['GB/T 39786-2021', 'GM/T 0001', 'GM/T 0002', 'GM/T 0004', 'GM/T 0005', 'GM/T 0024', 'GM/T 0054'],
  }
}

export const defaultCryptoConfig: CryptoConfig = {
  algorithms: ['SM4', 'SM3', 'SM2', 'AES-256'],
  cipherSuites: ['TLS_ECDHE_SM2_WITH_SM4_GCM_SM3', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
  protocols: ['TLSv1.3', 'TLSv1.2'],
  keyLengths: [256, 2048, 128],
  keyManagement: { rotationDays: 60, storage: 'HSM', useHardware: true },
  sm4Key: '0123456789abcdeffedcba9876543210',
}

export const weakCryptoConfig: CryptoConfig = {
  algorithms: ['MD5', '3DES', 'RC4', 'RSA'],
  cipherSuites: ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA'],
  protocols: ['TLSv1.0', 'TLSv1.1', 'SSLv3'],
  keyLengths: [512, 1024],
  keyManagement: { rotationDays: 365, storage: 'file', useHardware: false },
  sm4Key: '0123456789abcdeffedcba9876543210',
}
