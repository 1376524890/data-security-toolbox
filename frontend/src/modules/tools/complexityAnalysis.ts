// 代码算法时间/空间复杂度分析 — 开源工具与库：acorn(JS AST)、自定义启发式 Big-O 分析。

import { parse, type Node } from 'acorn'

export interface ComplexityResult {
  language: string
  timeComplexity: string
  spaceComplexity: string
  bigO: { time: string; space: string }
  lines: number
  functions: FunctionAnalysis[]
  loops: number
  recursion: boolean
  notes: string[]
}

export interface FunctionAnalysis {
  name: string
  time: string
  space: string
  lines: number
}

const isLoop = (node: any) => node.type === 'ForStatement' || node.type === 'WhileStatement' || node.type === 'DoWhileStatement' || node.type === 'ForInStatement' || node.type === 'ForOfStatement'

function countLoops(node: any): number {
  if (!node || typeof node !== 'object') return 0
  let count = 0
  if (isLoop(node)) count += 1
  for (const key of Object.keys(node)) {
    const child = node[key]
    if (Array.isArray(child)) child.forEach((c) => { count += countLoops(c) })
    else if (child && typeof child === 'object') count += countLoops(child)
  }
  return count
}

function countNestedLoops(node: any): number {
  // 返回最大嵌套深度
  if (!node || typeof node !== 'object') return 0
  let maxDepth = isLoop(node) ? 1 : 0
  for (const key of Object.keys(node)) {
    const child = node[key]
    if (Array.isArray(child)) child.forEach((c) => { maxDepth = Math.max(maxDepth, isLoop(node) ? 1 + countNestedLoops(c) : countNestedLoops(c)) })
    else if (child && typeof child === 'object') maxDepth = Math.max(maxDepth, isLoop(node) ? 1 + countNestedLoops(child) : countNestedLoops(child))
  }
  return maxDepth
}

function detectRecursion(ast: any, functionName?: string): boolean {
  // 在函数体内检测直接递归调用
  let found = false
  const walk = (node: any): void => {
    if (!node || typeof node !== 'object' || found) return
    if (node.type === 'CallExpression' && node.callee && node.callee.name && functionName && node.callee.name === functionName) found = true
    for (const key of Object.keys(node)) {
      const child = node[key]
      if (Array.isArray(child)) child.forEach(walk)
      else if (child && typeof child === 'object') walk(child)
    }
  }
  walk(ast)
  return found
}

function collectFunctions(ast: any): FunctionAnalysis[] {
  const fns: FunctionAnalysis[] = []
  const walk = (node: any): void => {
    if (!node || typeof node !== 'object') return
    if (node.type === 'FunctionDeclaration' && node.id) {
      const bodyLoops = countLoops(node.body)
      const nested = countNestedLoops(node.body)
      const recursive = detectRecursion(node.body, node.id.name)
      fns.push({ name: node.id.name, time: estimateTime(nested, recursive, bodyLoops), space: estimateSpace(nested, recursive), lines: node.loc ? node.loc.end.line - node.loc.start.line : 0 })
    } else if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
      const bodyLoops = countLoops(node.body)
      const nested = countNestedLoops(node.body)
      const recursive = detectRecursion(node.body)
      fns.push({ name: '(匿名函数)', time: estimateTime(nested, recursive, bodyLoops), space: estimateSpace(nested, recursive), lines: node.loc ? node.loc.end.line - node.loc.start.line : 0 })
    }
    for (const key of Object.keys(node)) {
      const child = node[key]
      if (Array.isArray(child)) child.forEach(walk)
      else if (child && typeof child === 'object') walk(child)
    }
  }
  walk(ast)
  return fns
}

function estimateTime(nested: number, recursive: boolean, totalLoops: number): string {
  if (nested >= 3) return 'O(n^3) 及以上'
  if (nested === 2) return 'O(n²)'
  if (nested === 1) return 'O(n)'
  if (recursive) return 'O(2^n) / O(n)（视递归分支）'
  if (totalLoops > 0) return 'O(n)'
  return 'O(1)'
}

function estimateSpace(nested: number, recursive: boolean): string {
  if (recursive) return 'O(n)（递归栈）'
  if (nested >= 2) return 'O(n²)'
  if (nested === 1) return 'O(n)'
  return 'O(1)'
}

export function analyzeComplexity(code: string, language: string): ComplexityResult {
  const notes: string[] = []
  if (!code.trim()) return { language, timeComplexity: '-', spaceComplexity: '-', bigO: { time: '-', space: '-' }, lines: 0, functions: [], loops: 0, recursion: false, notes: ['未输入代码'] }

  if (language === 'python') {
    return analyzePython(code)
  }

  // JavaScript / TypeScript via acorn
  try {
    const ast = parse(code, { ecmaVersion: 2022, sourceType: 'module', locations: true })
    const loops = countLoops(ast)
    const nested = countNestedLoops(ast)
    const fns = collectFunctions(ast)
    const recursion = fns.length ? fns.some((f) => f.time.includes('2^n')) : detectRecursion(ast)
    const lines = code.split('\n').length
    const time = estimateTime(nested, recursion, loops)
    const space = estimateSpace(nested, recursion)
    notes.push(`使用 acorn 解析 JS AST，识别 ${loops} 处循环，最大嵌套深度 ${nested}。`)
    if (fns.length) notes.push(`识别到 ${fns.length} 个函数。`)
    if (recursion) notes.push('检测到递归调用，需关注栈深度与时间复杂度。')
    return { language, timeComplexity: time, spaceComplexity: space, bigO: { time, space }, lines, functions: fns, loops, recursion, notes }
  } catch (e) {
    notes.push(`JS 解析失败（${String(e)}），改用启发式分析。`)
    return analyzeHeuristic(code, language)
  }
}

function analyzePython(code: string): ComplexityResult {
  const notes: string[] = []
  const lines = code.split('\n')
  // 简单启发式：按缩进统计 for/while 嵌套
  let maxIndent = 0
  let loops = 0
  lines.forEach((line) => {
    const indent = (line.match(/^\s*/) || [''])[0].length
    const trimmed = line.trim()
    if (/^(for|while)\b/.test(trimmed)) { loops += 1; maxIndent = Math.max(maxIndent, Math.max(1, Math.floor(indent / 4))) }
  })
  const recursion = /def .*:[\s\S]*?\b\w+\s*\(/.test(code)
  const time = maxIndent >= 3 ? 'O(n^3) 及以上' : maxIndent === 2 ? 'O(n²)' : maxIndent === 1 ? 'O(n)' : recursion ? 'O(2^n) / O(n)' : 'O(1)'
  const space = recursion ? 'O(n)（递归栈）' : maxIndent >= 2 ? 'O(n²)' : maxIndent === 1 ? 'O(n)' : 'O(1)'
  notes.push(`Python 启发式分析：识别 ${loops} 处循环，最大嵌套深度 ${maxIndent}。`)
  if (recursion) notes.push('检测到递归调用。')
  return { language: 'python', timeComplexity: time, spaceComplexity: space, bigO: { time, space }, lines: lines.length, functions: [], loops, recursion, notes }
}

function analyzeHeuristic(code: string, language: string): ComplexityResult {
  const notes: string[] = []
  const lines = code.split('\n')
  let loops = 0
  let nested = 0
  lines.forEach((line) => {
    if (/for\s*\(|while\s*\(|\bfor\b|\bwhile\b/.test(line)) loops += 1
    if (/for\s*\([^)]*\)\s*\{/.test(line) && /\bfor\b|\bwhile\b/.test(code)) nested += 1
  })
  const recursion = /(\w+)\s*\([^)]*\)\s*\{[\s\S]*\1\s*\(/.test(code)
  const time = loops > 2 ? 'O(n²) 及以上' : loops === 1 ? 'O(n)' : recursion ? 'O(2^n) / O(n)' : 'O(1)'
  const space = recursion ? 'O(n)（递归栈）' : loops > 1 ? 'O(n²)' : loops === 1 ? 'O(n)' : 'O(1)'
  notes.push(`启发式分析：识别 ${loops} 处循环。`)
  return { language: 'python', timeComplexity: time, spaceComplexity: space, bigO: { time, space }, lines: lines.length, functions: [], loops, recursion, notes }
}

export const defaultCodeSample = `// 二分查找：O(log n)
function binarySearch(arr, target) {
  let lo = 0, hi = arr.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (arr[mid] === target) return mid
    if (arr[mid] < target) lo = mid + 1
    else hi = mid - 1
  }
  return -1
}

// 冒泡排序：O(n^2)
function bubbleSort(arr) {
  for (let i = 0; i < arr.length; i++) {
    for (let j = 0; j < arr.length - i - 1; j++) {
      if (arr[j] > arr[j + 1]) [arr[j], arr[j + 1]] = [arr[j + 1], arr[j]]
    }
  }
  return arr
}
`
