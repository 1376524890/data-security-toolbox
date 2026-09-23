import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  listTasks: vi.fn(), getTask: vi.fn(), stopTask: vi.fn(), deleteTask: vi.fn(),
  deleteProbe: vi.fn(),
  createDeployment: vi.fn(), getDeployment: vi.fn(), manualBootstrap: vi.fn(),
  saveFileSource: vi.fn(), runFileSource: vi.fn(), listPolicyGroups: vi.fn(),
}))

vi.mock('../api/client', () => ({ apiPost: mocks.post }))
vi.mock('../api/tasks', () => ({
  listTasks: mocks.listTasks, getTask: mocks.getTask,
  stopTask: mocks.stopTask, deleteTask: mocks.deleteTask,
}))
vi.mock('../api/probeDeployments', () => ({
  createDeployment: mocks.createDeployment,
  getDeployment: mocks.getDeployment,
  manualBootstrap: mocks.manualBootstrap,
}))
vi.mock('../api/fileSources', () => ({
  saveFileSource: mocks.saveFileSource, runFileSource: mocks.runFileSource,
}))
vi.mock('../api/policyGroups', () => ({ listPolicyGroups: mocks.listPolicyGroups }))
vi.mock('../api/probes', () => ({ deleteProbe: mocks.deleteProbe }))

// The 密码评估 panel draws a gauge; jsdom has no canvas, so echarts is stubbed
// the way the big-screen test stubs it - the panel's own numbers are asserted
// through the state test, not through a canvas.
vi.mock('echarts', () => {
  const chart = { setOption: vi.fn(), resize: vi.fn(), dispose: vi.fn() }
  class LinearGradient { constructor(..._args: unknown[]) {} }
  return { init: () => chart, graphic: { LinearGradient } }
})

import TaskCenter from '../modules/tasks/TaskCenter.vue'

let app: App
let host: HTMLElement
const flush = async () => {
  await new Promise((resolve) => setTimeout(resolve, 0))
  await nextTick()
  await new Promise((resolve) => setTimeout(resolve, 0))
}
const buttons = () => Array.from(host.querySelectorAll('button'))
const click = (label: string) => {
  const button = buttons().find((item) => item.textContent?.trim() === label)
  if (!button) throw new Error(`no button labelled ${label}`)
  button.click()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  mocks.listTasks.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 50 })
  mocks.listPolicyGroups.mockResolvedValue({ items: [] })
  // The tree is lazy: the root listing arrives when 检测范围 is first shown.
  mocks.post.mockImplementation(async (path: string) => {
    if (path === '/targets/test') {
      return { ok: true, protocol: 'ssh', error: '', host_key_sha256: 'SHA256:FAKE' }
    }
    if (path === '/targets/browse') {
      return { truncated: false, reason: '', rows: [
        { path: '/data', name: 'data', type: 'dir', size: 0, depth: 0 },
        { path: '/etc/passwd', name: 'passwd', type: 'file', size: 12, depth: 0 },
      ] }
    }
    return { id: 1, kind: 'scan' }
  })
  host = document.createElement('div')
  document.body.appendChild(host)
  app = createApp(TaskCenter)
  app.use(ElementPlus)
  app.mount(host)
})

afterEach(() => {
  app.unmount()
  host.remove()
  ElMessage.closeAll()
  vi.unstubAllGlobals()
})

/** Walk the wizard up to 检测范围 with one reachable target. */
async function reachScopeStep(): Promise<void> {
  await flush()
  click('新建任务')
  await flush()
  click('下一步')                       // 任务类型
  await flush()
  const target = host.querySelector<HTMLInputElement>('.el-dialog input')!
  target.value = '10.9.9.9'
  target.dispatchEvent(new Event('input', { bubbles: true }))
  await flush()
  click('下一步')                       // 目标主机
  await flush()
  const password = host.querySelector<HTMLInputElement>('.el-dialog input[type="password"]')!
  password.value = 'secret'
  password.dispatchEvent(new Event('input', { bubbles: true }))
  await flush()
  click('下一步')                       // 连接方式
  await flush()
  click('测试')                         // 连通性测试
  await flush()
  click('下一步')
  await flush()
}

describe('task wizard: ticking a directory reaches the wizard', () => {
  it('enables 下发任务 only after a directory is checked in the tree', async () => {
    await reachScopeStep()
    expect(host.querySelector('.el-tree-node__content')).toBeTruthy()
    expect(host.textContent).toContain('已选 0 个目录')

    click('下一步')                       // 任务属性
    await flush()
    const submit = () => buttons().find((item) => item.textContent?.trim() === '下发任务')!
    expect(submit().disabled).toBe(true)
    // The footer has to say why, otherwise the grey button is unexplainable.
    expect(host.querySelector('.block-reason')?.textContent).toContain('尚未勾选检测目录')

    click('上一步')
    await flush()
    // Tick the directory through the checkbox itself, exactly as an operator would.
    host.querySelector<HTMLInputElement>('.el-tree-node__content input[type="checkbox"]')!.click()
    await flush()
    expect(host.textContent).toContain('已选 1 个目录')

    click('下一步')
    await flush()
    expect(submit().disabled).toBe(false)
  })

  it('dispatches the one-shot check once a directory is ticked', async () => {
    await reachScopeStep()
    host.querySelector<HTMLInputElement>('.el-tree-node__content input[type="checkbox"]')!.click()
    await flush()
    click('下一步')
    await flush()
    mocks.saveFileSource.mockResolvedValue({ id: 11 })
    mocks.runFileSource.mockResolvedValue({ id: 11 })
    click('下发任务')
    await flush()
    expect(mocks.post).toHaveBeenCalledWith('/scan', expect.objectContaining({
      target: '10.9.9.9', nuclei: true, probe_id: null,
    }))
    expect(mocks.saveFileSource.mock.calls[0][1].root_path).toBe('/data')
    expect(mocks.createDeployment).not.toHaveBeenCalled()
  })

  it('carries the password assessment into the scan, and lets the operator drop it', async () => {
    await reachScopeStep()
    host.querySelector<HTMLInputElement>('.el-tree-node__content input[type="checkbox"]')!.click()
    await flush()
    click('下一步')                       // 任务属性
    await flush()
    expect(host.textContent).toContain('密码评估')
    mocks.saveFileSource.mockResolvedValue({ id: 11 })
    mocks.runFileSource.mockResolvedValue({ id: 11 })

    click('下发任务')
    await flush()
    expect(mocks.post).toHaveBeenCalledWith('/scan', expect.objectContaining({ crypto_assess: true }))

    // The switch is a real choice: turning it off keeps the scan but drops the
    // per-host observation it would otherwise carry.
    mocks.post.mockClear()
    const toggle = host.querySelector<HTMLElement>('.el-dialog .el-switch')!
    toggle.click()
    await flush()
    click('下发任务')
    await flush()
    expect(mocks.post).toHaveBeenCalledWith('/scan', expect.objectContaining({ crypto_assess: false }))
  })

  it('clears the checkboxes together with the stored keys', async () => {
    await reachScopeStep()
    host.querySelector<HTMLInputElement>('.el-tree-node__content input[type="checkbox"]')!.click()
    await flush()
    expect(host.textContent).toContain('已选 1 个目录')
    click('清空选择')
    await flush()
    expect(host.textContent).toContain('已选 0 个目录')
    expect(host.querySelector<HTMLInputElement>('.el-tree-node__content input[type="checkbox"]')!.checked)
      .toBe(false)
  })
})

/** The stuck row from the field: a monitoring task with a 200-segment backlog. */
const monitorRow = (overrides: Record<string, unknown> = {}) => ({
  id: 3, kind: 'monitoring', status: 'Running', progress: 100,
  current_stage: '持续监测中 · 共 218 段（已分析 13，进行中 200，失败 5）',
  log: '', payload: { probe_id: 1 }, result: {}, error: '',
  created_at: '2026-09-22T09:22:33Z', started_at: null, finished_at: null, ...overrides,
})

/** A finished platform scan: the row the 密码评估 section hangs off. */
const scanRow = (overrides: Record<string, unknown> = {}) => ({
  id: 7, kind: 'scan', status: 'Success', progress: 100, current_stage: '扫描完成',
  log: '', payload: { target: '10.0.0.9' }, error: '',
  result: {
    target: '10.0.0.9', hosts: ['10.0.0.9'], alive_hosts: 1, assets: 2, findings: 1,
    crypto_profile_hosts: 1,
    crypto_profiles: {
      '10.0.0.9': {
        config: { algorithms: ['SHA1', 'SM4'], cipherSuites: ['TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
          protocols: ['TLSv1.0'], keyLengths: [1024],
          keyManagement: { rotationDays: 365, storage: 'file', useHardware: false } },
        passwordSignals: [], passwordTypes: ['明文口令'],
        tlsHandshakeCount: 2, serviceCount: 5,
      },
    },
  },
  created_at: '2026-09-22T09:22:33Z', started_at: null, finished_at: null, ...overrides,
})

describe('task centre: the password assessment rides on the scan', () => {
  it('offers the assessment for the hosts the scan observed', async () => {
    const row = scanRow()
    mocks.listTasks.mockResolvedValue({ items: [row], total: 1, page: 1, page_size: 50 })
    mocks.getTask.mockResolvedValue(row)
    click('刷新')
    await flush()
    host.querySelector<HTMLElement>('.el-table__row')!.click()
    await flush()

    expect(mocks.getTask).toHaveBeenCalledWith(7)
    expect(host.textContent).toContain('密码评估')
    expect(host.textContent).toContain('评估该主机')
    // The observed host is what the operator picks from, and the raw result
    // block must not also dump the whole profile as one opaque row.
    expect(host.textContent).toContain('10.0.0.9')
    expect(host.textContent).not.toContain('crypto_profiles')
  })

  it('stays out of the way for a task that carries no observation', async () => {
    const row = scanRow({ result: { target: '10.0.0.9', hosts: [], assets: 0, findings: 0 } })
    mocks.listTasks.mockResolvedValue({ items: [row], total: 1, page: 1, page_size: 50 })
    mocks.getTask.mockResolvedValue(row)
    click('刷新')
    await flush()
    host.querySelector<HTMLElement>('.el-table__row')!.click()
    await flush()
    expect(host.textContent).not.toContain('评估该主机')
  })
})

describe('task centre: a monitoring task can be stopped and its probe retired', () => {
  it('offers both actions on a running monitoring row', async () => {
    mocks.listTasks.mockResolvedValue({ items: [monitorRow()], total: 1, page: 1, page_size: 50 })
    click('刷新')
    await flush()
    expect(host.textContent).toContain('回收探针')
    // The stop stays offered: refusing the kind outright is the bug being fixed.
    expect(buttons().some((item) => item.textContent?.trim() === '停止')).toBe(true)
  })

  it('stops a monitoring task instead of refusing the kind', async () => {
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm' as never)
    mocks.listTasks.mockResolvedValue({ items: [monitorRow()], total: 1, page: 1, page_size: 50 })
    click('刷新')
    await flush()
    click('停止')
    await flush()
    expect(mocks.stopTask).toHaveBeenCalledWith(3)
    // The dialog has to warn that the capture ends and the probe goes away.
    expect(String(confirm.mock.calls[0][0])).toContain('回收本任务部署的探针')
    confirm.mockRestore()
  })

  it('retires the probe with the credential its install retained', async () => {
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm' as never)
    mocks.listTasks.mockResolvedValue({ items: [monitorRow()], total: 1, page: 1, page_size: 50 })
    mocks.deleteProbe.mockResolvedValue({ status: 'queued', deployment_id: 9 })
    click('刷新')
    await flush()
    click('回收探针')
    await flush()
    // No SSH secret in the payload: the server uses the one the install kept.
    expect(mocks.deleteProbe).toHaveBeenCalledWith(1, { remove_remote: true })
    confirm.mockRestore()
  })
})
