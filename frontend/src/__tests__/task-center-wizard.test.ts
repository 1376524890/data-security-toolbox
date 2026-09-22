import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import ElementPlus, { ElMessage } from 'element-plus'

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  listTasks: vi.fn(), getTask: vi.fn(), stopTask: vi.fn(), deleteTask: vi.fn(),
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
