import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import TaskActions from '../components/common/TaskActions.vue'
import type { Task } from '../types/task'

const mocks = vi.hoisted(() => ({ confirm: vi.fn(), stop: vi.fn(), remove: vi.fn(), error: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessageBox: { confirm: mocks.confirm }, ElMessage: { success: vi.fn(), error: mocks.error } }))
vi.mock('../api/tasks', () => ({ stopTask: mocks.stop, deleteTask: mocks.remove }))
vi.mock('../stores/auth', () => ({ useAuthStore: () => ({ user: { role: 'admin' } }) }))
let app: App
let host: HTMLDivElement
const changed = vi.fn()
function mount(status: string) {
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(TaskActions, { task: { id: 7, kind: 'data_asset_scan', status } as Task, onChanged: changed })
  app.component('el-button', { template: '<button><slot /></button>' })
  app.mount(host)
}
async function click() {
  host.querySelector('button')!.click()
  await new Promise(resolve => setTimeout(resolve, 0))
  await nextTick()
}
beforeEach(() => { vi.clearAllMocks(); mocks.confirm.mockResolvedValue('confirm'); mocks.stop.mockResolvedValue({}); mocks.remove.mockResolvedValue({}) })
afterEach(() => { app.unmount(); host.remove() })
describe('probe task actions', () => {
  it('stops a pending task and refreshes its parent', async () => {
    mount('Pending')
    expect(host.textContent).toContain('停止')
    await click()
    expect(mocks.stop).toHaveBeenCalledWith(7)
    expect(changed).toHaveBeenCalledOnce()
  })
  it('does not stop when confirmation is cancelled', async () => {
    mocks.confirm.mockRejectedValue('cancel')
    mount('Running')
    await click()
    expect(mocks.stop).not.toHaveBeenCalled()
  })
  it('deletes a stopped task and reports API failure without refreshing', async () => {
    mocks.remove.mockRejectedValue(new Error('删除失败'))
    mount('Cancelled')
    expect(host.textContent).toContain('删除')
    await click()
    expect(mocks.remove).toHaveBeenCalledWith(7)
    expect(mocks.error).toHaveBeenCalledWith('删除失败')
    expect(changed).not.toHaveBeenCalled()
  })
})
