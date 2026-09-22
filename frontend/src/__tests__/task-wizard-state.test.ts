import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  success: vi.fn(), warning: vi.fn(), error: vi.fn(),
  createDeployment: vi.fn(), getDeployment: vi.fn(), manualBootstrap: vi.fn(),
  saveFileSource: vi.fn(), runFileSource: vi.fn(), listPolicyGroups: vi.fn(),
}))

vi.mock('element-plus', () => ({
  ElMessage: { success: mocks.success, warning: mocks.warning, error: mocks.error },
}))
vi.mock('../api/client', () => ({ apiPost: mocks.post }))
vi.mock('../api/probeDeployments', () => ({
  createDeployment: mocks.createDeployment,
  getDeployment: mocks.getDeployment,
  manualBootstrap: mocks.manualBootstrap,
}))
vi.mock('../api/fileSources', () => ({
  saveFileSource: mocks.saveFileSource, runFileSource: mocks.runFileSource,
}))
vi.mock('../api/policyGroups', () => ({ listPolicyGroups: mocks.listPolicyGroups }))

import { useTaskWizard } from '../modules/tasks/composables/useTaskWizard'

beforeEach(() => { vi.clearAllMocks() })

/** A host that has already passed the connectivity test and picked a scope. */
function reachableHost() {
  const wizard = useTaskWizard()
  const host = wizard.hosts.value[0]
  host.host = '10.0.0.9'
  host.selected = ['/data']
  host.test = { ok: true }
  host.hostKey = 'SHA256:abc'
  return wizard
}

describe('task wizard: task type replaces the probe checkbox', () => {
  it('does not expose a per-target probe switch any more', () => {
    const wizard = useTaskWizard()
    expect(Object.keys(wizard.hosts.value[0])).not.toContain('mode')
    expect(wizard.taskType.value).toBe('inspection')
  })

  it('keeps the submit button disabled with a reason until the target is usable', () => {
    const wizard = useTaskWizard()
    expect(wizard.ready.value).toBe(false)
    expect(wizard.blockReason.value).toContain('IP')
    const host = wizard.hosts.value[0]
    host.host = '10.0.0.9'
    expect(wizard.blockReason.value).toContain('连通性测试')
    host.test = { ok: true }
    expect(wizard.blockReason.value).toContain('检测目录')
    host.selected = ['/data']
    expect(wizard.blockReason.value).toBe('')
    expect(wizard.ready.value).toBe(true)
  })

  it('drops a stale connectivity test when the operator edits the connection', () => {
    const wizard = reachableHost()
    expect(wizard.ready.value).toBe(true)
    wizard.invalidate(wizard.hosts.value[0])
    expect(wizard.ready.value).toBe(false)
    expect(wizard.blockReason.value).toContain('连通性测试')
  })
})

describe('task wizard: 检查任务', () => {
  it('scans the target services with the vulnerability templates and reads every ticked directory', async () => {
    mocks.post.mockResolvedValue({ id: 1, kind: 'scan' })
    mocks.saveFileSource
      .mockResolvedValueOnce({ id: 11 })
      .mockResolvedValueOnce({ id: 12 })
    mocks.runFileSource.mockResolvedValue({ id: 11 })
    const wizard = reachableHost()
    wizard.hosts.value[0].selected = ['/data', '/srv']
    const result = await wizard.submit()

    expect(result).toEqual({ ok: 1, failed: 0 })
    // fingerprint + vulnerability library match on the target's network services
    expect(mocks.post).toHaveBeenCalledWith('/scan', expect.objectContaining({
      target: '10.0.0.9', nuclei: true, top_ports: 200, probe_id: null,
    }))
    // one file source per ticked directory: no silently dropped scope
    expect(mocks.saveFileSource).toHaveBeenCalledTimes(2)
    expect(mocks.saveFileSource.mock.calls.map((call) => call[1].root_path))
      .toEqual(['/data', '/srv'])
    expect(mocks.runFileSource).toHaveBeenCalledTimes(2)
    // nothing is installed on the target for a check task
    expect(mocks.createDeployment).not.toHaveBeenCalled()
  })
})

describe('task wizard: 监测任务', () => {
  it('deploys a probe and succeeds once the probe calls back', async () => {
    mocks.createDeployment.mockResolvedValue({ id: 7, status: 'CREATED' })
    mocks.getDeployment.mockResolvedValue({ id: 7, status: 'REGISTERED', probe_id: 4, registered_at: 'now' })
    const wizard = reachableHost()
    wizard.taskType.value = 'monitoring'
    const result = await wizard.submit()

    expect(result).toEqual({ ok: 1, failed: 0 })
    expect(mocks.createDeployment).toHaveBeenCalledWith(expect.objectContaining({
      host: '10.0.0.9', profile: 'standard', data_paths: ['/data'], retain_credential: true,
    }))
    expect(wizard.hosts.value[0].registered).toBe(true)
    expect(wizard.hosts.value[0].manual).toBeNull()
    // a monitoring task never falls back to a platform-only file read
    expect(mocks.post).not.toHaveBeenCalledWith('/scan', expect.anything())
  })

  it('offers the manual install config when the automatic deployment never registers', async () => {
    mocks.createDeployment.mockResolvedValue({ id: 8, status: 'CREATED' })
    mocks.getDeployment.mockResolvedValue({ id: 8, status: 'FAILED' })
    mocks.manualBootstrap.mockResolvedValue({
      deployment_id: 8, backend_url: 'http://api', version: '3.7.0', expires_at: 'later',
      toml: 'bootstrap_token = "t"', packages: [], steps: ['上传探针包'],
    })
    const wizard = reachableHost()
    wizard.taskType.value = 'monitoring'
    const result = await wizard.submit()

    expect(result).toEqual({ ok: 0, failed: 1 })
    const host = wizard.hosts.value[0]
    expect(host.registered).toBe(false)
    expect(mocks.manualBootstrap).toHaveBeenCalledWith(8)
    expect(host.manual?.toml).toContain('bootstrap_token')
    expect(host.deployError).toContain('未回连')
  })

  it('marks the target connected when the hand-installed probe calls back', async () => {
    mocks.getDeployment.mockResolvedValue({ id: 9, status: 'REGISTERED', probe_id: 5, registered_at: 'now' })
    const wizard = reachableHost()
    const host = wizard.hosts.value[0]
    host.deploymentId = 9
    expect(await wizard.checkCallback(host)).toBe(true)
    expect(host.registered).toBe(true)
    expect(host.deployError).toBe('')
  })
})
