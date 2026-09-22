/**
 * The "新建任务" wizard: 任务类型 → 目标主机 → 连接方式 → 连通性测试 → 检测范围 → 任务属性.
 *
 * The task type is the operator's one choice and it decides everything after it:
 *
 * - 检查任务 (inspection) is single-shot and installs nothing. The platform reads
 *   the ticked directories over the remote protocol *and*, on the same target,
 *   runs the network-service check — port/service fingerprint plus vulnerability
 *   templates matched against the package's nuclei rule set.
 * - 监测任务 (monitoring) must deploy a probe to the host; the probe then captures
 *   traffic continuously and reports data-asset scans back. If the automatic
 *   deployment cannot reach the host (SSH blocked, host unreachable), the wizard
 *   mints a hand-install config and keeps the dialog open so the operator can
 *   install the package themselves and watch for the probe to call back.
 *
 * The wizard deliberately does not ask "does this target need a probe?": that is
 * exactly what the task type answers, and asking it twice let the answer and the
 * behaviour disagree. Credentials live in this draft only — nothing is persisted
 * until the operator submits.
 */
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiPost } from '../../../api/client'
import { createDeployment, getDeployment, manualBootstrap } from '../../../api/probeDeployments'
import type { ManualBootstrap } from '../../../types/probeDeployment'
import { saveFileSource, runFileSource } from '../../../api/fileSources'
import { listPolicyGroups, type PolicyGroup } from '../../../api/policyGroups'

export type TaskType = 'inspection' | 'monitoring'

/** The two task types, in the order the wizard shows them, with the sentence
 *  that tells the operator what each one does. */
export const TASK_TYPES: { value: TaskType; label: string; hint: string }[] = [
  {
    value: 'inspection',
    label: '检查任务（单次）',
    hint: '不下发探针：平台直连读取勾选目录做数据检测，同时对目标网络服务做风险扫描、指纹识别并匹配漏洞库。',
  },
  {
    value: 'monitoring',
    label: '监测任务（持续）',
    hint: '必须在该主机部署探针：探针持续抓取网络流量并按周期上报数据资产；自动部署失败时可改为手动安装并等待回连。',
  },
]

export interface TreeRow { path: string; name: string; type: string; size: number; depth: number; reason?: string }
/** A node of the lazy scope tree: directories expand, files are leaves and can
 *  only be shown, never ticked. */
export interface TreeNode extends TreeRow { leaf: boolean; disabled: boolean }

export interface WizardHost {
  key: number
  host: string
  port: number
  username: string
  authType: 'password' | 'private_key'
  password: string
  privateKey: string
  keyPassphrase: string
  /** Transport the platform speaks itself when reading files (inspection). */
  protocol: 'sftp' | 'ftp' | 'ftps'
  test: { ok: boolean; error?: string; message?: string } | null
  hostKey: string
  root: string
  selected: string[]
  busy: boolean
  error: string
  /** Monitoring only: the deployment this target was dispatched as. */
  deploymentId: number | null
  deployStatus: string
  deployError: string
  registered: boolean
  manual: ManualBootstrap | null
  checking: boolean
}

let nextKey = 1

export function blankHost(): WizardHost {
  return {
    key: nextKey++, host: '', port: 22, username: 'root', authType: 'password',
    password: '', privateKey: '', keyPassphrase: '', protocol: 'sftp',
    test: null, hostKey: '', root: '/', selected: [], busy: false, error: '',
    deploymentId: null, deployStatus: '', deployError: '', registered: false,
    manual: null, checking: false,
  }
}

/** How long the wizard waits for a freshly installed probe to call back before
 *  it offers the hand-install route. */
export const CALLBACK_WINDOW_MS = 60_000
const CALLBACK_POLL_MS = 3_000

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

export function useTaskWizard() {
  const step = ref(0)
  const taskType = ref<TaskType>('inspection')
  const hosts = ref<WizardHost[]>([blankHost()])
  const groups = ref<PolicyGroup[]>([])
  const policyGroupIds = ref<number[]>([])
  /** Inspection: how many of the most common ports the service check covers. */
  const topPorts = ref(200)
  /** Monitoring: how often the probe re-inventories the ticked directories. */
  const intervalSeconds = ref(0)
  const busy = ref(false)

  /** Why "下发任务" is disabled, in the operator's words. Empty means ready.
   *  One explicit reason beats a grey button nobody can explain. */
  const blockReason = computed<string>(() => {
    if (!hosts.value.length) return '请至少添加一个目标主机'
    for (const host of hosts.value) {
      if (!host.host.trim()) return '请填写目标主机的 IP 或主机名'
      if (!host.test?.ok) return `目标 ${host.host} 尚未通过连通性测试`
      if (!host.selected.length) return `目标 ${host.host} 尚未勾选检测目录`
    }
    return ''
  })
  const ready = computed(() => blockReason.value === '')

  function addHost(): void { hosts.value.push(blankHost()) }
  function removeHost(key: number): void { hosts.value = hosts.value.filter((item) => item.key !== key) }

  function spec(host: WizardHost): Record<string, unknown> {
    return {
      protocol: 'ssh', host: host.host.trim(), port: host.port, username: host.username,
      auth_type: host.authType,
      password: host.authType === 'password' ? host.password : undefined,
      private_key: host.authType === 'private_key' ? host.privateKey : undefined,
      key_passphrase: host.keyPassphrase || undefined,
    }
  }

  /** A credential change invalidates the previous test: the operator must prove
   *  the connection they are about to submit, not an earlier one. */
  function invalidate(host: WizardHost): void {
    host.test = null
    host.hostKey = ''
  }

  async function testHost(host: WizardHost): Promise<void> {
    host.busy = true
    host.error = ''
    try {
      const result = await apiPost<{ ok: boolean; error?: string; message?: string; host_key_sha256?: string }>(
        '/targets/test', spec(host))
      host.test = result
      host.hostKey = result.host_key_sha256 || ''
      if (!result.ok) host.error = result.message || result.error || '连通性测试失败'
    } catch (err) {
      host.test = { ok: false }
      host.error = String(err)
    } finally {
      host.busy = false
    }
  }

  /** el-tree lazy loader: one level per expansion, so a deep tree is browsed on
   *  demand instead of in one bounded sweep. */
  async function loadNode(host: WizardHost, node: { level: number; data?: TreeNode },
                          resolve: (rows: TreeNode[]) => void): Promise<void> {
    const path = node.level === 0 ? (host.root || '/') : String(node.data?.path || '/')
    try {
      const result = await apiPost<{ rows: TreeRow[]; truncated: boolean; reason: string }>(
        '/targets/browse', { ...spec(host), roots: [path], max_depth: 1, max_entries: 500 })
      if (result.truncated) ElMessage.warning(`目录过大，已截断（${result.reason}）`)
      resolve(result.rows.map((row) => ({
        ...row, leaf: row.type !== 'dir', disabled: row.type !== 'dir',
      })))
    } catch (err) {
      host.error = String(err)
      ElMessage.warning(`无法列出 ${path}：${String(err)}`)
      resolve([])
    }
  }

  /** Cascading check: a ticked directory means "this whole subtree", so the
   *  scope is the checked keys only (the tree reports parents that are fully
   *  checked, not every descendant). */
  function onCheck(host: WizardHost, keys: string[]): void {
    host.selected = keys.filter(Boolean)
  }

  async function loadGroups(): Promise<void> {
    groups.value = (await listPolicyGroups({ page: 1, page_size: 200 })).items
  }

  /** 检查任务: platform-side only, one shot.
   *
   * Two calls because they are two kinds of work: the network-service check
   * (fingerprint + vulnerability templates) touches the host's ports, and each
   * ticked directory becomes its own read-only file source so the data detection
   * covers the whole scope instead of silently keeping only the first path. */
  async function dispatchInspection(host: WizardHost): Promise<void> {
    await apiPost('/scan', {
      target: host.host.trim(), discovery: false, top_ports: topPorts.value, ports: [],
      nuclei: true, nuclei_tags: '', nuclei_templates: '', probe_id: null,
    })
    for (const path of host.selected) {
      const source = await saveFileSource(null, {
        name: `${host.host} 检查采集 ${path}`.slice(0, 120),
        protocol: host.protocol, host: host.host.trim(), port: host.port,
        username: host.username, password: host.password, root_path: path,
        host_key_sha256: host.hostKey, enabled: true, limits: {}, interval_minutes: 0,
      })
      await runFileSource(source.id, 'scan')
    }
  }

  /** Poll one deployment until the probe registers, fails, or the window ends. */
  async function waitForRegistration(host: WizardHost): Promise<boolean> {
    const deadline = Date.now() + CALLBACK_WINDOW_MS
    for (;;) {
      const deployment = await getDeployment(host.deploymentId as number)
      host.deployStatus = deployment.status
      if (deployment.probe_id || deployment.registered_at) return true
      if (['FAILED', 'CANCELLED', 'REMOVED'].includes(deployment.status)) return false
      if (Date.now() >= deadline) return false
      await sleep(CALLBACK_POLL_MS)
    }
  }

  /** 监测任务: deploy the probe, then wait for it to call back.
   *
   * The deployment row is created before anything is polled so a failure always
   * has a row to hand out for the manual route — a pushed deployment that never
   * registered is exactly the case the hand install exists for. */
  async function dispatchMonitoring(host: WizardHost): Promise<boolean> {
    const deployment = await createDeployment({
      name: `${host.host} 监测任务`,
      idempotency_key: `${host.host}:${Date.now()}:${host.key}`,
      host: host.host.trim(), port: host.port, username: host.username,
      auth_type: host.authType,
      password: host.authType === 'password' ? host.password : undefined,
      private_key: host.authType === 'private_key' ? host.privateKey : undefined,
      key_passphrase: host.keyPassphrase || undefined,
      profile: 'standard', data_paths: host.selected,
      data_interval_seconds: intervalSeconds.value > 0 ? intervalSeconds.value : undefined,
      // The probe is task-dedicated: keep its credential so the platform can
      // uninstall it once this task ends.
      retain_credential: true,
    })
    host.deploymentId = deployment.id
    host.deployStatus = deployment.status
    host.manual = null
    if (await waitForRegistration(host)) {
      host.registered = true
      host.deployError = ''
      return true
    }
    host.deployError = `自动部署未回连（当前状态 ${host.deployStatus || '未知'}）`
    await loadManual(host)
    return false
  }

  /** Mint the hand-install config for a target whose automatic push did not
   *  work. Failure here is reported but never thrown: the operator still needs
   *  the deployment id and the error to act on. */
  async function loadManual(host: WizardHost): Promise<void> {
    if (!host.deploymentId) return
    try {
      host.manual = await manualBootstrap(host.deploymentId)
    } catch (err) {
      host.deployError = `${host.deployError}；手动安装凭据获取失败：${String(err)}`
    }
  }

  /** "检测回连": re-read the deployment and report whether the hand-installed
   *  probe has registered. */
  async function checkCallback(host: WizardHost): Promise<boolean> {
    if (!host.deploymentId) return false
    host.checking = true
    try {
      const deployment = await getDeployment(host.deploymentId)
      host.deployStatus = deployment.status
      host.registered = Boolean(deployment.probe_id || deployment.registered_at)
      if (host.registered) {
        host.deployError = ''
        ElMessage.success(`${host.host} 的探针已回连`)
      } else {
        ElMessage.warning(`${host.host} 的探针尚未回连（当前 ${deployment.status}）`)
      }
      return host.registered
    } catch (err) {
      host.deployError = String(err)
      ElMessage.error(String(err))
      return false
    } finally {
      host.checking = false
    }
  }

  async function submit(): Promise<{ ok: number; failed: number }> {
    busy.value = true
    let ok = 0
    let failed = 0
    try {
      for (const host of hosts.value) {
        host.error = ''
        try {
          const done = taskType.value === 'monitoring'
            ? await dispatchMonitoring(host)
            : (await dispatchInspection(host), true)
          if (done) ok += 1
          else failed += 1
        } catch (err) {
          failed += 1
          host.error = String(err)
          if (taskType.value === 'monitoring') host.deployError = String(err)
        }
      }
      if (ok && !failed) ElMessage.success(`已下发 ${ok} 个目标`)
      else if (ok) ElMessage.warning(`已下发 ${ok} 个目标，${failed} 个未完成`)
      else ElMessage.error('没有目标下发成功')
      return { ok, failed }
    } finally {
      busy.value = false
    }
  }

  function reset(): void {
    step.value = 0
    taskType.value = 'inspection'
    hosts.value = [blankHost()]
    policyGroupIds.value = []
    topPorts.value = 200
    intervalSeconds.value = 0
  }

  return {
    step, taskType, hosts, groups, policyGroupIds, topPorts, intervalSeconds, busy,
    blockReason, ready,
    addHost, removeHost, testHost, loadNode, onCheck, loadGroups, invalidate,
    submit, checkCallback, reset,
  }
}
