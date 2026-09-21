/**
 * The "新建任务" wizard: targets → connection → reachability → scope → schedule.

 * Reachability and the directory tree come from the synchronous target helpers,
 * so the operator ticks a real scope instead of typing paths blind. A probe
 * target is dispatched as a probe deployment (with the ticked directories as its
 * collection paths); a direct target is saved as a pinned-key file source and
 * scanned by the platform. Credentials live in this draft only — nothing is
 * persisted until the operator submits.
 */
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiPost } from '../../../api/client'
import { preflight, createDeployment } from '../../../api/probeDeployments'
import { saveFileSource, runFileSource } from '../../../api/fileSources'
import { listPolicyGroups, type PolicyGroup } from '../../../api/policyGroups'

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
  mode: 'probe' | 'direct'
  /** Transport used when mode is 'direct' (no probe): the platform speaks it
   *  itself. */
  protocol: 'sftp' | 'ftp' | 'ftps'
  test: { ok: boolean; error?: string; message?: string } | null
  hostKey: string
  root: string
  selected: string[]
  busy: boolean
  error: string
}

let nextKey = 1
function blankHost(): WizardHost {
  return { key: nextKey++, host: '', port: 22, username: 'root', authType: 'password',
    password: '', privateKey: '', keyPassphrase: '', mode: 'probe', protocol: 'sftp',
    test: null, hostKey: '',
    root: '/', selected: [], busy: false, error: '' }
}

export function useTaskWizard() {
  const step = ref(0)
  const hosts = ref<WizardHost[]>([blankHost()])
  const groups = ref<PolicyGroup[]>([])
  const policyGroupIds = ref<number[]>([])
  const taskMode = ref<'once' | 'scheduled'>('once')
  const intervalSeconds = ref(3600)
  const capture = ref(false)
  const busy = ref(false)

  const ready = computed(() => hosts.value.length > 0 &&
    hosts.value.every((item) => item.host && item.test?.ok && item.selected.length > 0))

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

  async function submit(): Promise<{ ok: number; failed: number }> {
    busy.value = true
    let ok = 0
    let failed = 0
    try {
      for (const host of hosts.value) {
        try {
          // Only directories are tickable, so the selection is already the scope.
          const paths = host.selected
          if (!paths.length) throw new Error('请至少勾选一个检测目录')
          if (host.mode === 'probe') {
            await preflight({
              host: host.host, port: host.port, username: host.username, auth_type: host.authType,
              password: host.authType === 'password' ? host.password : undefined,
              private_key: host.authType === 'private_key' ? host.privateKey : undefined,
              key_passphrase: host.keyPassphrase || undefined,
              profile: 'standard', data_paths: paths,
              data_interval_seconds: taskMode.value === 'scheduled' ? intervalSeconds.value : undefined,
            } as never)
            await createDeployment({
              name: `${host.host} 采集任务`,
              idempotency_key: `${host.host}:${Date.now()}:${host.key}`,
              host: host.host, port: host.port, username: host.username, auth_type: host.authType,
              password: host.authType === 'password' ? host.password : undefined,
              private_key: host.authType === 'private_key' ? host.privateKey : undefined,
              key_passphrase: host.keyPassphrase || undefined,
              profile: 'standard', data_paths: paths,
              data_interval_seconds: taskMode.value === 'scheduled' ? intervalSeconds.value : undefined,
              // The probe is task-dedicated: keep its credential so the platform
              // can uninstall it once this task ends.
              retain_credential: true,
            })
          } else {
            const source = await saveFileSource(null, {
              name: `${host.host} 直连采集`, protocol: host.protocol, host: host.host, port: host.port,
              username: host.username, password: host.password, root_path: paths[0] || host.root,
              host_key_sha256: host.hostKey, enabled: true, limits: {},
              interval_minutes: taskMode.value === 'scheduled' ? Math.max(1, Math.round(intervalSeconds.value / 60)) : 0,
            })
            await runFileSource(source.id, 'scan')
          }
          ok += 1
        } catch (err) {
          failed += 1
          host.error = String(err)
        }
      }
      if (ok) ElMessage.success(`已下发 ${ok} 个目标${failed ? `，${failed} 个失败` : ''}`)
      else ElMessage.error('没有目标下发成功')
      return { ok, failed }
    } finally {
      busy.value = false
    }
  }

  function reset(): void {
    step.value = 0
    hosts.value = [blankHost()]
    policyGroupIds.value = []
    taskMode.value = 'once'
    intervalSeconds.value = 3600
    capture.value = false
  }

  return { step, hosts, groups, policyGroupIds, taskMode, intervalSeconds, capture, busy, ready,
    addHost, removeHost, testHost, loadNode, onCheck, loadGroups, submit, reset }
}
