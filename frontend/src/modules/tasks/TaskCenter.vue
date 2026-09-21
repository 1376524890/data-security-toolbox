<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { deleteTask, getTask, listTasks, stopTask } from '../../api/tasks'
import type { Task } from '../../types/task'
import { formatDateTime } from '../../utils/format'
import { useTaskWizard } from './composables/useTaskWizard'

// 任务中心: the task list (progress + health, expandable to a detail and a short
// problem summary) and the only place a scan is dispatched — the "新建任务"
// wizard on the right.
const loading = ref(true)
const error = ref('')
const rows = ref<Task[]>([])
const total = ref(0)
const filters = reactive({ page: 1, page_size: 50, status: '', kind: '' })
const detail = ref<Task | null>(null)

const wizardOpen = ref(false)
const wizard = useTaskWizard()

const KINDS = ['probe_scan', 'data_asset_scan', 'network_scan', 'file_source_scan', 'database_scan']

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const page = await listTasks({ ...filters })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

/** A short, honest read of a task's health from the fields the worker reports. */
function health(task: Task): { label: string; tone: string } {
  if (task.status === 'Failed') return { label: task.error || '失败', tone: 'danger' }
  if (task.status === 'Partial') return { label: task.error || '部分完成', tone: 'warning' }
  if (task.status === 'Running') return { label: task.current_stage || '运行中', tone: 'primary' }
  if (task.status === 'Pending') return { label: task.current_stage || '排队中', tone: 'info' }
  if (task.status === 'Cancelled') return { label: '已取消', tone: 'info' }
  return { label: task.current_stage || '完成', tone: 'success' }
}

function duration(task: Task): string {
  if (!task.started_at) return '—'
  const start = new Date(task.started_at).getTime()
  const end = task.finished_at ? new Date(task.finished_at).getTime() : Date.now()
  const sec = Math.max(0, Math.round((end - start) / 1000))
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`
}

async function open(task: Task): Promise<void> {
  detail.value = await getTask(task.id)
}

async function stop(task: Task): Promise<void> {
  try { await stopTask(task.id); ElMessage.success('已请求停止'); await load() }
  catch (err) { ElMessage.error(String(err)) }
}

async function remove(task: Task): Promise<void> {
  try { await deleteTask(task.id); await load() }
  catch (err) { ElMessage.error(String(err)) }
}

async function openWizard(): Promise<void> {
  wizard.reset()
  if (!wizard.groups.value.length) await wizard.loadGroups()
  wizardOpen.value = true
}

async function submitWizard(): Promise<void> {
  const result = await wizard.submit()
  if (result.ok) {
    wizardOpen.value = false
    await load()
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <strong>任务中心</strong>
      <span class="muted">下发与进度监控；任务结束后按引用计数卸载探针</span>
      <div class="toolbar-spacer" />
      <el-select v-model="filters.status" clearable placeholder="全部状态" style="width: 140px" @change="load">
        <el-option v-for="s in ['Pending', 'Running', 'Success', 'Failed', 'Partial', 'Cancelled']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="filters.kind" clearable placeholder="全部类型" style="width: 160px" @change="load">
        <el-option v-for="k in KINDS" :key="k" :label="k" :value="k" />
      </el-select>
      <el-button @click="load">刷新</el-button>
      <el-button type="primary" @click="openWizard">新建任务</el-button>
    </div>

    <StateBox :loading="loading" :error="error" :empty="!rows.length" empty-text="还没有任务" @retry="load">
      <el-table :data="rows" size="small" @row-click="open">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="detail">
              <div><b>阶段</b>：{{ row.current_stage || '—' }}</div>
              <div v-if="row.error"><b>问题</b>：{{ row.error }}</div>
              <div v-if="Object.keys(row.result || {}).length"><b>结果摘要</b>：{{ JSON.stringify(row.result).slice(0, 400) }}</div>
              <div v-if="row.log"><b>日志</b>：{{ String(row.log).slice(-400) }}</div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="kind" label="类型" width="150" />
        <el-table-column label="状态" width="110"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        <el-table-column label="完成度" width="200">
          <template #default="{ row }"><el-progress :percentage="Math.max(0, Math.min(100, row.progress || 0))" :stroke-width="10" /></template>
        </el-table-column>
        <el-table-column label="健康度" min-width="200">
          <template #default="{ row }"><el-tag size="small" :type="health(row).tone as never">{{ health(row).label }}</el-tag></template>
        </el-table-column>
        <el-table-column label="耗时" width="110"><template #default="{ row }">{{ duration(row) }}</template></el-table-column>
        <el-table-column label="创建时间" width="180"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{ row }">
            <el-button v-if="['Pending', 'Running'].includes(row.status)" link type="warning" size="small" @click.stop="stop(row)">停止</el-button>
            <el-button link type="danger" size="small" @click.stop="remove(row)">移除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination background layout="total, prev, pager, next" :total="total" :page-size="filters.page_size"
                     :current-page="filters.page" style="margin-top: 10px"
                     @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <el-dialog v-model="wizardOpen" title="新建任务" width="980px" top="6vh">
      <el-steps :active="wizard.step.value" simple finish-status="success" style="margin-bottom: 14px">
        <el-step title="目标主机" />
        <el-step title="连接方式" />
        <el-step title="连通性测试" />
        <el-step title="检测范围" />
        <el-step title="任务属性" />
      </el-steps>

      <!-- 1. 目标主机（IP/端口） -->
      <template v-if="wizard.step.value === 0">
        <el-table :data="wizard.hosts.value" size="small">
          <el-table-column label="IP / 主机" min-width="200"><template #default="{ row }"><el-input v-model="row.host" placeholder="10.0.0.10" /></template></el-table-column>
          <el-table-column label="端口" width="110"><template #default="{ row }"><el-input-number v-model="row.port" :min="1" :max="65535" controls-position="right" style="width: 100%" /></template></el-table-column>
          <el-table-column label="操作" width="90"><template #default="{ row }"><el-button link type="danger" @click="wizard.removeHost(row.key)">删除</el-button></template></el-table-column>
        </el-table>
        <el-button style="margin-top: 8px" @click="wizard.addHost">添加主机</el-button>
      </template>

      <!-- 2. 连接方式与凭据 -->
      <template v-else-if="wizard.step.value === 1">
        <div v-for="host in wizard.hosts.value" :key="host.key" class="host-block">
          <div class="host-title">{{ host.host }}:{{ host.port }}</div>
          <el-form label-width="110px" size="small">
            <el-form-item label="连接方式">
              <el-radio-group v-model="host.mode">
                <el-radio-button value="probe">下发探针</el-radio-button>
                <el-radio-button value="direct">不走探针（远程协议）</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="用户名"><el-input v-model="host.username" style="width: 260px" /></el-form-item>
            <el-form-item label="认证方式">
              <el-radio-group v-model="host.authType">
                <el-radio-button value="password">密码</el-radio-button>
                <el-radio-button value="private_key">私钥</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item v-if="host.authType === 'password'" label="密码">
              <el-input v-model="host.password" type="password" show-password style="width: 320px" />
            </el-form-item>
            <template v-else>
              <el-form-item label="私钥"><el-input v-model="host.privateKey" type="textarea" :rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" /></el-form-item>
              <el-form-item label="私钥口令"><el-input v-model="host.keyPassphrase" type="password" show-password style="width: 260px" /></el-form-item>
            </template>
          </el-form>
        </div>
      </template>

      <!-- 3. 连通性测试 -->
      <template v-else-if="wizard.step.value === 2">
        <el-table :data="wizard.hosts.value" size="small">
          <el-table-column label="目标" min-width="200"><template #default="{ row }">{{ row.host }}:{{ row.port }}</template></el-table-column>
          <el-table-column label="结果" min-width="260">
            <template #default="{ row }">
              <el-tag v-if="row.test" size="small" :type="row.test.ok ? 'success' : 'danger'">
                {{ row.test.ok ? `可达${row.hostKey ? ' · ' + row.hostKey.slice(0, 24) + '…' : ''}` : (row.test.message || row.test.error || '不可达') }}
              </el-tag>
              <span v-else class="muted">未测试</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="120"><template #default="{ row }"><el-button size="small" :loading="row.busy" @click="wizard.testHost(row)">测试</el-button></template></el-table-column>
        </el-table>
        <el-button style="margin-top: 8px" @click="wizard.hosts.value.forEach((h) => wizard.testHost(h))">全部测试</el-button>
      </template>

      <!-- 4. 目录树 + 勾选范围 -->
      <template v-else-if="wizard.step.value === 3">
        <div v-for="host in wizard.hosts.value" :key="host.key" class="host-block">
          <div class="host-title">{{ host.host }}：选择监测/检测范围（勾选目录）</div>
          <div class="toolbar">
            <el-input v-model="host.root" placeholder="根目录，例如 /srv" style="width: 260px" />
            <el-button :loading="host.busy" @click="wizard.browseHost(host)">扫描目录树</el-button>
            <span class="muted">已选 {{ host.selected.length }} 个目录</span>
          </div>
          <el-table v-if="host.rows.length" :data="host.rows" size="small" max-height="240">
            <el-table-column width="50"><template #default="{ row }">
              <el-checkbox :model-value="host.selected.includes(row.path)" :disabled="row.type !== 'dir'"
                           @change="() => wizard.toggle(host, row.path)" />
            </template></el-table-column>
            <el-table-column label="路径" min-width="320">
              <template #default="{ row }"><span :style="{ paddingLeft: `${row.depth * 14}px` }">{{ row.name }}</span></template>
            </el-table-column>
            <el-table-column prop="type" label="类型" width="90" />
            <el-table-column prop="size" label="字节" width="100" />
          </el-table>
        </div>
      </template>

      <!-- 5. 任务属性 -->
      <template v-else>
        <el-form label-width="130px" size="small">
          <el-form-item label="检测项（策略组）">
            <el-select v-model="wizard.policyGroupIds.value" multiple filterable placeholder="留空用默认规则" style="width: 420px">
              <el-option v-for="group in wizard.groups.value" :key="group.id" :label="group.name" :value="group.id" />
            </el-select>
          </el-form-item>
          <el-form-item label="任务属性">
            <el-radio-group v-model="wizard.taskMode.value">
              <el-radio-button value="once">单次检测</el-radio-button>
              <el-radio-button value="scheduled">定时持续监测</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-if="wizard.taskMode.value === 'scheduled'" label="间隔（秒）">
            <el-input-number v-model="wizard.intervalSeconds.value" :min="60" :max="2592000" :step="600" />
          </el-form-item>
          <el-form-item label="流量监控抓包">
            <el-switch v-model="wizard.capture.value" />
            <div class="muted">开启后请把探针部署在网络关键位置以抓取全局流量；每 30 秒一段抓包并自动分析。</div>
          </el-form-item>
        </el-form>
        <el-alert type="warning" :closable="false" show-icon
                  title="注意：探针安装凭据在安装成功后即销毁，平台无法在任务结束时自动卸载探针——回收需要在任务结束后重新提供凭据执行卸载。" />
      </template>

      <template #footer>
        <el-button :disabled="wizard.step.value === 0" @click="wizard.step.value -= 1">上一步</el-button>
        <el-button v-if="wizard.step.value < 4" type="primary" @click="wizard.step.value += 1">下一步</el-button>
        <el-button v-else type="primary" :loading="wizard.busy.value" :disabled="!wizard.ready.value" @click="submitWizard">下发任务</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; }
.host-block { border: 1px solid var(--soc-border); border-radius: 8px; padding: 10px 12px; margin-bottom: 10px; }
.host-title { font-weight: 600; margin-bottom: 8px; }
.detail { padding: 6px 12px; font-size: 12px; line-height: 1.8; color: var(--soc-text-dim); word-break: break-all; }
:deep(.el-table__row) { cursor: pointer; }
</style>
