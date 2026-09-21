<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import DatabaseConnectionForm from './components/DatabaseConnectionForm.vue'
import DatabaseScanDetail from './components/DatabaseScanDetail.vue'
import { useDatabaseConnections } from './composables/useDatabaseConnections'

// The list, the create/edit draft, the scope picker and the scan history live in
// the composable; this view only binds them into the template below.
const {
  loading, error, connections, engines, note,
  formOpen, form, saving, testing, editing,
  selectedId, detail, scopeLoading, schemas, schema, tables, pickedTables,
  dispatching, scanOpen, scanDetail, autoRefresh, runsOn, confirmedTables, enabledCount, reachableCount,
  load, loadScans, select, openCreate, openEdit, save, remove, test,
  loadScope, loadTables, toggleTable, start, openScan,
  statusType, testLabel, reasonLabel,
} = useDatabaseConnections()

function formatTime(value: string | null | undefined): string {
  return value ? value.replace('T', ' ').slice(0, 19) : '—'
}

function coverage(row: { complete_scope: boolean | null }): string {
  return row.complete_scope === null ? '—' : row.complete_scope ? '完整' : '部分'
}
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <div class="toolbar-title">目标数据库连接（平台直连盘点）</div>
        <div class="toolbar-spacer" />
        <el-button type="primary" @click="openCreate">新建连接</el-button>
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="连接总数" :value="connections.length" />
        <StatCard label="已启用" :value="enabledCount" />
        <StatCard label="最近测试连通" :value="reachableCount" tone="success"
                  sub="只代表最近一次测试，不代表当前可用" />
        <StatCard label="当前选中" :value="runsOn || '未选择'" tone="info" />
      </div>

      <el-alert v-if="note" type="info" :closable="false" show-icon style="margin: 12px 0"
                :title="note" />

      <div class="soc-card">
        <el-table :data="connections" size="small" row-key="id" highlight-current-row
                  empty-text="尚未配置目标数据库连接" @row-click="select">
          <el-table-column prop="name" label="名称" min-width="150" show-overflow-tooltip />
          <el-table-column label="引擎" width="110">
            <template #default="{ row }">
              <el-tag size="small" type="info">{{ row.engine_label || row.engine }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="地址" min-width="190">
            <template #default="{ row }"><code class="key">{{ row.host }}:{{ row.port }}</code></template>
          </el-table-column>
          <el-table-column prop="database" label="库/schema" width="120" show-overflow-tooltip />
          <el-table-column prop="username" label="账号" width="110" show-overflow-tooltip />
          <el-table-column label="密码" width="80">
            <template #default="{ row }">
              <el-tag size="small" :type="row.password_set ? 'success' : 'warning'">
                {{ row.password_set ? '已保存' : '未设置' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="连通测试" width="150">
            <template #default="{ row }">
              <el-tag size="small" :type="statusType(row.last_test_status)">
                {{ testLabel(row.last_test_status) }}
              </el-tag>
              <div class="muted small">{{ formatTime(row.last_test_at) }}</div>
            </template>
          </el-table-column>
          <el-table-column label="启用" width="70">
            <template #default="{ row }">
              <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '是' : '否' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="最近采集" width="160">
            <template #default="{ row }">{{ formatTime(row.last_scan_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="215" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" :loading="testing === row.id"
                         @click.stop="test(row)">测试连接</el-button>
              <el-button link size="small" @click.stop="openEdit(row)">编辑</el-button>
              <el-button link type="danger" size="small" @click.stop="remove(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div v-if="selectedId" class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title">
          <span class="dot" />采集范围：{{ runsOn }}
          <div class="toolbar-spacer" />
          <el-switch v-model="autoRefresh" size="small" active-text="自动刷新任务" />
          <el-button size="small" :loading="scopeLoading" @click="loadScope">读取库与表</el-button>
          <el-button size="small" @click="loadScans">刷新任务</el-button>
        </div>
        <el-form inline label-width="88px" style="margin-bottom: 8px">
          <el-form-item label="库 / schema">
            <el-select v-model="schema" style="width: 240px" placeholder="先读取库列表"
                       :disabled="!schemas.length" @change="loadTables">
              <el-option v-for="name in schemas" :key="name" :label="name" :value="name" />
            </el-select>
          </el-form-item>
          <el-form-item label="已选表">
            <span>{{ pickedTables.length }} 张（该库共 {{ confirmedTables }} 张普通表）</span>
          </el-form-item>
          <el-form-item>
            <el-button link type="primary" @click="pickedTables = []">清空选择</el-button>
          </el-form-item>
        </el-form>
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 10px"
                  title="采集以只读会话连接目标，只读取每张表的样本行（服务端上限），登记表/列元数据与命中的敏感性类型，不导出整表数据。不选表时按整库（schema 内全部表，受预算上限约束）采集。" />
        <el-table :data="tables" size="small" max-height="320"
                  empty-text="尚未读取目标表清单；点击「读取库与表」从目标库读取">
          <el-table-column label="选择" width="70">
            <template #default="{ row }">
              <el-checkbox :model-value="pickedTables.includes(row.name)"
                           :disabled="row.kind !== 'table'" @change="toggleTable(row.name)" />
            </template>
          </el-table-column>
          <el-table-column prop="name" label="表名" min-width="240" show-overflow-tooltip />
          <el-table-column prop="kind" label="类型" width="110" />
          <el-table-column prop="columns" label="列数" width="80" />
        </el-table>
        <div class="toolbar" style="margin-top: 10px">
          <span class="muted small">视图/系统表默认不勾选，避免把元数据当业务数据盘点。</span>
          <div class="toolbar-spacer" />
          <el-button type="primary" :loading="dispatching" @click="start">启动采集</el-button>
        </div>
      </div>

      <div v-if="detail" class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />采集任务（最近 10 次）</div>
        <el-table :data="detail.scans" size="small" empty-text="该连接尚未发起采集">
          <el-table-column prop="task_id" label="任务" width="80" />
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag size="small" :type="statusType(row.status)">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="stage" label="阶段" min-width="150" show-overflow-tooltip />
          <el-table-column label="进度" width="80">
            <template #default="{ row }">{{ row.progress }}%</template>
          </el-table-column>
          <el-table-column label="表(已读/总数)" width="130">
            <template #default="{ row }">{{ row.tables_scanned }} / {{ row.tables_total }}</template>
          </el-table-column>
          <el-table-column prop="rows_read" label="样本行" width="100" />
          <el-table-column prop="hits" label="命中" width="90" />
          <el-table-column label="覆盖" width="80">
            <template #default="{ row }">{{ coverage(row) }}</template>
          </el-table-column>
          <el-table-column label="结束原因" width="140">
            <template #default="{ row }">{{ reasonLabel(row.termination_reason) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="90" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="openScan(row)">详情</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <DatabaseConnectionForm v-model="formOpen" :form="form" :engines="engines"
                              :editing="editing" :saving="saving" @save="save" />

      <DatabaseScanDetail v-model="scanOpen" :scan-detail="scanDetail" />
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.key { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.muted { color: var(--soc-text-dim); }
.small { font-size: 12px; }
</style>
