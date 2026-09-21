<script setup lang="ts">
import { useRouter } from 'vue-router'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import { useDataAssetJobs } from './composables/useDataAssetJobs'

// The job list, the polling timer and the API orchestration live in the
// composable; this view only binds them into the template below.
const router = useRouter()
const {
  loading, error, probes, profiles, jobs, probeId, profileId, pathsText, dispatching,
  autoRefresh, selectedProfile, statusType, coverageOf, running, finished, partial,
  load, loadJobs, dispatch, cancel, remove, coverageNote,
  assetJob, assetRows, assetLoading, assetError, assetPage, assetTotal, assetAssociation,
  openAssets, closeAssets, loadAssets,
} = useDataAssetJobs()
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <div class="toolbar-title">数据资产采集任务</div>
        <div class="toolbar-spacer" />
        <el-checkbox v-model="autoRefresh">自动刷新（5s）</el-checkbox>
        <el-button @click="loadJobs">刷新</el-button>
        <el-button @click="router.push('/scan-profiles')">扫描配置</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="进行中" :value="running" tone="primary" sub="Pending / Running" />
        <StatCard label="成功" :value="finished" tone="success" />
        <StatCard label="部分完成" :value="partial" tone="warning" sub="到达预算上限或未覆盖全部范围" />
        <StatCard label="可见任务" :value="jobs.length" sub="最近 50 条" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />下发新任务</div>
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 10px"
                  title="路径留空时使用所选扫描配置的 include_paths；显式填写路径则覆盖配置。探针在下次轮询时领取任务。" />
        <el-form label-width="110px">
          <el-form-item label="扫描配置">
            <el-select v-model="profileId" clearable placeholder="选择配置（可选）" style="width: 320px">
              <el-option v-for="item in profiles" :key="item.id"
                         :label="`${item.name} v${item.version}${item.enabled ? '' : '（已停用）'}`" :value="item.id" />
            </el-select>
            <span v-if="selectedProfile" class="muted" style="margin-left: 10px">
              {{ selectedProfile.include_paths.join('  ') || '未设置包含路径' }}
            </span>
          </el-form-item>
          <el-form-item label="覆盖路径">
            <el-input v-model="pathsText" type="textarea" :rows="2" placeholder="每行一个绝对路径；留空则使用配置" />
          </el-form-item>
          <el-form-item label="目标探针">
            <el-select v-model="probeId" placeholder="选择探针" style="width: 320px">
              <el-option v-for="probe in probes" :key="probe.id"
                         :label="`${probe.name}（${probe.ip_address || probe.hostname}）· ${probe.status}`" :value="probe.id" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="dispatching" :disabled="!probeId" @click="dispatch">下发任务</el-button>
          </el-form-item>
        </el-form>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />任务与进度</div>
        <el-table :data="jobs" size="small" empty-text="暂无数据资产任务">
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column label="状态" width="110">
            <template #default="{ row }">
              <el-tag size="small" :type="statusType(row.status)">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="进度" min-width="200">
            <template #default="{ row }">
              <el-progress :percentage="Math.min(row.progress || 0, 100)"
                           :status="row.status === 'Failed' ? 'exception' : row.status === 'Success' ? 'success' : undefined" />
              <div class="muted small">{{ row.current_stage }}</div>
            </template>
          </el-table-column>
          <el-table-column label="覆盖情况" min-width="220">
            <template #default="{ row }">
              <span v-if="(row.result || {}).files_analyzed === undefined && !Object.keys(coverageOf(row)).length" class="muted">—</span>
              <span v-else class="muted small">
                文件 {{ coverageOf(row).files_analyzed ?? '—' }} / {{ coverageOf(row).max_files ?? '—' }}，
                目录 {{ coverageOf(row).directories_scanned ?? coverageOf(row).directories_visited ?? '—' }}，
                读取 {{ coverageOf(row).bytes_read ?? '—' }} 字节
                <span v-if="coverageNote(row)" class="warn-text">{{ coverageNote(row) }}</span>
              </span>
            </template>
          </el-table-column>
          <el-table-column label="结果" width="200">
            <template #default="{ row }">
              <span v-if="row.result && row.result.assets !== undefined" class="small">
                资产 {{ row.result.assets }}，未观测到 {{ row.result.not_observed ?? 0 }}
                <span v-if="row.result.complete_scope === false" class="warn-text">（未完整覆盖，不会标记数据消失）</span>
              </span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="error" label="错误" min-width="140" show-overflow-tooltip>
            <template #default="{ row }"><span class="danger-text">{{ row.error || '' }}</span></template>
          </el-table-column>
          <el-table-column label="操作" width="190" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small"
                         @click="openAssets(row)">查看资产</el-button>
              <el-button link size="small" :disabled="!['Pending', 'Running'].includes(row.status)"
                         @click="cancel(row)">取消</el-button>
              <el-button link type="danger" size="small"
                         :disabled="['Pending', 'Running'].includes(row.status)" @click="remove(row)">移除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot warn" />尚未接入（P1）</div>
        <el-alert type="warning" :closable="false" show-icon
                  title="定时巡检、增量计划与业务系统范围（P1）尚未实现：平台不会自动下发扫描，也不会声称已按业务系统归类。" />
      </div>
    </StateBox>
    <el-drawer :model-value="!!assetJob" :title="`任务 #${assetJob?.id} · 采集资产`" size="860px" @close="closeAssets">
      <el-alert type="info" :closable="false" show-icon
                title="列出本任务关联的资产，详情显示资产当前状态；后续扫描可能更新内容和检测结果。" />
      <el-alert v-if="assetAssociation === 'latest_scan_only'" type="warning" :closable="false" show-icon
                title="旧任务未保存完整关联清单，仅展示最后一次扫描仍属于本任务的资产；被后续扫描更新的资产可能不在此列表，不能据此判断当时未采集。" style="margin-top: 10px" />
      <StateBox :loading="assetLoading" :error="assetError" :empty="false" @retry="loadAssets(assetPage)">
        <el-table :data="assetRows" size="small" empty-text="暂无可关联的已入库资产" style="margin-top: 12px">
          <el-table-column prop="path" label="资产路径" min-width="290" show-overflow-tooltip />
          <el-table-column prop="instance_type" label="类型" width="100" />
          <el-table-column prop="sensitivity" label="敏感级别" width="100" />
          <el-table-column prop="coverage" label="内容覆盖" width="100" />
          <el-table-column label="详情" width="90">
            <template #default="{ row }">
              <el-button link type="primary" @click="router.push(`/asset-instances/${row.id}`)">查看</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-pagination :current-page="assetPage" :page-size="50" :total="assetTotal"
                       layout="total, prev, pager, next" @current-change="loadAssets" />
      </StateBox>
    </el-drawer>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.muted { color: var(--soc-text-dim); }
.small { font-size: 12px; }
.warn-text { color: #f59e0b; }
.danger-text { color: #ef4444; }
</style>
