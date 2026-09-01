<template>
  <div>
    <h2 class="page-title">报告中心</h2>

    <div class="stat-row">
      <div v-for="(t, key) in moduleMeta" :key="key" class="stat-card">
        <div class="label">{{ t.label }}</div>
        <div class="value">{{ (summary.by_type && summary.by_type[key]?.count) || 0 }}</div>
        <div class="sub">{{ summary.by_type && summary.by_type[key]?.latest ? '最近: ' + fmtTime(summary.by_type[key].latest) : '暂无报告' }}</div>
      </div>
    </div>
    <div class="stat-card total"><div class="label">报告总计</div><div class="value">{{ summary.total_reports || 0 }}</div></div>

    <!-- 快捷入口 -->
    <div class="panel">
      <div class="panel-title">五大检测模块</div>
      <div class="module-grid">
        <el-card v-for="m in moduleMetaArr" :key="m.key" class="module-card" shadow="hover" @click="go(m.key)">
          <div class="m-icon">{{ m.icon }}</div>
          <div class="m-name">{{ m.label }}</div>
          <div class="m-desc">{{ m.desc }}</div>
          <el-button type="primary" size="small" style="margin-top:10px">进入分析</el-button>
        </el-card>
      </div>
    </div>

    <!-- 各类型报告列表 -->
    <el-tabs v-model="activeType">
      <el-tab-pane v-for="(t, key) in moduleMeta" :key="key" :name="key" :label="`${t.label}(${sumOf(key)})`">
        <el-table :data="reports" stripe size="small" empty-text="暂无该类型报告">
          <el-table-column prop="id" label="报告 ID" width="210" />
          <el-table-column prop="probe_id" label="来源探针" width="150" />
          <el-table-column prop="task_id" label="任务 ID" width="150" />
          <el-table-column label="生成时间" width="200">
            <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="操作">
            <template #default="{ row }">
              <el-button size="small" type="primary" link @click="viewDetail(row)">查看详情</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <!-- 详情抽屉 -->
    <el-drawer v-model="drawer" title="报告详情" size="55%">
      <pre class="detail-pre">{{ detailJson }}</pre>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const router = useRouter()
const summary = ref({})
const activeType = ref('asset')
const reports = ref([])
const drawer = ref(false)
const detail = ref({})

const moduleMeta = {
  asset: { label: '数据资产识别', icon: '资产', path: '/results/asset', desc: '数据分类分级与敏感数据识别' },
  metadata: { label: '元数据分析', icon: '元数', path: '/results/metadata', desc: 'EXIF/文档元数据提取与风险评估' },
  algo: { label: '密码算法评估', icon: '算法', path: '/results/algo', desc: '商用密码算法识别与合规评级' },
  protocol: { label: '网络协议分析', icon: '协议', path: '/results/protocol', desc: '流量逐层解码与会话重组' },
  traffic: { label: '网络流量分析', icon: '流量', path: '/results/traffic', desc: '流量统计与入侵检测告警' }
}
const moduleMetaArr = Object.entries(moduleMeta).map(([key, v]) => ({ key, ...v }))

const detailJson = computed(() => JSON.stringify(detail.value, null, 2))
const sumOf = (key) => (summary.value.by_type && summary.value.by_type[key]?.count) || 0

function fmtTime(t) { return t ? t.replace('T', ' ').slice(0, 19) : '' }

async function loadSummary() {
  try { summary.value = (await api.resultSummary()).data } catch (e) { /* 忽略 */ }
}

async function loadReports() {
  try {
    const res = await api.results(activeType.value)
    reports.value = res.data.reports || []
  } catch (e) {
    reports.value = []
    ElMessage.warning('获取报告列表失败')
  }
}

function go(key) { router.push(moduleMeta[key].path) }

async function viewDetail(row) {
  drawer.value = true
  detail.value = { loading: true }
  try {
    detail.value = (await api.resultDetail(row.id)).data
  } catch (e) {
    detail.value = { error: '加载失败' }
  }
}

watch(activeType, loadReports)

onMounted(() => { loadSummary(); loadReports() })
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.stat-row { display: flex; gap: 12px; margin-bottom: 12px; }
.stat-card { flex: 1; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 16px; }
.stat-card.total { max-width: 200px; }
.label { color: var(--text-secondary); font-size: 13px; }
.value { font-size: 24px; font-weight: 700; margin-top: 4px; }
.sub { color: var(--text-muted); font-size: 12px; margin-top: 6px; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; margin-bottom: 16px; }
.panel-title { font-weight: 700; margin-bottom: 12px; }
.module-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.module-card { text-align: center; cursor: pointer; }
.m-icon { font-size: 20px; font-weight: 700; color: var(--color-primary); background: var(--el-color-primary-light-9); width: 44px; height: 44px; line-height: 44px; border-radius: var(--radius); margin: 0 auto; }
.m-name { font-weight: 700; margin: 6px 0 2px; }
.m-desc { color: var(--text-secondary); font-size: 12px; }
.detail-pre { background: var(--bg-code); padding: 12px; border-radius: var(--radius-sm); max-height: 70vh; overflow: auto; font-size: 12px; color: var(--text-primary); }
</style>