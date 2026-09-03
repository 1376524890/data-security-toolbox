import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from './views/DashboardView.vue'
import IncidentsView from './views/IncidentsView.vue'
import DetectionsView from './views/DetectionsView.vue'
import RiskView from './views/RiskView.vue'
import AssetsView from './views/AssetsView.vue'
import DataAssetsView from './views/DataAssetsView.vue'
import GraphView from './views/GraphView.vue'
import FilesView from './views/FilesView.vue'
import PcapsView from './views/PcapsView.vue'
import IntelligenceView from './views/IntelligenceView.vue'
import IntegrationsView from './views/IntegrationsView.vue'
import AuditView from './views/AuditView.vue'
import AlgorithmsView from './views/AlgorithmsView.vue'
import TasksView from './views/TasksView.vue'
import ProbesView from './views/ProbesView.vue'
import ReportsView from './views/ReportsView.vue'
import OfflineResourcesView from './views/OfflineResourcesView.vue'
import AlertsView from './views/AlertsView.vue'
import LoginView from './views/LoginView.vue'
import { me } from './api/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: LoginView, meta: { title: '登录' } },
    { path: '/', component: DashboardView, meta: { title: '安全态势 / 总览' } },
    { path: '/alerts', component: AlertsView, meta: { title: '安全调查 / 告警中心' } },
    { path: '/incidents', component: IncidentsView, meta: { title: '安全调查 / 安全事件' } },
    { path: '/detections', component: DetectionsView, meta: { title: '安全调查 / 检测结果' } },
    { path: '/risk', component: RiskView, meta: { title: '安全调查 / 风险分析' } },
    { path: '/assets', component: AssetsView, meta: { title: '资产与数据 / IT资产' } },
    { path: '/data-assets', component: DataAssetsView, meta: { title: '资产与数据 / 数据资产' } },
    { path: '/graph', component: GraphView, meta: { title: '资产与数据 / 资产关系图' } },
    { path: '/files', component: FilesView, meta: { title: '资产与数据 / 文件分析' } },
    { path: '/pcaps', component: PcapsView, meta: { title: '网络分析 / PCAP分析' } },
    { path: '/intelligence', component: IntelligenceView, meta: { title: '威胁与检测 / 威胁情报' } },
    { path: '/integrations', component: IntegrationsView, meta: { title: '威胁与检测 / 检测组件' } },
    { path: '/audit', component: AuditView, meta: { title: '威胁与检测 / 安全审计' } },
    { path: '/algorithms', component: AlgorithmsView, meta: { title: '威胁与检测 / 算法评估' } },
    { path: '/tasks', component: TasksView, meta: { title: '运行管理 / 任务中心' } },
    { path: '/probes', component: ProbesView, meta: { title: '运行管理 / 探针管理' } },
    { path: '/reports', component: ReportsView, meta: { title: '运行管理 / 报告中心' } },
    { path: '/offline-resources', component: OfflineResourcesView, meta: { title: '系统 / 离线资源' } },
  ],
})

router.beforeEach(async (to) => {
  if (to.path === '/login') return true
  try {
    await me()
    return true
  } catch {
    return '/login'
  }
})

export default router
