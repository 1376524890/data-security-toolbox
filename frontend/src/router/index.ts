import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { activeMenuEntry } from './menu'
import { useAuthStore } from '../stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    component: () => import('../views/LoginView.vue'),
    meta: { title: '登录', public: true },
  },
  {
    path: '/',
    component: () => import('../modules/dashboard/Dashboard.vue'),
    meta: { title: 'Dashboard', group: 'Overview' },
  },
  // Security Operations
  { path: '/alerts', component: () => import('../modules/operations/alerts/AlertCenter.vue'), meta: { title: 'Alert Center', group: 'Security Operations' } },
  { path: '/incidents', component: () => import('../modules/operations/incidents/IncidentCenter.vue'), meta: { title: 'Incident Center', group: 'Security Operations' } },
  { path: '/detections', component: () => import('../modules/operations/detections/DetectionCenter.vue'), meta: { title: 'Detection Center', group: 'Security Operations' } },
  { path: '/risk', component: () => import('../modules/operations/detections/RiskAnalysis.vue'), meta: { title: 'Risk Analysis', group: 'Security Operations' } },
  // Network Analysis
  { path: '/network/pcap', component: () => import('../modules/network/pcap/PcapWorkbench.vue'), meta: { title: 'PCAP Workbench', group: 'Network Analysis' } },
  { path: '/network/live', component: () => import('../modules/network/traffic/LiveTraffic.vue'), meta: { title: 'Live Traffic', group: 'Network Analysis' } },
  { path: '/network/flows', component: () => import('../modules/network/traffic/FlowExplorer.vue'), meta: { title: 'Flow Explorer', group: 'Network Analysis' } },
  { path: '/network/protocols', component: () => import('../modules/network/protocol/ProtocolAnalysis.vue'), meta: { title: 'Protocol Analysis', group: 'Network Analysis' } },
  // Asset & Data Security
  // 任务中心 owns dispatch + progress + sources + scan config.
  { path: '/tasks', component: () => import('../modules/tasks/TaskCenter.vue'), meta: { title: '任务中心', group: 'Asset & Data Security' } },
  // 数据资产: one hub with the object model, the inventory and the assessment tabs.
  { path: '/data-assets', component: () => import('../modules/data-security/DataAssetHub.vue'), meta: { title: '数据资产', group: 'Asset & Data Security' } },
  // 采集与规则 owns sources, scan config, collection jobs and all rule management.
  { path: '/collection-rules', component: () => import('../modules/collection/CollectionRules.vue'), meta: { title: '采集与规则', group: 'Asset & Data Security' } },
  { path: '/files', component: () => import('../modules/data-security/FileAnalysis.vue'), meta: { title: '文件证据', group: 'Asset & Data Security' } },
  { path: '/data-types/:category', component: () => import('../modules/data-security/DataTypeDetail.vue'), meta: { title: 'DataType Detail', group: 'Asset & Data Security' } },
  { path: '/data-objects/:id', component: () => import('../modules/data-security/DataObjectDetail.vue'), meta: { title: 'DataObject Detail', group: 'Asset & Data Security' } },
  { path: '/asset-instances/:id', component: () => import('../modules/data-security/AssetInstanceDetail.vue'), meta: { title: 'AssetInstance Detail', group: 'Asset & Data Security' } },
  // 数据流动与防护 keeps only results and the egress verdict.
  { path: '/network/dlp', component: () => import('../modules/data-security/flow/DataFlowProtection.vue'), meta: { title: '数据流动与防护', group: 'Asset & Data Security' } },
  // Old top-level routes are gone from the menu; these redirects keep deep links
  // and any bookmark working without re-introducing a second navigation entry.
  { path: '/asset-inventory', redirect: { path: '/data-assets', query: { view: 'inventory' } } },
  { path: '/data-types', redirect: { path: '/data-assets', query: { view: 'types' } } },
  { path: '/sensitive', redirect: { path: '/data-assets', query: { view: 'assessment' } } },
  { path: '/data-asset-jobs', redirect: { path: '/collection-rules', query: { view: 'jobs' } } },
  { path: '/source-management', redirect: { path: '/collection-rules', query: { view: 'sources' } } },
  { path: '/database-connections', redirect: { path: '/collection-rules', query: { view: 'sources' } } },
  { path: '/scan-profiles', redirect: { path: '/collection-rules', query: { view: 'profiles' } } },
  { path: '/rule-versions', redirect: { path: '/collection-rules', query: { view: 'versions' } } },
  // Threat Intelligence
  { path: '/threat/ioc', component: () => import('../modules/threat/IocCenter.vue'), meta: { title: 'IOC', group: 'Threat Intelligence' } },
  { path: '/threat/cve', component: () => import('../modules/threat/CveCenter.vue'), meta: { title: 'CVE', group: 'Threat Intelligence' } },
  // The detection-rule library is a tab of 采集与规则 now; keep the old URL alive.
  { path: '/threat/rules', redirect: { path: '/collection-rules', query: { view: 'library' } } },
  { path: '/threat/offline', component: () => import('../modules/threat/OfflineResource.vue'), meta: { title: 'Offline Resource', group: 'Threat Intelligence' } },
  // Security Engines
  { path: '/engines', component: () => import('../modules/engines/EnginesOverview.vue'), meta: { title: 'Engines', group: 'Security Engines' } },
  { path: '/engines/:name', component: () => import('../modules/engines/EngineDetail.vue'), meta: { title: 'Engine', group: 'Security Engines' } },
  // Operations
  // Tools
  { path: '/algorithms', component: () => import('../modules/tools/AlgorithmEvaluation.vue'), meta: { title: 'Algorithm Evaluation', group: 'Tools' } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const auth = useAuthStore()
  if (!auth.loaded) await auth.load()
  if (!auth.user) return { path: '/login', query: { redirect: to.fullPath } }
  const match = activeMenuEntry(to.path, to.query)
  if (match) to.meta.title = match.title
  return true
})

export default router
