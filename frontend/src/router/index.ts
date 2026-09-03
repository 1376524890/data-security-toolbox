import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { flatMenu } from './menu'
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
  { path: '/assets', component: () => import('../modules/asset/AssetCenter.vue'), meta: { title: 'Asset Center', group: 'Asset & Data Security' } },
  { path: '/data-assets', component: () => import('../modules/data-security/DataAsset.vue'), meta: { title: 'Data Asset', group: 'Asset & Data Security' } },
  { path: '/sensitive', component: () => import('../modules/data-security/SensitiveDiscovery.vue'), meta: { title: 'Sensitive Discovery', group: 'Asset & Data Security' } },
  { path: '/files', component: () => import('../modules/data-security/FileAnalysis.vue'), meta: { title: 'File Analysis', group: 'Asset & Data Security' } },
  // Threat Intelligence
  { path: '/threat/ioc', component: () => import('../modules/threat/IocCenter.vue'), meta: { title: 'IOC', group: 'Threat Intelligence' } },
  { path: '/threat/cve', component: () => import('../modules/threat/CveCenter.vue'), meta: { title: 'CVE', group: 'Threat Intelligence' } },
  { path: '/threat/rules', component: () => import('../modules/threat/RulesCenter.vue'), meta: { title: 'Rules', group: 'Threat Intelligence' } },
  { path: '/threat/offline', component: () => import('../modules/threat/OfflineResource.vue'), meta: { title: 'Offline Resource', group: 'Threat Intelligence' } },
  // Security Engines
  { path: '/engines/:name', component: () => import('../modules/engines/EngineDetail.vue'), meta: { title: 'Engine', group: 'Security Engines' } },
  // Operations
  { path: '/probes', component: () => import('../modules/operations-admin/ProbeCenter.vue'), meta: { title: 'Probe', group: 'Operations' } },
  { path: '/tasks', component: () => import('../modules/operations-admin/TaskCenter.vue'), meta: { title: 'Tasks', group: 'Operations' } },
  { path: '/health', component: () => import('../modules/operations-admin/HealthCenter.vue'), meta: { title: 'Health', group: 'Operations' } },
  { path: '/reports', component: () => import('../modules/operations-admin/ReportCenter.vue'), meta: { title: 'Reports', group: 'Operations' } },
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
  const flat = flatMenu()
  const match = flat.find((m) => m.path === to.path)
  if (match) to.meta.title = match.title
  return true
})

export default router
