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
    // 数据安全态势大屏: the platform-wide homepage, drawn without the console
    // shell (the sidebar and header step aside for the wall view).
    path: '/',
    component: () => import('../modules/dashboard/DashboardScreen.vue'),
    meta: { title: '数据安全态势大屏', group: 'Overview', layout: 'screen' },
  },
  {
    // 数据安全综合驾驶舱: the daily-use page, inside the console shell.
    path: '/cockpit',
    component: () => import('../modules/dashboard/cockpit/DashboardCockpit.vue'),
    meta: { title: '数据安全驾驶舱', group: 'Overview' },
  },
  // Asset & Data Security
  // 任务中心 owns dispatch + progress + sources + scan config.
  { path: '/tasks', component: () => import('../modules/tasks/TaskCenter.vue'), meta: { title: '任务中心', group: 'Asset & Data Security' } },
  // 数据资产: one hub with the object model, the inventory and the assessment tabs.
  { path: '/data-assets', component: () => import('../modules/data-security/DataAssetHub.vue'), meta: { title: '数据资产', group: 'Asset & Data Security' } },
  // 采集与规则 owns sources, scan config, collection jobs and all rule management.
  { path: '/collection-rules', component: () => import('../modules/collection/CollectionRules.vue'), meta: { title: '采集与规则', group: 'Asset & Data Security' } },
  { path: '/files', component: () => import('../modules/data-security/FileEvidence.vue'), meta: { title: '文件证据', group: 'Asset & Data Security' } },
  // 数据流动与防护 keeps only results and the egress verdict.
  { path: '/network/dlp', component: () => import('../modules/data-security/flow/DataFlowProtection.vue'), meta: { title: '数据流动与防护', group: 'Asset & Data Security' } },
  // Old top-level routes are gone from the menu; these redirects keep deep links
  // and any bookmark working without re-introducing a second navigation entry.
  { path: '/asset-inventory', redirect: { path: '/data-assets' } },
  { path: '/data-types', redirect: { path: '/data-assets' } },
  { path: '/sensitive', redirect: { path: '/data-assets' } },
  { path: '/data-asset-jobs', redirect: { path: '/collection-rules', query: { view: 'jobs' } } },
  { path: '/source-management', redirect: { path: '/collection-rules' } },
  { path: '/database-connections', redirect: { path: '/collection-rules' } },
  { path: '/scan-profiles', redirect: { path: '/collection-rules' } },
  { path: '/rule-versions', redirect: { path: '/collection-rules', query: { view: 'versions' } } },
  { path: '/threat/rules', redirect: { path: '/collection-rules' } },
  { path: '/threat/ioc', redirect: { path: '/collection-rules' } },
  { path: '/threat/cve', redirect: { path: '/collection-rules' } },
  { path: '/threat/offline', redirect: { path: '/collection-rules' } },
  { path: '/engines', redirect: { path: '/collection-rules' } },
  { path: '/algorithms', redirect: { path: '/collection-rules' } },
  // 数据大屏 used to live at '/screen'; '/' is the wall view again, so old links
  // land on the same page instead of falling through the catch-all.
  { path: '/screen', redirect: { path: '/' } },
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
