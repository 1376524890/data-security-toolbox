import { createRouter, createWebHistory } from 'vue-router'

// 路由守卫：基于 JWT 的登录态检查（阶段二起预留）
const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/dashboard' },
    { path: '/dashboard', name: 'Dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: '总览仪表盘' } },
    { path: '/probes', name: 'Probes', component: () => import('../views/Probes.vue'), meta: { title: '探针管理' } },
    { path: '/tasks', name: 'Tasks', component: () => import('../views/Tasks.vue'), meta: { title: '任务管理' } },
    { path: '/results/asset', name: 'AssetResults', component: () => import('../views/AssetResults.vue'), meta: { title: '数据资产识别' } },
    { path: '/results/metadata', name: 'MetadataResults', component: () => import('../views/MetadataResults.vue'), meta: { title: '元数据分析' } },
    { path: '/results/algo', name: 'AlgoResults', component: () => import('../views/AlgoResults.vue'), meta: { title: '算法评估' } },
    { path: '/results/protocol', name: 'ProtocolResults', component: () => import('../views/ProtocolResults.vue'), meta: { title: '协议分析' } },
    { path: '/results/traffic', name: 'TrafficResults', component: () => import('../views/TrafficResults.vue'), meta: { title: '流量分析' } },
    { path: '/tools/regex-gen', name: 'RegexGen', component: () => import('../views/RegexGen.vue'), meta: { title: '正则生成器' } },
    { path: '/reports', name: 'Reports', component: () => import('../views/Reports.vue'), meta: { title: '报告中心' } },
    { path: '/settings', name: 'Settings', component: () => import('../views/Settings.vue'), meta: { title: '系统设置' } }
  ]
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} - 数据安全检测工具箱` : '数据安全检测工具箱'
})

export default router