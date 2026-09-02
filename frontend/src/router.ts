import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from './views/DashboardView.vue'
import AssetsView from './views/AssetsView.vue'
import FilesView from './views/FilesView.vue'
import PcapsView from './views/PcapsView.vue'
import AlgorithmsView from './views/AlgorithmsView.vue'
import TasksView from './views/TasksView.vue'
import ReportsView from './views/ReportsView.vue'
import AuditView from './views/AuditView.vue'
import ProbesView from './views/ProbesView.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: DashboardView },
    { path: '/assets', component: AssetsView },
    { path: '/files', component: FilesView },
    { path: '/pcaps', component: PcapsView },
    { path: '/algorithms', component: AlgorithmsView },
    { path: '/tasks', component: TasksView },
    { path: '/reports', component: ReportsView },
    { path: '/audit', component: AuditView },
    { path: '/probes', component: ProbesView },
  ],
})

