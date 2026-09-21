/** The sidebar: six top-level sections, each with its own sub-list.

 * There is no separate "group" level above these — 资产中心 / 任务中心 / 数据资产 /
 * 数据流动与防护 / 文件证据 / 采集与规则 ARE the sections, and every page lives
 * under one of them. A sub-item that opens a tab of a hub carries its own
 * ``view`` query, so the same route can appear more than once with a distinct
 * highlight and a distinct deep link.
 */
export interface MenuItem {
  path: string
  title: string
  icon: string
  query?: Record<string, string>
}

export interface MenuGroup {
  group: string
  items: MenuItem[]
}

/** The el-menu index for an item: path plus its view query, so two sub-items on
 * the same route never share a highlight. */
export function menuIndex(item: MenuItem): string {
  const query = item.query ? new URLSearchParams(item.query).toString() : ''
  return query ? `${item.path}?${query}` : item.path
}

export const menuGroups: MenuGroup[] = [
  { group: '资产中心', items: [
    { path: '/', title: '安全驾驶舱', icon: 'Odometer' },
    { path: '/assets', title: '资产大屏', icon: 'Monitor' },
    { path: '/probes', title: '探针管理', icon: 'Connection' },
    { path: '/probe-deployments', title: '探针部署', icon: 'Position' },
    { path: '/health', title: '健康状态', icon: 'Odometer' },
    { path: '/reports', title: '报告中心', icon: 'Document' },
    { path: '/audit', title: '安全审计', icon: 'DocumentChecked' },
  ]},
  { group: '任务中心', items: [
    { path: '/tasks', title: '任务监控', icon: 'List' },
  ]},
  { group: '数据资产', items: [
    { path: '/data-assets', title: '数据资产', icon: 'Coin' },
    { path: '/data-assets', title: '资产目录', icon: 'Grid', query: { view: 'inventory' } },
    { path: '/data-assets', title: '数据类型', icon: 'Files', query: { view: 'types' } },
    { path: '/data-assets', title: '数据安全评估', icon: 'DataAnalysis', query: { view: 'assessment' } },
    { path: '/detections', title: '检测中心', icon: 'Aim' },
    { path: '/alerts', title: '告警中心', icon: 'Bell' },
    { path: '/incidents', title: '安全事件中心', icon: 'Warning' },
    { path: '/risk', title: '风险分析', icon: 'TrendCharts' },
  ]},
  { group: '数据流动与防护', items: [
    { path: '/network/dlp', title: '传输结果', icon: 'Lock' },
    { path: '/network/dlp', title: '数据流动', icon: 'Share', query: { view: 'flow' } },
    { path: '/network/dlp', title: '数据出境', icon: 'Position', query: { view: 'egress' } },
    { path: '/network/pcap', title: 'PCAP 工作台', icon: 'Connection' },
    { path: '/network/live', title: '实时流量', icon: 'TrendCharts' },
    { path: '/network/flows', title: '会话流探索', icon: 'Share' },
    { path: '/network/protocols', title: '协议分析', icon: 'Operation' },
  ]},
  { group: '文件证据', items: [
    { path: '/files', title: '文件证据', icon: 'Document' },
  ]},
  { group: '采集与规则', items: [
    { path: '/collection-rules', title: '来源管理', icon: 'DataLine' },
    { path: '/collection-rules', title: '扫描配置', icon: 'Setting', query: { view: 'profiles' } },
    { path: '/collection-rules', title: '采集任务', icon: 'Upload', query: { view: 'jobs' } },
    { path: '/collection-rules', title: '规则版本', icon: 'Tickets', query: { view: 'versions' } },
    { path: '/collection-rules', title: '策略分组', icon: 'Collection', query: { view: 'groups' } },
    { path: '/collection-rules', title: '检测规则库', icon: 'Document', query: { view: 'library' } },
    { path: '/threat/ioc', title: 'IOC 情报', icon: 'Aim' },
    { path: '/threat/cve', title: 'CVE 漏洞', icon: 'Warning' },
    { path: '/engines', title: '引擎总览', icon: 'Cpu' },
    { path: '/algorithms', title: '算法评估', icon: 'DataAnalysis' },
  ]},
]

export interface FlatRoute { path: string; title: string; group: string; query?: Record<string, string> }

/** Flat view of the menu, used to resolve a route's display title. A sub-item
 * with a ``view`` query only matches when that query is present. */
export function flatMenu(): FlatRoute[] {
  return menuGroups.flatMap((section) => section.items.map((item) => ({
    path: item.path, title: item.title, group: section.group, query: item.query,
  })))
}

/** The menu entry that should be highlighted for the current route, if any. */
export function activeMenuIndex(path: string, query: Record<string, unknown>): string {
  const view = query.view ? String(query.view) : ''
  const exact = flatMenu().find((item) => item.path === path && (item.query?.view || '') === view)
  if (exact) return menuIndex({ path, title: exact.title, icon: '', query: exact.query })
  const queryless = flatMenu().find((item) => item.path === path && !item.query)
  if (queryless) return path
  const anyView = flatMenu().find((item) => item.path === path)
  return anyView ? menuIndex({ path, title: anyView.title, icon: '', query: anyView.query }) : path
}

/** The sub-item (title + section) a route maps to, matched on path **and** view
 * query so two sub-items that share a route resolve to themselves. */
export function activeMenuEntry(path: string, query: Record<string, unknown>):
{ title: string; group: string } | undefined {
  const view = query.view ? String(query.view) : ''
  const items = flatMenu()
  const exact = items.find((item) => item.path === path && (item.query?.view || '') === view)
    || items.find((item) => item.path === path && !item.query)
    || items.find((item) => item.path === path)
  if (exact) return exact
  // Detail routes (/data-types/:category, /data-objects/:id, …) belong to the
  // section whose entry is their longest path prefix.
  const owner = items
    .filter((item) => item.path !== '/' && path.startsWith(item.path))
    .sort((a, b) => b.path.length - a.path.length)[0]
  return owner
}
