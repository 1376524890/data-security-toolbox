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
    { path: '/', title: '数据大屏', icon: 'Odometer' },
  ]},
  { group: '任务中心', items: [
    { path: '/tasks', title: '任务监控', icon: 'List' },
  ]},
  { group: '数据资产', items: [
    { path: '/data-assets', title: '数据资产', icon: 'Coin' },
  ]},
  { group: '数据流动与防护', items: [
    { path: '/network/dlp', title: '风险数据流动报告', icon: 'Lock' },
    { path: '/network/dlp', title: '数据出境报告', icon: 'Position', query: { view: 'egress' } },
  ]},
  { group: '文件证据', items: [
    { path: '/files', title: '风险文件', icon: 'Document' },
    { path: '/files', title: '风险 PCAP', icon: 'Connection', query: { view: 'pcaps' } },
  ]},
  { group: '采集与规则', items: [
    { path: '/collection-rules', title: '规则集与规则', icon: 'Collection' },
    { path: '/collection-rules', title: '规则版本', icon: 'Tickets', query: { view: 'versions' } },
    { path: '/collection-rules', title: '策略分组', icon: 'Files', query: { view: 'groups' } },
    { path: '/collection-rules', title: '出境判定名单', icon: 'Position', query: { view: 'egress' } },
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
