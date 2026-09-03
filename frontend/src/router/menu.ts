export interface MenuItem { path: string; title: string; icon: string }
export interface MenuGroup { group: string; items: MenuItem[] }
export type MenuNode = MenuItem | MenuGroup

export const menuGroups: MenuNode[] = [
  { path: '/', title: '安全驾驶舱', icon: 'Odometer' },
  { group: '安全运营', items: [
    { path: '/alerts', title: '告警中心', icon: 'Bell' },
    { path: '/incidents', title: '安全事件中心', icon: 'Warning' },
    { path: '/detections', title: '检测中心', icon: 'Aim' },
    { path: '/risk', title: '风险分析', icon: 'DataAnalysis' },
  ]},
  { group: '网络分析', items: [
    { path: '/network/pcap', title: 'PCAP 工作台', icon: 'Connection' },
    { path: '/network/live', title: '实时流量', icon: 'TrendCharts' },
    { path: '/network/flows', title: '会话流探索', icon: 'Share' },
    { path: '/network/protocols', title: '协议分析', icon: 'Operation' },
  ]},
  { group: '资产与数据安全', items: [
    { path: '/assets', title: '资产中心', icon: 'Monitor' },
    { path: '/data-assets', title: '数据资产', icon: 'Coin' },
    { path: '/sensitive', title: '敏感发现', icon: 'Search' },
    { path: '/files', title: '文件分析', icon: 'Document' },
  ]},
  { group: '威胁情报', items: [
    { path: '/threat/ioc', title: 'IOC 情报', icon: 'Aim' },
    { path: '/threat/cve', title: 'CVE 漏洞', icon: 'Warning' },
    { path: '/threat/rules', title: '检测规则', icon: 'Document' },
    { path: '/threat/offline', title: '离线资源', icon: 'Files' },
  ]},
  { group: '安全引擎', items: [
    { path: '/engines/zeek', title: 'Zeek', icon: 'Cpu' },
    { path: '/engines/suricata', title: 'Suricata', icon: 'Cpu' },
    { path: '/engines/sigma', title: 'Sigma', icon: 'Cpu' },
    { path: '/engines/wazuh', title: 'Wazuh', icon: 'Cpu' },
    { path: '/engines/osquery', title: 'osquery', icon: 'Cpu' },
    { path: '/engines/openscap', title: 'OpenSCAP', icon: 'Cpu' },
  ]},
  { group: '运维管理', items: [
    { path: '/probes', title: '探针管理', icon: 'Connection' },
    { path: '/tasks', title: '任务中心', icon: 'List' },
    { path: '/health', title: '健康状态', icon: 'Odometer' },
    { path: '/reports', title: '报告中心', icon: 'Document' },
  ]},
  { group: '工具', items: [
    { path: '/algorithms', title: '算法评估', icon: 'DataAnalysis' },
  ]},
]

export interface FlatRoute { path: string; title: string; group: string }

export function flatMenu(): FlatRoute[] {
  const out: FlatRoute[] = []
  menuGroups.forEach((node) => {
    if ('group' in node) node.items.forEach((item) => out.push({ path: item.path, title: item.title, group: node.group }))
    else out.push({ path: node.path, title: node.title, group: '总览' })
  })
  return out
}
