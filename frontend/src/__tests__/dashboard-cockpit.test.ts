import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import ElementPlus from 'element-plus'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import DashboardCockpit from '../modules/dashboard/cockpit/DashboardCockpit.vue'
import * as dashboard from '../api/dashboard'
import { cockpitOverview, cockpitTasks, cockpitTrend } from './fixtures/cockpitOverview'

// ECharts needs a real canvas, which jsdom does not have; the option objects the
// page builds are asserted in the state test, so the drawing itself is stubbed.
const chart = vi.hoisted(() => ({
  setOption: vi.fn(), on: vi.fn(), off: vi.fn(), dispose: vi.fn(), resize: vi.fn(),
}))
vi.mock('echarts', () => {
  class LinearGradient { constructor(..._args: unknown[]) {} }
  return { init: () => chart, graphic: { LinearGradient } }
})

const push = vi.hoisted(() => vi.fn())
vi.mock('vue-router', () => ({ useRouter: () => ({ push }) }))

vi.mock('../api/dashboard', () => ({
  getCockpitOverview: vi.fn(), getCockpitTrend: vi.fn(), getCockpitTasks: vi.fn(),
}))

let app: App
let host: HTMLElement

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountPage = async () => {
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(DashboardCockpit)
  app.use(ElementPlus)
  // main.ts registers every icon globally; the cards look their icons up by name.
  for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
    app.component(key, component as never)
  }
  app.mount(host)
  await flushing()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(dashboard.getCockpitOverview).mockResolvedValue(cockpitOverview)
  vi.mocked(dashboard.getCockpitTrend).mockResolvedValue(cockpitTrend)
  vi.mocked(dashboard.getCockpitTasks).mockResolvedValue({ items: cockpitTasks })
})

afterEach(() => {
  app.unmount()
  host.remove()
})

describe('数据安全综合驾驶舱 view', () => {
  it('renders the eight KPI cards from the overview counters', async () => {
    await mountPage()
    const text = host.textContent || ''
    expect(host.querySelectorAll('.ov-card').length).toBe(8)
    for (const label of ['资产总数', '数据资产', '网络资产', '发现项', '安全事件', '告警',
      '高风险项', '数据外发事件']) {
      expect(text).toContain(label)
    }
    expect(text).toContain('3,685')
    expect(text).toContain('2,793')
    expect(text).toContain('979')
    expect(text).toContain('162')
    expect(text).toContain('771')
    // The week window and its honest fallback both render.
    expect(text).toContain('较上周')
    expect(text).toContain('+23%')
  })

  it('draws the posture ring, the focus list and the probe/engine rows', async () => {
    await mountPage()
    const text = host.textContent || ''
    expect(text).toContain('数据安全健康度')
    expect(text).toContain('78.6')
    expect(text).toContain('一般')
    // All four sub-scores come from the server, none are computed here.
    for (const label of ['资产安全', '数据防护', '检测响应', '合规管理']) {
      expect(text).toContain(label)
    }
    expect(text).toContain('82.0')
    // 本周重点关注 rows carry their own values and hints.
    expect(text).toContain('本周重点关注')
    expect(text).toContain('未处理告警')
    // The tail shows the week delta when there is one and the hint otherwise.
    expect(text).toContain('较上周 -50%')
    expect(text).toContain('需及时处理')
    // 探针与引擎状态 prints the real up/total pairs.
    expect(text).toContain('探针与引擎状态')
    expect(text).toContain('12/12')
    expect(text).toContain('5/8')
  })

  it('draws the four analysis cards with real categories and rates', async () => {
    await mountPage()
    const text = host.textContent || ''
    expect(text).toContain('资产分布')
    expect(text).toContain('风险等级分布')
    expect(text).toContain('合规检查完成情况')
    expect(text).toContain('数据流动审计')

    // 资产类型 tab: mapped labels, counts and the share of the ring.
    expect(text).toContain('主机')
    expect(text).toContain('1,245')
    // The share is of the slices actually drawn (1 245 / 2 466), not of the
    // asset total the KPI band shows - the ring never implies a hidden rest.
    expect(text).toContain('50.5%')
    // 风险等级 uses the console's 严重/高危/中危/低危 wording.
    expect(text).toContain('严重')
    expect(text).toContain('385')
    expect(text).toContain('16.5%')
    // 合规: the overall rate plus each check with its pair.
    expect(text).toContain('85%')
    expect(text).toContain('数据分类分级')
    expect(text).toContain('数据出境')
    // A check with no denominator says so instead of showing 0%.
    expect(text).toContain('无数据')
    // 数据流动: the three classes and the two headline boxes.
    expect(text).toContain('外部流出事件')
    expect(text).toContain('内部流动事件')
    expect(text).toContain('44')
    expect(text).toContain('30100'.replace('30100', '30,100'))
  })

  it('draws the closed loop with its counts and the newest tasks', async () => {
    await mountPage()
    const text = host.textContent || ''
    expect(text).toContain('数据安全闭环流程')
    for (const label of ['资产发现', '安全发现', '安全事件', '告警处置', '分析报告']) {
      expect(text).toContain(label)
    }
    expect(host.querySelectorAll('.sp-node').length).toBe(5)
    // 分析报告 has no console page: it is drawn, not clickable.
    const nodes = Array.from(host.querySelectorAll('.sp-node')) as HTMLElement[]
    expect(nodes[4].tagName).toBe('DIV')
    expect(nodes[0].tagName).toBe('BUTTON')

    // 最近任务 shows the task name from the payload, its kind and its status.
    expect(text).toContain('最近任务')
    expect(text).toContain('192.168.110.168 检查采集 /home')
    expect(text).toContain('文件采集')
    expect(text).toContain('部分完成')
    expect(text).toContain('主动扫描 192.168.110.168')
    expect(text).toContain('brand_new_kind')
  })

  it('opens the page that owns a KPI when the card is clicked', async () => {
    await mountPage()
    const cards = Array.from(host.querySelectorAll('.ov-card')) as HTMLElement[]
    cards[0].click()
    await nextTick()
    expect(push).toHaveBeenCalledWith('/data-assets')
    cards[2].click()
    await nextTick()
    expect(push).toHaveBeenCalledWith('/data-assets?view=network')
    cards[7].click()
    await nextTick()
    expect(push).toHaveBeenCalledWith('/network/dlp?view=egress')
    const steps = Array.from(host.querySelectorAll('.sp-node')) as HTMLElement[]
    steps[1].click()
    await nextTick()
    expect(push).toHaveBeenCalledWith('/files')
  })

  it('keeps the last good numbers and says they are old when a refresh fails', async () => {
    await mountPage()
    expect(host.textContent).toContain('3,685')
    vi.mocked(dashboard.getCockpitOverview).mockRejectedValue(new Error('网关超时'))
    await (host.querySelector('.ck-refresh') as HTMLElement).click()
    await flushing()
    expect(host.querySelector('.ck-stale')?.textContent).toContain('网关超时')
    expect(host.textContent).toContain('3,685')
  })
})
