/**
 * The data-security assessment state: one endpoint per tab, all sharing the same
 * five-段式 envelope. Results are cached per tab so switching back is instant,
 * and a failed refresh keeps the last good payload instead of blanking the page.
 */
import { computed, onMounted, ref } from 'vue'
import { getAssessment, type AssessmentEnvelope, type AssessmentKind } from '../../../../api/assessments'

export const ASSESSMENT_TABS: { key: AssessmentKind; label: string }[] = [
  { key: 'overview', label: '评估总览' },
  { key: 'classification', label: '数据分级' },
  { key: 'exposure', label: '数据脆弱性' },
  { key: 'compliance', label: '合规基线' },
]

export interface SectionTable {
  key: string
  title: string
  columns: { prop: string; label: string }[]
  rows: Record<string, unknown>[]
}

const COLUMNS: Record<string, { prop: string; label: string }[]> = {
  level_distribution: [
    { prop: 'level', label: '等级' }, { prop: 'name', label: '含义' }, { prop: 'count', label: '对象数' },
  ],
  types: [
    { prop: 'category', label: '类型' }, { prop: 'level', label: '分级' },
    { prop: 'object_count', label: '对象数' }, { prop: 'active_instance_count', label: '活跃实例' },
  ],
  protocols: [
    { prop: 'protocol', label: '协议' }, { prop: 'flows', label: '会话' }, { prop: 'bytes', label: '字节' },
  ],
  regions: [{ prop: 'region', label: '地区' }, { prop: 'count', label: '对象数' }],
  rules: [
    { prop: 'rule_id', label: '规则' }, { prop: 'title', label: '标题' }, { prop: 'severity', label: '严重度' },
  ],
  findings: [
    { prop: 'rule_id', label: '规则' }, { prop: 'severity', label: '严重度' }, { prop: 'count', label: '命中' },
  ],
  vulnerability_severity: [{ prop: 'severity', label: '严重度' }, { prop: 'count', label: '数量' }],
  finding_severity: [{ prop: 'severity', label: '严重度' }, { prop: 'count', label: '数量' }],
  dimensions: [
    { prop: 'label', label: '维度' }, { prop: 'title', label: '标题' }, { prop: 'conclusion', label: '结论' },
  ],
  transfers: [
    { prop: 'pcap_id', label: 'PCAP' }, { prop: 'filename', label: '对象' },
    { prop: 'dst_ip', label: '目的地址' }, { prop: 'bucket', label: '判定' },
    { prop: 'region', label: '地区' }, { prop: 'reason', label: '依据' },
  ],
}

const TITLES: Record<string, string> = {
  level_distribution: '分级分布',
  types: '类型明细',
  protocols: '协议分布',
  regions: '地区分布',
  rules: '适用合规项',
  findings: '合规命中',
  vulnerability_severity: '漏洞等级',
  finding_severity: '引擎发现等级',
  dimensions: '五个维度',
  transfers: '传输对象（出境判定）',
}

export function useDataSecurityAssessment() {
  const active = ref<AssessmentKind>('overview')
  const loading = ref(false)
  const error = ref('')
  const payloads = ref<Partial<Record<AssessmentKind, AssessmentEnvelope>>>({})

  const current = computed<AssessmentEnvelope | null>(() => payloads.value[active.value] || null)

  const tables = computed<SectionTable[]>(() => {
    const sections = current.value?.sections || {}
    const out: SectionTable[] = []
    for (const [key, columns] of Object.entries(COLUMNS)) {
      const rows = sections[key]
      if (Array.isArray(rows) && rows.length) {
        out.push({ key, title: TITLES[key] || key, columns, rows: rows as Record<string, unknown>[] })
      }
    }
    return out
  })

  const dedup = computed(() => (current.value?.sections?.dedup as Record<string, unknown>) || null)
  const direction = computed(() => (current.value?.sections?.direction as Record<string, number>) || null)
  const buckets = computed(() => (current.value?.sections?.buckets as Record<string, number>) || null)

  async function load(kind: AssessmentKind = active.value): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await getAssessment(kind)
      payloads.value = { ...payloads.value, [kind]: data }
    } catch (err) {
      error.value = String(err)
    } finally {
      loading.value = false
    }
  }

  function select(kind: AssessmentKind): void {
    active.value = kind
    if (!payloads.value[kind]) load(kind)
  }

  onMounted(() => load('overview'))

  return { active, loading, error, current, tables, dedup, direction, buckets, load, select }
}
