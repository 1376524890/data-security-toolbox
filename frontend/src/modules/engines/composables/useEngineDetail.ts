/**
 * Engine detail state: the registry entry behind a console route, the matching
 * integration, the rule inventory, the findings and the recent tasks.
 *
 * `name` is the route-derived computed ref, handed in so the page keeps owning
 * the route.  The console route (``/engines/sigma``) and the name a finding is
 * stored under (``sigma_log_engine``) differ, so the route is resolved through
 * the registry; the rule count comes from the registry as well, because
 * ``/health`` only reports tshark/zeek/suricata.  The static labels stay in the
 * view, everything the server answers with lives here.
 */
import { computed, onMounted, ref, watch, type ComputedRef } from 'vue'
import { listIntegrations } from '../../../api/integrations'
import { getHealth, type HealthResponse } from '../../../api/health'
import { getEngineRegistry, type EngineInfo } from '../../../api/engine'
import { listTasks } from '../../../api/tasks'
import { listDetections } from '../../../api/detections'
import { listRules, getRuleContent, type RuleItem } from '../../../api/rules'
import type { IntegrationStatus } from '../../../types/integration'
import type { Task } from '../../../types/task'
import type { DetectionFinding } from '../../../types/finding'
import type { EngineStatus } from '../../../components/security/EngineStatusCard.vue'

export function useEngineDetail(name: ComputedRef<string>) {
  const loading = ref(true)
  const error = ref('')
  const integrations = ref<IntegrationStatus[]>([])
  const health = ref<HealthResponse | null>(null)
  const engines = ref<EngineInfo[]>([])
  const tasks = ref<Task[]>([])
  const findings = ref<DetectionFinding[]>([])
  const findingsTotal = ref(0)
  const rules = ref<RuleItem[]>([])
  const ruleKeyword = ref('')
  const rulePage = ref(1)
  const filteredRules = computed(() => rules.value.filter(item =>
    `${item.name} ${item.rule_id || ''} ${item.path}`.toLowerCase().includes(ruleKeyword.value.toLowerCase())))
  const visibleRules = computed(() => filteredRules.value.slice((rulePage.value - 1) * 30, rulePage.value * 30))

  async function expandRule(row: RuleItem, expanded: RuleItem[]): Promise<void> {
    if (!expanded.includes(row) || row.content) return
    try { row.content = (await getRuleContent(row)).content }
    catch (err) { error.value = err instanceof Error ? err.message : String(err) }
  }
  watch(ruleKeyword, () => { rulePage.value = 1 })
  watch(name, () => { rulePage.value = 1; void load() })

  // ``/engines/sigma`` is a console route while a finding stores the engine's own
  // name (``sigma_log_engine``). Resolving the route through the registry is what
  // makes the rule count, the rule list and the detection list agree: filtering
  // findings by the route name returned nothing for every engine.
  const engineMeta = computed(() =>
    engines.value.find((e) => (e.slug || e.name) === name.value || e.name.toLowerCase() === name.value.toLowerCase()),
  )
  const detectionEngine = computed(() => engineMeta.value?.detection_engine || name.value)
  const engineOptions = computed(() =>
    engines.value.map((e) => ({ value: e.slug || e.name, label: `${e.label || e.name} (${e.detection_count ?? 0})` })),
  )

  // The rule inventory comes from the registry. ``/health`` only reports
  // tshark/zeek/suricata, so overriding an adapter's own count with it blanked the
  // rule number on every other engine page.
  const ruleCount = computed<number | null>(() => {
    if (typeof engineMeta.value?.rule_count === 'number') return engineMeta.value.rule_count
    const adapter = integrations.value.find((i) => i.name.toLowerCase() === name.value.toLowerCase())
    return typeof adapter?.rule_count === 'number' ? adapter.rule_count : null
  })

  const integration = computed<EngineStatus | null>(() => {
    const item = integrations.value.find((i) => i.name.toLowerCase() === name.value.toLowerCase())
    if (!item) return null
    return { ...item, rule_count: ruleCount.value ?? item.rule_count }
  })

  const isSigma = computed(() => (engineMeta.value?.name || name.value) === 'sigma_log_engine')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [ints, h, eng, taskResult] = await Promise.all([
        listIntegrations(),
        getHealth(),
        getEngineRegistry(),
        listTasks({ page: 1, page_size: 20 }),
      ])
      integrations.value = ints
      health.value = h
      engines.value = eng
      tasks.value = taskResult.items
      // Rules and detections are fetched by the engine's own name, which is only
      // known once the registry has answered.
      const [ruleResult, found] = await Promise.all([
        listRules({ engine: detectionEngine.value, include_content: false }),
        listDetections({ engine: detectionEngine.value, page: 1, page_size: 20 }),
      ])
      rules.value = ruleResult.items
      findings.value = found.items
      findingsTotal.value = found.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  onMounted(load)

  return {
    loading, error, integrations, health, engines, tasks, findings, findingsTotal, rules,
    ruleKeyword, rulePage, filteredRules, visibleRules, engineMeta, engineOptions, ruleCount,
    integration, isSigma, expandRule, load,
  }
}
