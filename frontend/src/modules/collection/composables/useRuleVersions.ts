/**
 * The rule-version console: the central rule set, its published versions and the
 * *observed* sync result per probe.
 *
 * The central rule set is the single source of truth for detection rules; this
 * page shows the published versions and what each probe actually reports, so a
 * failed hot update is visible instead of only in a probe log.
 *
 * The view keeps the template and the buttons; the API calls and the page state
 * live here.
 */
import { onMounted, ref, computed, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import {
  listRuleSets, listRuleSetVersions, publishRuleSetVersion, rollbackRuleSetVersion,
  type RuleSetSummary, type RuleSetVersion,
} from '../../../api/ruleSets'
import { listProbes, type Probe } from '../../../api/probes'
import { useAutoRefresh } from '../../../composables/useAutoRefresh'
import { useTableSort, sortRows } from '../../../composables/useTableSort'

export function useRuleVersions() {
  const loading = ref(true)
  const error = ref('')
  const ruleSet = ref<RuleSetSummary | null>(null)
  const versions = ref<RuleSetVersion[]>([])
  const probes = ref<Probe[]>([])

  const dialog = ref(false)
  const saving = ref(false)
  const draft = reactive({ version: '', changelog: '', min_agent_version: '' })

  // Both tables arrive whole (the versions of one rule set, one page of probes),
  // so filtering and sorting stay in the browser instead of costing a round trip
  // per keystroke. Each table owns its own sort state: sharing one would make a
  // click in the probe table re-order the version table behind it.
  const versionFilters = reactive({ search: '' })
  const probeFilters = reactive({ search: '', sync: '' })
  const versionTable = useTableSort()
  const probeTable = useTableSort()

  const activeVersion = computed(() => ruleSet.value?.active_version || null)
  const syncedProbes = computed(() => probes.value.filter((p) => probedVersion(p) !== ''))
  const outOfDateProbes = computed(() =>
    probes.value.filter((p) => {
      const current = probedVersion(p)
      return current !== '' && activeVersion.value !== null && current !== activeVersion.value.version
    }),
  )
  const failedProbes = computed(() => probes.value.filter((p) => String(probeField(p, 'ruleset_last_error') || '') !== ''))

  function md(probe: Probe): Record<string, unknown> {
    return (probe.metadata || {}) as Record<string, unknown>
  }
  function probeField(probe: Probe, key: string): unknown {
    return md(probe)[key]
  }
  function probedVersion(probe: Probe): string {
    return String(probeField(probe, 'current_ruleset_version') || '')
  }
  function shortHash(value: string): string {
    return value ? `${value.slice(0, 12)}…` : '—'
  }

  /** Sort the probe table by what it shows, not by where the value is stored. */
  function probeSortValue(row: Probe, prop: string): unknown {
    if (prop === 'current_ruleset_version') return probedVersion(row)
    return (row as unknown as Record<string, unknown>)[prop]
  }

  const visibleVersions = computed(() => {
    const needle = versionFilters.search.trim().toLowerCase()
    const rows = versions.value.filter((row) => !needle
      || [row.version, row.changelog, row.published_by, row.origin_version]
        .some((field) => String(field || '').toLowerCase().includes(needle)))
    return sortRows(rows, versionTable.sort.prop, versionTable.sort.order,
                    (row, prop) => (row as unknown as Record<string, unknown>)[prop])
  })

  const visibleProbes = computed(() => {
    const needle = probeFilters.search.trim().toLowerCase()
    const rows = probes.value.filter((row) => {
      // "尚未上报" is its own state: a probe that predates rule-version reporting
      // is not out of date, it is unable to say.
      if (probeFilters.sync === 'unsynced' && probedVersion(row) !== '') return false
      if (probeFilters.sync === 'outdated' && !outOfDateProbes.value.includes(row)) return false
      if (probeFilters.sync === 'failed' && !failedProbes.value.includes(row)) return false
      if (!needle) return true
      return [row.name, row.hostname, row.ip_address]
        .some((field) => String(field || '').toLowerCase().includes(needle))
    })
    return sortRows(rows, probeTable.sort.prop, probeTable.sort.order, probeSortValue)
  })

  async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
    if (!silent) { loading.value = true; error.value = '' }
    try {
      const sets = await listRuleSets()
      ruleSet.value = sets.items[0] || null
      if (!ruleSet.value) {
        versions.value = []
        probes.value = []
        return
      }
      const [versionResult, probeResult] = await Promise.all([
        listRuleSetVersions(ruleSet.value.id),
        listProbes({ page: 1, page_size: 200 }),
      ])
      versions.value = versionResult.items
      probes.value = probeResult.items
      error.value = ''
    } catch (err) {
      if (!silent) error.value = err instanceof Error ? err.message : String(err)
    } finally {
      if (!silent) loading.value = false
    }
  }

  // A probe's reported sync state changes when it next checks in, so a minute
  // keeps the "N 台待更新" reading honest without polling hard.
  useAutoRefresh(load, { intervalMs: 60000 })

  function openPublish(): void {
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')
    draft.version = `rel-${stamp}`
    draft.changelog = ''
    draft.min_agent_version = ''
    dialog.value = true
  }

  async function publish(): Promise<void> {
    if (!ruleSet.value) return
    saving.value = true
    try {
      const created = await publishRuleSetVersion(ruleSet.value.id, {
        version: draft.version, changelog: draft.changelog, min_agent_version: draft.min_agent_version,
      })
      dialog.value = false
      await load()
      ElMessage.success(`已发布 ${created.version}（${created.rule_count} 条规则），探针将在下次同步时更新`)
    } catch (err) {
      // A rejected publish is a real validation failure (bad rule, duplicate
      // version); the server reason is shown instead of a generic message.
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      saving.value = false
    }
  }

  async function rollback(row: RuleSetVersion): Promise<void> {
    if (!ruleSet.value) return
    try {
      const created = await rollbackRuleSetVersion(ruleSet.value.id, {
        to_version: row.version, changelog: `回滚到 ${row.version}`,
      })
      await load()
      ElMessage.success(`已回滚并发布新版本 ${created.version}（来源 ${created.origin_version}）`)
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  onMounted(load)

  return {
    loading,
    error,
    ruleSet,
    versions,
    visibleVersions,
    versionFilters,
    versionTable,
    visibleProbes,
    probeFilters,
    probeTable,
    probes,
    dialog,
    saving,
    draft,
    activeVersion,
    syncedProbes,
    outOfDateProbes,
    failedProbes,
    probeField,
    probedVersion,
    shortHash,
    load,
    openPublish,
    publish,
    rollback,
  }
}
