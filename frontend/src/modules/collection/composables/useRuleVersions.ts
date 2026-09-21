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

export function useRuleVersions() {
  const loading = ref(true)
  const error = ref('')
  const ruleSet = ref<RuleSetSummary | null>(null)
  const versions = ref<RuleSetVersion[]>([])
  const probes = ref<Probe[]>([])

  const dialog = ref(false)
  const saving = ref(false)
  const draft = reactive({ version: '', changelog: '', min_agent_version: '' })

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

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
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
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

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
