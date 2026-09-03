<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { listRules, type RuleItem } from '../../api/rules'
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'

const loading = ref(true)
const error = ref('')
const rules = ref<RuleItem[]>([])
const activeType = ref<'sigma' | 'suricata' | 'yara'>('sigma')

const filtered = computed(() => rules.value.filter((r: RuleItem) => r.type === activeType.value))
const types = computed(() => ['sigma', 'suricata', 'yara'].map((t) => ({ label: t, value: t, count: rules.value.filter((r: RuleItem) => r.type === t).length })))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listRules()
    rules.value = result.items
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-radio-group v-model="activeType">
        <el-radio-button v-for="t in types" :key="t.value" :value="t.value">{{ t.label }} ({{ t.count }})</el-radio-button>
      </el-radio-group>
      <div class="toolbar-spacer" />
    </div>
    <StateBox :loading="loading" :error="error" :empty="!filtered.length" @retry="load">
      <div class="grid cols-2">
        <div v-for="(r, idx) in filtered" :key="r.path" class="soc-card rule-card">
          <div class="rule-head">
            <div class="rule-name">{{ r.name }}</div>
            <StatusBadge :value="r.type" />
          </div>
          <div class="rule-meta">
            <span>类型 <span class="mono">{{ r.type }}</span></span>
            <span>大小 <span class="mono">{{ r.size }} B</span></span>
          </div>
          <div class="rule-path mono">{{ r.path }}</div>
          <RawViewer :value="r.content" language="yaml" :height="220" />
        </div>
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.rule-card { display: flex; flex-direction: column; gap: 8px; }
.rule-head { display: flex; align-items: center; justify-content: space-between; }
.rule-name { font-weight: 700; color: var(--soc-text-strong); }
.rule-meta { display: flex; gap: 16px; color: var(--soc-text-muted); font-size: 12px; }
.rule-path { color: var(--soc-text-dim); font-size: 11px; word-break: break-all; }
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
