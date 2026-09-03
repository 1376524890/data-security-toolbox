<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { listOfflineResources } from '../../api/offline'
import type { OfflineResource } from '../../types/offline'
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const resources = ref<OfflineResource[]>([])
const activeType = ref<'sigma_rules' | 'suricata_rules' | 'yara'>('sigma_rules')

const filtered = computed(() => resources.value.filter((r: OfflineResource) => r.resource_type === activeType.value))
const types = computed(() => ['sigma_rules', 'suricata_rules', 'yara'].map((t) => ({ label: t.replace('_', ' '), value: t, count: resources.value.filter((r: OfflineResource) => r.resource_type === t).length })))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    resources.value = await listOfflineResources()
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
      <span class="gap-note">YARA 规则端点未提供（缺口已记录）</span>
    </div>
    <StateBox :loading="loading" :error="error" :empty="!filtered.length" @retry="load">
      <div class="grid cols-3">
        <div v-for="r in filtered" :key="r.id" class="soc-card rule-card">
          <div class="rule-head">
            <div class="rule-name">{{ r.name }}</div>
            <StatusBadge :value="r.status" />
          </div>
          <div class="rule-meta">
            <span>版本 <span class="mono">{{ r.version }}</span></span>
            <span>规则数 <span class="mono">{{ r.count }}</span></span>
          </div>
          <div class="rule-meta">
            <span>导入时间 {{ formatDateTime(r.imported_at) }}</span>
          </div>
          <div class="rule-path mono">{{ r.storage_path }}</div>
          <JsonViewer :value="r.resource_metadata" title="资源元数据" :height="140" />
        </div>
      </div>
      <div v-if="activeType === 'yara' && !filtered.length" class="soc-card">
        <div class="text-dim">暂无 YARA 规则资源；需要后端提供 YARA 规则列表接口</div>
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
