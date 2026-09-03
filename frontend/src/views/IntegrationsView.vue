<script setup lang="ts">
import { ref } from 'vue'
import EngineStatusCard from '../components/EngineStatusCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listIntegrations } from '../api/integrations'
import { apiGet } from '../api/client'
import type { IntegrationStatus } from '../types/integration'
import type { HealthResponse } from '../types/common'

const loading = ref(true)
const error = ref('')
const items = ref<IntegrationStatus[]>([])
const health = ref<HealthResponse | null>(null)

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [integrationResult, healthResult] = await Promise.all([listIntegrations(), apiGet<HealthResponse>('/health')])
    items.value = integrationResult
    health.value = healthResult
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

void load()
</script>

<template>
  <div class="page-card">
    <el-descriptions v-if="health" :column="3" border class="health">
      <el-descriptions-item label="API">{{ health.status }}</el-descriptions-item>
      <el-descriptions-item label="PostgreSQL">{{ health.database }}</el-descriptions-item>
      <el-descriptions-item label="Redis">{{ health.redis }}</el-descriptions-item>
      <el-descriptions-item label="Celery">{{ health.celery?.running || 0 }} running / {{ health.celery?.queued || 0 }} queued</el-descriptions-item>
      <el-descriptions-item label="Analysis Worker">{{ health.analysis_worker }}</el-descriptions-item>
      <el-descriptions-item label="tshark/Zeek/Suricata">{{ health.tshark ? 'Y' : 'N' }} / {{ health.zeek ? 'Y' : 'N' }} / {{ health.suricata ? 'Y' : 'N' }}</el-descriptions-item>
      <el-descriptions-item label="Storage">{{ formatBytes(health.storage_usage_bytes || 0) }}</el-descriptions-item>
      <el-descriptions-item label="Queue Depth">{{ health.queue?.pending || 0 }} pending / {{ health.queue?.oldest_pending_age || 0 }}s oldest</el-descriptions-item>
      <el-descriptions-item label="Probes">{{ health.probe_count || 0 }} total / {{ health.offline_probe_count || 0 }} offline</el-descriptions-item>
    </el-descriptions>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-row v-else :gutter="12">
      <el-col v-for="item in items" :key="item.name" :span="8" class="col"><EngineStatusCard :item="item" /></el-col>
    </el-row>
  </div>
</template>

<style scoped>
.col { margin-bottom: 12px; }
.health { margin-bottom: 16px; }
</style>
