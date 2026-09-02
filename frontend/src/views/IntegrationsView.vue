<script setup lang="ts">
import { ref } from 'vue'
import EngineStatusCard from '../components/EngineStatusCard.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listIntegrations } from '../api/integrations'
import type { IntegrationStatus } from '../types/integration'

const loading = ref(true)
const error = ref('')
const items = ref<IntegrationStatus[]>([])

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = await listIntegrations()
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
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-row v-else :gutter="12">
      <el-col v-for="item in items" :key="item.name" :span="8" class="col"><EngineStatusCard :item="item" /></el-col>
    </el-row>
  </div>
</template>

<style scoped>.col { margin-bottom: 12px; }</style>
