<script setup lang="ts">
import LoadingState from '../LoadingState.vue'
import ErrorState from '../ErrorState.vue'
import EmptyState from '../EmptyState.vue'

defineProps<{
  loading?: boolean
  error?: string
  empty?: boolean
  emptyText?: string
}>()
defineEmits<{ retry: [] }>()
</script>

<template>
  <LoadingState v-if="loading" />
  <ErrorState v-else-if="error" :message="error" @retry="$emit('retry')" />
  <EmptyState v-else-if="empty" :description="emptyText" />
  <slot v-else />
</template>
