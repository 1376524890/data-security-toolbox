<script setup lang="ts">
/**
 * The card shell every cockpit panel sits in: a title with the page's blue
 * accent bar, an optional right-hand tool area (tabs, "更多 ›"), and a body
 * that scrolls instead of stretching the grid row.
 */
defineProps<{ title: string; action?: string; flush?: boolean }>()
defineEmits<{ action: [] }>()
</script>

<template>
  <section class="ck-card">
    <header class="ck-card-head">
      <span class="ck-card-title"><i class="ck-accent" />{{ title }}</span>
      <span class="ck-card-tools">
        <slot name="actions" />
        <button v-if="action" type="button" class="ck-more" @click="$emit('action')">
          {{ action }}<span class="ck-more-arrow">›</span>
        </button>
      </span>
    </header>
    <div class="ck-card-body" :class="{ flush }"><slot /></div>
  </section>
</template>

<style scoped>
.ck-card {
  display: flex; flex-direction: column; min-height: 0; height: 100%;
  background: var(--soc-panel); border: 1px solid var(--soc-border);
  border-radius: var(--soc-radius-lg, 10px); box-shadow: var(--soc-shadow);
}
.ck-card-head {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  padding: 12px 16px 10px; flex-shrink: 0;
}
.ck-card-title {
  display: inline-flex; align-items: center; gap: 8px;
  font-size: 14px; font-weight: 600; color: var(--soc-text-strong);
}
.ck-accent {
  width: 3px; height: 14px; border-radius: 2px;
  background: linear-gradient(180deg, var(--soc-primary), var(--soc-primary-2));
}
.ck-card-tools { display: inline-flex; align-items: center; gap: 8px; flex-shrink: 0; }
.ck-more {
  border: 0; background: none; cursor: pointer; font-size: 12px;
  color: var(--soc-text-muted); display: inline-flex; align-items: center; gap: 2px;
  padding: 2px 4px; border-radius: 4px;
}
.ck-more:hover { color: var(--soc-primary); background: var(--soc-primary-dim); }
.ck-more-arrow { font-size: 14px; line-height: 1; }
.ck-card-body { flex: 1; min-height: 0; padding: 0 16px 14px; overflow: auto; }
.ck-card-body.flush { padding: 0; }
</style>
