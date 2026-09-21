<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import FileAnalysis from './FileAnalysis.vue'
import PcapWorkbench from '../network/pcap/PcapWorkbench.vue'

// 文件证据 shows the two kinds of evidence a data review actually needs: the
// risky files the platform collected, and the risky captures. The capture side
// reuses the existing PCAP parsing and display rather than a second viewer.
const route = useRoute()
const router = useRouter()
const active = ref(String(route.query.view || 'files'))
watch(() => route.query.view, (value) => { if (value) active.value = String(value) })
function onChange(name: string): void {
  router.replace({ query: { ...route.query, view: name } })
}
</script>

<template>
  <div>
    <div class="hub-title">文件证据</div>
    <el-tabs :model-value="active" @tab-change="(name: string | number) => onChange(String(name))">
      <el-tab-pane label="风险文件" name="files">
        <FileAnalysis v-if="active === 'files'" />
      </el-tab-pane>
      <el-tab-pane label="风险 PCAP" name="pcaps">
        <PcapWorkbench v-if="active === 'pcaps'" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.hub-title { font-weight: 600; margin-bottom: 8px; }
</style>
