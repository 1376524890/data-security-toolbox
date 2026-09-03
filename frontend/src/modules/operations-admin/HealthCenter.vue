<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { getHealth, type HealthResponse } from '../../api/health'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { formatBytes } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const health = ref<HealthResponse | null>(null)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    health.value = await getHealth()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function statusOf(value?: string): string { return value === 'ok' ? 'ready' : value === 'unavailable' ? 'error' : (value || 'disabled') }

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="!health" @retry="load">
      <template v-if="health">
        <div class="stat-grid cols-4">
          <StatCard label="服务" :value="health.status" :sub="health.service" tone="success" />
          <StatCard label="存储使用" :value="formatBytes(health.storage_usage_bytes)" :sub="`上限 ${formatBytes(health.storage_max_bytes)}`" tone="info" />
          <StatCard label="分析工作进程" :value="health.analysis_worker" tone="warning" />
          <StatCard label="队列待处理" :value="health.queue?.pending || 0" tone="primary" />
        </div>

        <div class="grid cols-3" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />核心服务</div>
            <div class="svc-row"><span>API</span><StatusBadge :value="health.api === 'ok' ? 'ready' : 'error'" /></div>
            <div class="svc-row"><span>Database</span><StatusBadge :value="health.database === 'ok' ? 'ready' : 'error'" /></div>
            <div class="svc-row"><span>Redis</span><StatusBadge :value="statusOf(health.redis)" /></div>
            <div class="svc-row"><span>Celery Broker</span><StatusBadge :value="statusOf(health.celery?.broker)" /></div>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />工作进程 / 队列</div>
            <div class="svc-row"><span>工作进程</span><span class="mono">{{ health.celery?.workers || 0 }}</span></div>
            <div class="svc-row"><span>运行中</span><span class="mono">{{ health.celery?.running || 0 }}</span></div>
            <div class="svc-row"><span>排队中</span><span class="mono">{{ health.celery?.queued || 0 }}</span></div>
            <div class="svc-row"><span>最早等待</span><span class="mono">{{ health.queue?.oldest_pending_age?.toFixed(0) }}s</span></div>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />引擎能力</div>
            <div class="svc-row"><span>tshark</span><StatusBadge :value="health.tshark?.available ? 'ready' : 'disabled'" /></div>
            <div class="svc-row"><span>zeek</span><StatusBadge :value="health.zeek?.available ? 'ready' : 'disabled'" /></div>
            <div class="svc-row"><span>suricata</span><StatusBadge :value="health.suricata?.available ? 'ready' : 'disabled'" /></div>
            <div class="svc-row"><span>suricata 规则</span><span class="mono">{{ health.suricata?.rule_count ?? '-' }}</span></div>
          </div>
        </div>

        <div class="soc-card" style="margin-top: 12px">
          <div class="soc-card-title"><span class="dot" />探针状态</div>
          <div class="grid cols-4">
            <StatCard label="总探针" :value="health.probe?.count || 0" />
            <StatCard label="在线" :value="health.probe?.online || 0" tone="success" />
            <StatCard label="降级" :value="health.probe?.degraded || 0" tone="warning" />
            <StatCard label="离线" :value="health.probe?.offline || 0" tone="danger" />
          </div>
        </div>
      </template>
    </StateBox>
  </div>
</template>

<style scoped>
.svc-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-bottom: 1px dashed var(--soc-border); color: var(--soc-text-muted); }
</style>
