<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getSensitivityLevels, listDataTypes } from '../../api/dataCatalog'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const rows = ref<Awaited<ReturnType<typeof listDataTypes>> | null>(null)
const levels = ref<Awaited<ReturnType<typeof getSensitivityLevels>> | null>(null)
const search = ref('')

const filtered = computed(() => {
  const items = rows.value?.items || []
  const needle = search.value.trim().toLowerCase()
  if (!needle) return items
  return items.filter((item) =>
    item.category.includes(needle) || item.entity.toLowerCase().includes(needle))
})

const totals = computed(() => {
  const items = rows.value?.items || []
  return {
    types: items.length,
    objects: items.reduce((sum, item) => sum + item.object_count, 0),
    instances: items.reduce((sum, item) => sum + item.active_instance_count, 0),
    duplicates: items.reduce((sum, item) => sum + item.confirmed_duplicate_count, 0),
    candidates: items.reduce((sum, item) => sum + item.candidate_count, 0),
  }
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [center, levelResult] = await Promise.all([listDataTypes(), getSensitivityLevels()])
    rows.value = center
    levels.value = levelResult
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function openType(row: { category: string }): void {
  router.push({ path: `/data-types/${encodeURIComponent(row.category)}` })
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <div class="toolbar-title">数据类型中心</div>
        <el-tag v-if="rows" size="small" type="info">
          分级来源：{{ rows.mapping_source === 'settings_override' ? '平台覆盖配置' : '内置默认' }}
        </el-tag>
        <div class="toolbar-spacer" />
        <el-input v-model="search" placeholder="按类型或实体名过滤" clearable style="width: 220px" />
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="敏感类型" :value="totals.types" sub="存在 ACTIVE 实例的类型" />
        <StatCard label="数据对象" :value="totals.objects" sub="逻辑对象（同内容跨主机合并）" />
        <StatCard label="活跃实例" :value="totals.instances" sub="探针上的物理副本" />
        <StatCard label="确认副本" :value="totals.duplicates" tone="warning"
                  :sub="`完整 Hash 相同的额外副本；疑似副本 ${totals.candidates} 个`" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />类型明细</div>
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 10px"
                  title="去重口径：确认副本按“完整 SHA256 相同”的对象计 max(活跃实例数 - 1, 0) 求和；部分指纹只形成疑似副本，单独统计，不并入确认副本。" />
        <el-table :data="filtered" size="small" empty-text="尚无扫描结果" @row-click="openType">
          <el-table-column prop="category" label="类型" min-width="140">
            <template #default="{ row }">
              <strong>{{ row.category }}</strong>
              <el-tag v-if="row.field_only" size="small" type="info" style="margin-left: 6px">仅字段名</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="entity" label="实体" width="150" />
          <el-table-column label="数据分级" width="130">
            <template #default="{ row }">
              <el-tag size="small" :type="row.level === 'L4' ? 'danger' : row.level === 'L3' ? 'warning' : 'info'">
                {{ row.level }} {{ row.level_name }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="旧严重度" width="100">
            <template #default="{ row }"><span class="muted">{{ row.severity }}</span></template>
          </el-table-column>
          <el-table-column prop="object_count" label="对象数" width="90" sortable />
          <el-table-column prop="active_instance_count" label="活跃实例" width="100" sortable />
          <el-table-column prop="host_count" label="主机数" width="90" />
          <el-table-column prop="confirmed_duplicate_count" label="确认副本" width="100" />
          <el-table-column prop="candidate_count" label="疑似副本" width="100" />
          <el-table-column label="判定来源" width="130">
            <template #default="{ row }">
              <span :class="row.source === 'settings_override' ? '' : 'muted'">
                {{ row.source === 'settings_override' ? '平台覆盖' : '内置默认' }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="80" fixed="right">
            <template #default>
              <el-button link type="primary" size="small">详情</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="grid cols-2" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />数据分级（L1～L4）</div>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item v-for="(meta, key) in (levels?.levels || {})" :key="key" :label="`${key} ${meta.name}`">
              {{ meta.description }}
            </el-descriptions-item>
          </el-descriptions>
          <div class="note">{{ levels?.note }}</div>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />不产生敏感的结构性实体</div>
          <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 10px"
                    title="以下实体照常上报，但不会把数据判为敏感，因此不会单独提升文件分级。" />
          <el-table :data="levels?.non_protected || []" size="small" empty-text="无">
            <el-table-column prop="entity" label="实体" width="160" />
            <el-table-column prop="severity" label="旧严重度" width="110" />
            <el-table-column label="说明" min-width="200">
              <template #default="{ row }">{{ row.level_description }}</template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.muted { color: var(--soc-text-dim); }
.note { color: var(--soc-text-dim); font-size: 12px; margin-top: 8px; }
:deep(.el-table__row) { cursor: pointer; }
</style>

