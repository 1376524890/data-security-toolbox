<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { DataObjectRow } from '../../api/dataCatalog'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import { useDataTypeDetail } from './composables/useDataTypeDetail'

// The type row, its object page and the pager live in the composable; this view
// only binds them into the template below.
const route = useRoute()
const router = useRouter()
const category = computed(() => String(route.params.category || ''))
const { loading, error, row, objects, page, pageSize, total, identityTag, load, setPage } = useDataTypeDetail(category)

function openObject(item: DataObjectRow): void {
  router.push({ path: `/data-objects/${item.id}` })
}
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <el-button link @click="router.back()">← 返回</el-button>
        <div class="toolbar-title">数据类型：{{ row?.category }}</div>
        <el-tag v-if="row" size="small" :type="row.level === 'L4' ? 'danger' : row.level === 'L3' ? 'warning' : 'info'">
          {{ row?.level }} {{ row?.level_name }}
        </el-tag>
        <el-tag v-if="row?.field_only" size="small" type="info">仅字段名也可判定</el-tag>
        <el-tag v-if="row?.protected === false" size="small" type="success">不提升分级</el-tag>
        <div class="toolbar-spacer" />
        <el-button @click="load">刷新</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="关联对象数" :value="row?.object_count ?? 0" sub="该类型内部计数，不跨类型去重" />
        <StatCard label="关联实例数" :value="row?.active_instance_count ?? 0" />
        <StatCard label="主机数" :value="row?.host_count ?? 0" sub="按来源去重（文件探针 / 数据库连接）" />
        <StatCard label="确认 / 疑似副本" :value="`${row?.confirmed_duplicate_count ?? 0} / ${row?.candidate_duplicate_count ?? 0}`"
                  tone="warning"
                  :sub="row?.truncated ? '结果已按上限截断' : `疑似需 ≥2 实例；待确认身份 ${row?.identity_pending_count ?? 0} 个`" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />判定说明</div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="实体">{{ row?.entity }}</el-descriptions-item>
          <el-descriptions-item label="判定来源">
            {{ row?.source === 'settings_override' ? '平台覆盖配置' : '内置默认规则' }}
          </el-descriptions-item>
          <el-descriptions-item label="数据分级">{{ row?.level }} {{ row?.level_name }}</el-descriptions-item>
          <el-descriptions-item label="旧严重度（仅展示）">{{ row?.severity }}</el-descriptions-item>
          <el-descriptions-item label="分级说明" :span="2">{{ row?.level_description }}</el-descriptions-item>
        </el-descriptions>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />包含该类型的数据对象</div>
        <el-table :data="objects" size="small" empty-text="该类型尚无活跃对象" @row-click="openObject">
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column label="对象标识" min-width="240">
            <template #default="{ row: item }"><code class="key">{{ item.object_key }}</code></template>
          </el-table-column>
          <el-table-column prop="object_type" label="类型" width="90" />
          <el-table-column label="身份" width="150">
            <template #default="{ row: item }">
              <el-tag size="small" :type="identityTag(item).type">{{ identityTag(item).text }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="size" label="大小(字节)" width="110" />
          <el-table-column label="实例数" width="110">
            <template #default="{ row: item }">{{ item.active_instance_count }} / {{ item.instance_count }}</template>
          </el-table-column>
          <el-table-column label="最近发现" width="170">
            <template #default="{ row: item }">{{ item.last_seen_at?.replace('T', ' ').slice(0, 19) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="80" fixed="right">
            <template #default><el-button link type="primary" size="small">详情</el-button></template>
          </el-table-column>
        </el-table>
        <el-pagination class="pagination" layout="total, prev, pager, next" :total="total"
                       :current-page="page" :page-size="pageSize" @current-change="setPage" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot warn" />尚未接入（P1）</div>
        <el-alert type="warning" :closable="false" show-icon
                  title="风险流向、网络关系与业务系统归属属于 P1 范围，当前平台未采集也未推断，页面不会绘制任何连线或归属。" />
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.key { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
:deep(.el-table__row) { cursor: pointer; }
</style>
