<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAssetInventory } from './composables/useAssetInventory'
const props = defineProps<{ sensitiveOnly?: boolean }>()
const route = useRoute(), router = useRouter()
const owner = computed(() => String(route.query.owner_key || ''))
const { rows, total, page, loading, error, search, source, status, load } = useAssetInventory(!!props.sensitiveOnly, owner)
const statuses: Record<string,string> = { ACTIVE: '在位', NOT_OBSERVED: '未再观测', SOURCE_RETIRED: '来源已退役' }
const sources: Record<string,string> = { file:'主机文件', database:'数据库', file_share:'共享文件' }
</script>
<template><div>
  <div class="toolbar"><strong>{{ sensitiveOnly ? '敏感发现' : '资产目录' }}</strong><span class="muted">{{ total }} 条 · {{ owner || '全部来源' }}</span><div class="toolbar-spacer" />
    <el-button v-if="sensitiveOnly" @click="router.push('/data-types')">按敏感类型汇总</el-button>
    <el-button @click="router.push('/data-asset-jobs')">采集任务</el-button>
  </div>
  <div class="toolbar">
    <el-input v-model="search" clearable placeholder="文件路径 / 表名" style="width:260px" @keyup.enter="load()" @clear="load()" />
    <el-select v-model="source" clearable placeholder="全部来源" style="width:140px" @change="load()"><el-option v-for="(label,key) in sources" :key="key" :label="label" :value="key" /></el-select>
    <el-select v-model="status" clearable placeholder="含全部历史" style="width:160px" @change="load()"><el-option v-for="(label,key) in statuses" :key="key" :label="label" :value="key" /></el-select>
    <el-button type="primary" @click="load()">查询</el-button>
    <el-button v-if="owner" @click="router.replace({ query: {} })">清除来源限定</el-button>
  </div>
  <el-alert v-if="error" :title="error" type="error" :closable="false" />
  <el-table :data="rows" size="small" v-loading="loading" empty-text="当前范围暂无资产" @row-dblclick="(row: any) => router.push(`/asset-instances/${row.id}`)">
    <el-table-column label="资产 / 路径" min-width="260" show-overflow-tooltip><template #default="{row}"><el-button link type="primary" @click="router.push(`/asset-instances/${row.id}`)">{{ row.name }}</el-button><div class="muted">{{row.path}}</div></template></el-table-column>
    <el-table-column label="来源" min-width="170"><template #default="{row}">{{row.source_name || row.probe_name || row.owner_key}}<div class="muted">{{sources[row.source_kind] || row.source_kind}} · {{row.host}}</div></template></el-table-column>
    <el-table-column label="敏感信息" min-width="150"><template #default="{row}"><el-tag v-for="category in row.categories" :key="category" size="small" type="warning" style="margin:2px">{{category}}</el-tag><span v-if="!row.categories.length" class="muted">未发现值命中</span></template></el-table-column>
    <el-table-column label="覆盖 / 状态" width="180"><template #default="{row}">{{statuses[row.status] || row.status}}<div class="muted">{{row.coverage || '未报告'}} · {{row.termination_reason || '—'}}</div></template></el-table-column>
    <el-table-column label="最近观测" width="190"><template #default="{row}">{{new Date(row.last_seen_at).toLocaleString()}}<div v-if="row.last_change" class="muted">{{row.last_change === 'new' ? '新增' : row.last_change === 'changed' ? '内容变化' : '无变化'}}</div></template></el-table-column>
  </el-table>
  <el-pagination :current-page="page" :page-size="50" :total="total" layout="total, prev, pager, next" @current-change="load" style="margin-top:12px" />
</div></template>
<style scoped>.muted {font-size:12px;color:var(--soc-text-dim);margin-top:3px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;}</style>
